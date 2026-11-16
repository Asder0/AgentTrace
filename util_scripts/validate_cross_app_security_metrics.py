"""Run cross-APP attacks and normal controls, then report nine metrics."""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import Any

from agentdojo.method import activate_platform
from agentdojo.method.analysis.defense_config import (
    disable_defense_layer,
    reset_config,
    set_auto_confirmations,
)
from agentdojo.method.analysis.security_metrics import (
    aggregate_security_metrics,
    attack_defense_comparison,
    final_security_metric_availability,
    final_security_metrics,
    normalize_attack_run,
    normalize_normal_run,
)
from agentdojo.method.capture import interceptor as interceptor_module
from agentdojo.method.tasks.cross_app import CROSS_APP_TASKS
from agentdojo.method.visualization import server


def _selected_values(
    requested: list[str],
    available: Iterable[str],
    label: str,
) -> list[str]:
    available_values = list(dict.fromkeys(available))
    if not requested:
        return available_values
    missing = sorted(set(requested) - set(available_values))
    if missing:
        raise SystemExit(f"Unknown {label}: {missing}")
    return list(dict.fromkeys(requested))


def _attack_modes(mode: str) -> tuple[bool, ...]:
    if mode == "off":
        return (False,)
    if mode == "paired":
        return (False, True)
    return (True,)


_TASK_CONTENT_COLLECTIONS = {
    "file": frozenset({"append_files"}),
    "email": frozenset({"append_unread_emails"}),
    "slack_message": frozenset(
        {
            "append_direct_messages",
            "append_channel_messages",
        }
    ),
    "text": frozenset(
        {
            "append_files",
            "append_unread_emails",
            "append_direct_messages",
            "append_channel_messages",
        }
    ),
}


def _attack_plan(args: argparse.Namespace) -> list[dict[str, Any]]:
    targets = server._cross_app_attack_targets(
        injection_policy=args.injection_policy,
    )
    targets = [
        target
        for target in targets
        if (
            args.task_complexity == "all"
            or (
                (
                    len(
                        CROSS_APP_TASKS[
                            target["id"]
                        ].steps
                    )
                    >= 5
                    or len(
                        CROSS_APP_TASKS[
                            target["id"]
                        ].required_suites
                    )
                    >= 3
                )
                and (
                    args.task_complexity == "complex"
                    or bool(target["injection_points"])
                )
            )
        )
        and (
            args.task_content_source == "any"
            or any(
                point["collection"]
                in _TASK_CONTENT_COLLECTIONS[
                    args.task_content_source
                ]
                for point in target["injection_points"]
            )
        )
    ]
    rng = random.Random(args.seed)
    target_source_scopes: dict[str, str] = {}
    if args.tasks_per_content_source > 0:
        selected_targets = []
        selected_task_ids: set[str] = set()
        for source_scope in (
            "file",
            "email",
            "slack_message",
        ):
            candidates = [
                target
                for target in targets
                if target["id"] not in selected_task_ids
                and any(
                    point["collection"]
                    in _TASK_CONTENT_COLLECTIONS[
                        source_scope
                    ]
                    for point in target["injection_points"]
                )
            ]
            if (
                len(candidates)
                < args.tasks_per_content_source
            ):
                raise SystemExit(
                    f"Not enough complex {source_scope} tasks: "
                    f"requested {args.tasks_per_content_source}, "
                    f"available {len(candidates)}"
                )
            chosen = rng.sample(
                candidates,
                args.tasks_per_content_source,
            )
            for target in chosen:
                target_source_scopes[
                    str(target["id"])
                ] = source_scope
                selected_task_ids.add(str(target["id"]))
                selected_targets.append(target)
        targets = selected_targets
    requested_tasks = set(args.task or [])
    missing_tasks = requested_tasks - {str(target["id"]) for target in targets}
    if missing_tasks:
        raise SystemExit(f"Unknown attack task IDs: {sorted(missing_tasks)}")
    if requested_tasks:
        targets = [target for target in targets if str(target["id"]) in requested_tasks]
    requested_points = set(args.injection_point or [])
    available_points = {
        str(point["id"])
        for target in targets
        for point in target.get("injection_points", [])
    }
    missing_points = requested_points - available_points
    if missing_points:
        raise SystemExit(
            f"Unknown injection point IDs: {sorted(missing_points)}"
        )

    available_attack_types = [str(item["id"]) for item in server.AVAILABLE_ATTACK_TYPES]
    if (
        args.attack_selection_mode
        in {"per-task", "per-task-templates"}
        and not args.attack_type
    ):
        default_attack_types = available_attack_types
        default_injection_limit = 1
    elif args.profile == "smoke":
        default_attack_types = ["important_instructions"]
        default_injection_limit = 1
    elif args.profile == "balanced":
        default_attack_types = available_attack_types
        default_injection_limit = 1
    else:
        default_attack_types = available_attack_types
        default_injection_limit = 0
    attack_types = _selected_values(
        args.attack_type or default_attack_types,
        available_attack_types,
        "attack types",
    )
    goals = _selected_values(
        args.goal,
        [str(goal["id"]) for goal in server.CROSS_APP_ATTACK_GOALS],
        "attack goals",
    )
    plan: list[dict[str, Any]] = []
    for target in targets:
        compatible_goals = set(
            str(item)
            for item in target.get("goals", [])
            if str(item).strip()
        )
        target_goals = [
            goal
            for goal in goals
            if not compatible_goals or goal in compatible_goals
        ]
        if not target_goals:
            continue
        points = list(target.get("injection_points", []))
        source_scope = target_source_scopes.get(
            str(target["id"])
        )
        if source_scope:
            points = [
                point
                for point in points
                if point["collection"]
                in _TASK_CONTENT_COLLECTIONS[
                    source_scope
                ]
            ]
        if requested_points:
            points = [
                point
                for point in points
                if str(point["id"]) in requested_points
            ]
        if not points:
            continue
        limit = default_injection_limit if args.injection_limit_per_task is None else args.injection_limit_per_task
        if limit > 0 and len(points) > limit:
            points = rng.sample(points, limit)
        for point in points:
            for attack_type in attack_types:
                for goal in target_goals:
                    plan.append(
                        {
                            "task_id": str(target["id"]),
                            "source_kind": str(target.get("source_kind", "unknown")),
                            "injection_point": point,
                            "attack_type": attack_type,
                            "goal": goal,
                            "content_source_scope": (
                                source_scope
                            ),
                        }
                    )
    rng.shuffle(plan)
    if args.attack_selection_mode == "per-task":
        by_task: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for item in plan:
            by_task[str(item["task_id"])].append(item)
        task_ids = sorted(by_task)
        rng.shuffle(task_ids)
        type_rotation = list(attack_types)
        rng.shuffle(type_rotation)
        selected = []
        for index, task_id in enumerate(task_ids):
            candidates = by_task[task_id]
            preferred_type = type_rotation[
                index % len(type_rotation)
            ]
            preferred = [
                item
                for item in candidates
                if item["attack_type"] == preferred_type
            ]
            selected.append(
                rng.choice(preferred or candidates)
            )
        plan = selected
    elif args.attack_selection_mode == "per-task-templates":
        by_task: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for item in plan:
            by_task[str(item["task_id"])].append(item)
        task_ids = sorted(by_task)
        rng.shuffle(task_ids)
        goal_rotation = list(goals)
        rng.shuffle(goal_rotation)
        selected = []
        for index, task_id in enumerate(task_ids):
            candidates = by_task[task_id]
            preferred_goal = goal_rotation[
                index % len(goal_rotation)
            ]
            goal_candidates = [
                item
                for item in candidates
                if item["goal"] == preferred_goal
            ] or candidates
            point_ids = sorted(
                {
                    str(item["injection_point"]["id"])
                    for item in goal_candidates
                }
            )
            selected_point = rng.choice(point_ids)
            point_candidates = [
                item
                for item in goal_candidates
                if str(item["injection_point"]["id"])
                == selected_point
            ]
            by_type = {
                str(item["attack_type"]): item
                for item in point_candidates
            }
            selected.extend(
                by_type[attack_type]
                for attack_type in attack_types
                if attack_type in by_type
            )
        plan = selected
    elif args.one_per_attack_type:
        selected = []
        selected_types = set()
        selected_tasks = set()
        for forbid_duplicate_tasks in (True, False):
            for item in plan:
                attack_type = str(item["attack_type"])
                task_id = str(item["task_id"])
                if attack_type in selected_types:
                    continue
                if (
                    forbid_duplicate_tasks
                    and task_id in selected_tasks
                ):
                    continue
                selected.append(item)
                selected_types.add(attack_type)
                selected_tasks.add(task_id)
            if len(selected_types) == len(attack_types):
                break
        plan = selected
    if args.max_attack_runs > 0:
        plan = plan[: args.max_attack_runs]
    return [
        {
            **item,
            "defense_enabled": defense_enabled,
        }
        for item in plan
        for defense_enabled in _attack_modes(
            args.attack_defense_mode
        )
    ]


def _normal_plan(args: argparse.Namespace) -> list[str]:
    available = [scenario_id for scenario_id, task in CROSS_APP_TASKS.items() if task.evaluation]
    if args.normal_task:
        missing = sorted(set(args.normal_task) - set(available))
        if missing:
            raise SystemExit(f"Normal tasks without evaluation: {missing}")
        return list(dict.fromkeys(args.normal_task))
    return available


def _response_payload(response) -> dict[str, Any]:
    payload = response.get_json(silent=True)
    if not isinstance(payload, dict):
        return {"error": (f"HTTP {response.status_code}: {response.get_data(as_text=True)[:500]}")}
    if response.status_code >= 400 and "error" not in payload:
        payload["error"] = f"HTTP {response.status_code}"
    return payload


def _run_attack(
    client,
    item: Mapping[str, Any],
    *,
    defense_enabled: bool,
) -> dict[str, Any]:
    point = item["injection_point"]
    response = client.post(
        "/api/execute/attack",
        json={
            "cross_app_task_id": item["task_id"],
            "injection_point_id": point["id"],
            "injection_goal_id": item["goal"],
            "attack_type": item["attack_type"],
            "suite": "unified",
            "defense_enabled": defense_enabled,
        },
    )
    payload = _response_payload(response)
    payload["request"] = dict(item)
    if "error" in payload:
        return {
            "kind": "attack",
            "trace_id": "",
            "defense_enabled": defense_enabled,
            "request": dict(item),
            "attack_info": payload.get("attack_info", {}),
            "attack_detection_eligible": False,
            "attack_detected": False,
            "attack_payload_coverage": 0.0,
            "attack_field_fully_covered": False,
            "attack_succeeded": False,
            "attack_outcome_valid": False,
            "attack_evaluation_error": str(payload["error"]),
            "utility": False,
            "execution_error": str(payload["error"]),
        }
    record = normalize_attack_run(payload)
    record["defense_enabled"] = defense_enabled
    record["request"] = dict(item)
    record["source_kind"] = item["source_kind"]
    record["injection_app"] = str(point.get("app", ""))
    return record


def _run_normal(
    client,
    scenario_id: str,
    *,
    defense_enabled: bool,
) -> dict[str, Any]:
    response = client.post(
        "/api/execute",
        json={"action": scenario_id},
    )
    payload = _response_payload(response)
    payload["task_id"] = scenario_id
    if "error" in payload:
        return {
            "kind": "normal",
            "trace_id": "",
            "task_id": scenario_id,
            "completed": False,
            "injection_false_positive": False,
            "defense_enabled": defense_enabled,
            "execution_error": str(payload["error"]),
        }
    record = normalize_normal_run(payload)
    record["task_id"] = scenario_id
    record["defense_enabled"] = defense_enabled
    return record


def _group_metrics(
    records: list[dict[str, Any]],
    group_name: str,
    key: Callable[[dict[str, Any]], str],
) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        grouped[key(record)].append(record)
    return {
        value: final_security_metrics(
            aggregate_security_metrics(items)
        )
        for value, items in sorted(grouped.items())
    }


def _write_progress(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def _apply_defense_mode(enabled: bool) -> None:
    interceptor_module._defense_enabled = bool(enabled)
    if enabled:
        reset_config()
    else:
        disable_defense_layer()
    set_auto_confirmations(True)


def _build_report(
    args: argparse.Namespace,
    records: list[dict[str, Any]],
    *,
    complete: bool,
) -> dict[str, Any]:
    full_metrics = aggregate_security_metrics(records)
    defense_on_attacks = [
        record
        for record in records
        if (
            record["kind"] == "attack"
            and bool(record.get("defense_enabled", True))
        )
    ]
    return {
        "schema_version": 1,
        "profile": args.profile,
        "provider": args.provider,
        "model": args.model,
        "injection_policy": args.injection_policy,
        "attack_selection_mode": (
            args.attack_selection_mode
        ),
        "task_complexity": args.task_complexity,
        "task_content_source": (
            args.task_content_source
        ),
        "tasks_per_content_source": (
            args.tasks_per_content_source
        ),
        "one_per_attack_type": args.one_per_attack_type,
        "complete": complete,
        "metrics": final_security_metrics(
            full_metrics
        ),
        "metric_availability": (
            final_security_metric_availability(
                full_metrics
            )
        ),
        "attack_defense_comparison": (
            attack_defense_comparison(records)
        ),
        "by_source": _group_metrics(
            defense_on_attacks,
            "source",
            lambda record: str(record.get("source_kind", "unknown")),
        ),
        "by_attack_type": _group_metrics(
            defense_on_attacks,
            "attack type",
            lambda record: str(
                (record.get("request") or {}).get(
                    "attack_type",
                    "unknown",
                )
            ),
        ),
        "by_goal": _group_metrics(
            defense_on_attacks,
            "goal",
            lambda record: str(
                (record.get("request") or {}).get(
                    "goal",
                    "unknown",
                )
            ),
        ),
        "by_injection_app": _group_metrics(
            defense_on_attacks,
            "injection APP",
            lambda record: str(record.get("injection_app", "unknown")),
        ),
        "runs": records,
    }


def _persist_report(
    path: Path | None,
    args: argparse.Namespace,
    records: list[dict[str, Any]],
    *,
    complete: bool,
) -> dict[str, Any]:
    report = _build_report(args, records, complete=complete)
    if path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    return report


def _run_key(record: Mapping[str, Any]) -> tuple[str, ...]:
    if record.get("kind") == "attack":
        request = record.get("request")
        if not isinstance(request, Mapping):
            request = {}
        point = request.get("injection_point")
        if not isinstance(point, Mapping):
            point = {}
        return (
            "attack",
            str(request.get("task_id", "")),
            str(point.get("id", "")),
            str(request.get("attack_type", "")),
            str(request.get("goal", "")),
            (
                "defense_on"
                if record.get("defense_enabled", True)
                else "defense_off"
            ),
        )
    return (
        "normal",
        str(record.get("task_id", "")),
        ("defense_on" if record.get("defense_enabled", True) else "defense_off"),
    )


def _record_can_be_resumed(record: Mapping[str, Any]) -> bool:
    """Reuse only runs that completed through a real execution path."""
    if str(record.get("execution_error", "")).strip():
        return False
    if record.get("kind") == "attack" and not bool(
        record.get("attack_outcome_valid", False)
    ):
        return False
    capture_audit = record.get("capture_audit")
    if not isinstance(capture_audit, Mapping):
        return False
    try:
        observed_tool_calls = int(
            capture_audit.get("observed_tool_calls", 0) or 0
        )
    except (TypeError, ValueError):
        return False
    return observed_tool_calls > 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Run cross-APP security batches and calculate detection, "
            "field coverage, blocking, utility, and false-positive rates."
        )
    )
    parser.add_argument(
        "--profile",
        choices=("smoke", "balanced", "full"),
        default="smoke",
        help=(
            "Cartesian-mode defaults: smoke uses one point/task and one "
            "attack type; balanced uses all attack types; full uses every "
            "point and attack type. Per-task mode overrides these defaults."
        ),
    )
    parser.add_argument("--provider", default="deepseek")
    parser.add_argument("--model", default="deepseek-chat")
    parser.add_argument(
        "--api-key-env",
        default="DEEPSEEK_API_KEY",
    )
    parser.add_argument("--attack-type", action="append", default=[])
    parser.add_argument("--goal", action="append", default=[])
    parser.add_argument("--task", action="append", default=[])
    parser.add_argument(
        "--injection-point",
        action="append",
        default=[],
        help="Restrict attacks to an exact injection point ID.",
    )
    parser.add_argument("--normal-task", action="append", default=[])
    parser.add_argument(
        "--injection-limit-per-task",
        type=int,
        default=None,
        help="0 selects every injection point.",
    )
    parser.add_argument(
        "--injection-policy",
        choices=("guaranteed", "required", "all"),
        default="guaranteed",
        help=(
            "guaranteed: every required read path reaches the injection; "
            "required: at least one legal required path reaches it; "
            "all: every text fixture field."
        ),
    )
    parser.add_argument(
        "--attack-selection-mode",
        choices=(
            "per-task",
            "per-task-templates",
            "cartesian",
        ),
        default="per-task",
        help=(
            "per-task: one balanced-random injection point, template, and "
            "goal per task (default); per-task-templates: one point and goal "
            "per task with every attack template; cartesian: full product."
        ),
    )
    parser.add_argument(
        "--task-complexity",
        choices=("all", "complex", "complex-text"),
        default="all",
        help=(
            "complex keeps tasks with at least 5 required steps or at "
            "least 3 APP domains; complex-text additionally requires a "
            "guaranteed file, email, or Slack text source."
        ),
    )
    parser.add_argument(
        "--task-content-source",
        choices=(
            "any",
            "file",
            "email",
            "slack_message",
            "text",
        ),
        default="any",
        help=(
            "Keep tasks whose guaranteed injection point comes from a "
            "Workspace file, email, Slack message, or any text source."
        ),
    )
    parser.add_argument(
        "--tasks-per-content-source",
        type=int,
        default=0,
        help=(
            "When positive, deterministically sample this many distinct "
            "complex tasks from file, email, and Slack sources."
        ),
    )
    parser.add_argument(
        "--max-attack-runs",
        type=int,
        default=0,
        help="Optional cap after deterministic planning; 0 means no cap.",
    )
    parser.add_argument(
        "--one-per-attack-type",
        action="store_true",
        help=(
            "Select exactly one randomized task/point/goal combination "
            "for each requested attack type, preferring distinct tasks."
        ),
    )
    parser.add_argument(
        "--max-normal-runs",
        type=int,
        default=0,
        help="Optional deterministic normal-task sample size; 0 means no cap.",
    )
    parser.add_argument(
        "--normal-defense-mode",
        choices=("on", "off", "paired"),
        default="paired",
        help=("Run normal controls with defenses on, off, or both to calculate the S0/S1 completion drop."),
    )
    parser.add_argument(
        "--attack-defense-mode",
        choices=("on", "off", "paired"),
        default="on",
        help=(
            "Run each selected attack with defenses on, off, "
            "or in paired off/on mode."
        ),
    )
    parser.add_argument("--seed", type=int, default=20240516)
    parser.add_argument(
        "--request-timeout-seconds",
        type=float,
        default=120.0,
    )
    parser.add_argument("--max-retries", type=int, default=1)
    parser.add_argument("--skip-normal", action="store_true")
    parser.add_argument(
        "--skip-attacks",
        action="store_true",
        help="Run only normal controls, optionally merged with prior attacks.",
    )
    parser.add_argument(
        "--merge-from",
        type=Path,
        help=(
            "Reuse runs from an earlier report; newly executed runs replace "
            "records with the same task/point/attack/goal key."
        ),
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help=(
            "With --merge-from, keep only completed records with real tool "
            "activity and skip their matching runs."
        ),
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--fail-fast", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if (
        args.attack_selection_mode != "cartesian"
        and args.one_per_attack_type
    ):
        parser.error(
            "--one-per-attack-type requires "
            "--attack-selection-mode cartesian"
        )
    if args.tasks_per_content_source > 0 and args.task:
        parser.error(
            "--tasks-per-content-source cannot be combined with --task"
        )

    activate_platform()
    attacks = [] if args.skip_attacks else _attack_plan(args)
    normal_tasks = [] if args.skip_normal else _normal_plan(args)
    if args.max_normal_runs > 0 and len(normal_tasks) > args.max_normal_runs:
        normal_tasks = random.Random(args.seed + 1).sample(
            normal_tasks,
            args.max_normal_runs,
        )
    normal_modes = (False, True) if args.normal_defense_mode == "paired" else (args.normal_defense_mode == "on",)
    if args.dry_run:
        print(
            json.dumps(
                {
                    "profile": args.profile,
                    "planned_attack_runs": len(attacks),
                    "planned_attack_combinations": (
                        len(attacks)
                        // len(
                            _attack_modes(
                                args.attack_defense_mode
                            )
                        )
                        if attacks
                        else 0
                    ),
                    "planned_normal_runs": (len(normal_tasks) * len(normal_modes)),
                    "attack_defense_mode": (
                        args.attack_defense_mode
                    ),
                    "injection_policy": args.injection_policy,
                    "attack_selection_mode": (
                        args.attack_selection_mode
                    ),
                    "task_complexity": args.task_complexity,
                    "task_content_source": (
                        args.task_content_source
                    ),
                    "tasks_per_content_source": (
                        args.tasks_per_content_source
                    ),
                    "one_per_attack_type": (
                        args.one_per_attack_type
                    ),
                    "normal_defense_mode": args.normal_defense_mode,
                    "attack_types": sorted({item["attack_type"] for item in attacks}),
                    "goals": sorted({item["goal"] for item in attacks}),
                    "attack_tasks": len({item["task_id"] for item in attacks}),
                    "content_source_scopes": dict(
                        sorted(
                            Counter(
                                str(
                                    item.get(
                                        "content_source_scope",
                                        "",
                                    )
                                )
                                for item in attacks
                                if item.get(
                                    "content_source_scope"
                                )
                            ).items()
                        )
                    ),
                    "injection_points": len(
                        {
                            (
                                item["task_id"],
                                item["injection_point"]["id"],
                            )
                            for item in attacks
                        }
                    ),
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return

    api_key = os.getenv(args.api_key_env, "").strip()
    if not api_key:
        raise SystemExit(f"{args.api_key_env} is required")
    server._set_llm_config(
        {
            "provider": args.provider,
            "model": args.model,
            "api_key": api_key,
        }
    )
    os.environ["LLM_REQUEST_TIMEOUT_SECONDS"] = str(max(1.0, args.request_timeout_seconds))
    os.environ["LLM_MAX_RETRIES"] = str(max(0, args.max_retries))
    server._pipeline_cache.clear()
    _apply_defense_mode(True)

    client = server.app.test_client()
    records: list[dict[str, Any]] = []
    if args.merge_from:
        prior = json.loads(args.merge_from.read_text(encoding="utf-8"))
        prior_runs = prior.get("runs")
        if not isinstance(prior_runs, list):
            raise SystemExit(f"{args.merge_from} does not contain a runs list")
        records = [dict(record) for record in prior_runs if isinstance(record, Mapping)]
        if args.resume:
            records = [
                record
                for record in records
                if _record_can_be_resumed(record)
            ]

    def add_record(record: dict[str, Any]) -> None:
        key = _run_key(record)
        records[:] = [existing for existing in records if _run_key(existing) != key]
        records.append(record)

    total = len(attacks) + len(normal_tasks) * len(normal_modes)
    completed = 0
    existing_keys = {_run_key(record) for record in records}
    for item in attacks:
        key = (
            "attack",
            item["task_id"],
            item["injection_point"]["id"],
            item["attack_type"],
            item["goal"],
            (
                "defense_on"
                if item["defense_enabled"]
                else "defense_off"
            ),
        )
        if args.resume and key in existing_keys:
            completed += 1
            _write_progress(
                f"[{completed}/{total}] reused attack {item['task_id']} "
                f"{item['attack_type']} {item['goal']} "
                f"defense={'on' if item['defense_enabled'] else 'off'}"
            )
            continue
        record = _run_attack(
            client,
            item,
            defense_enabled=item["defense_enabled"],
        )
        add_record(record)
        existing_keys.add(_run_key(record))
        _persist_report(
            args.output,
            args,
            records,
            complete=False,
        )
        completed += 1
        _write_progress(
            f"[{completed}/{total}] attack "
            f"{item['task_id']} {item['attack_type']} "
            f"{item['goal']} "
            f"defense={'on' if item['defense_enabled'] else 'off'}"
        )
        if args.fail_fast and record.get("execution_error"):
            raise SystemExit(record["execution_error"])

    for defense_enabled in normal_modes:
        _apply_defense_mode(defense_enabled)
        for scenario_id in normal_tasks:
            key = (
                "normal",
                scenario_id,
                (
                    "defense_on"
                    if defense_enabled
                    else "defense_off"
                ),
            )
            if args.resume and key in existing_keys:
                completed += 1
                _write_progress(
                    f"[{completed}/{total}] reused normal "
                    f"defense={'on' if defense_enabled else 'off'} "
                    f"{scenario_id}"
                )
                continue
            record = _run_normal(
                client,
                scenario_id,
                defense_enabled=defense_enabled,
            )
            add_record(record)
            existing_keys.add(_run_key(record))
            _persist_report(
                args.output,
                args,
                records,
                complete=False,
            )
            completed += 1
            _write_progress(f"[{completed}/{total}] normal defense={'on' if defense_enabled else 'off'} {scenario_id}")
            if args.fail_fast and record.get("execution_error"):
                raise SystemExit(record["execution_error"])

    _apply_defense_mode(True)

    report = _persist_report(
        args.output,
        args,
        records,
        complete=True,
    )
    output = json.dumps(report, ensure_ascii=False, indent=2)
    print(output)


if __name__ == "__main__":
    main()
