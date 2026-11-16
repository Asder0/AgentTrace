"""Build and validate the deterministic per-task cross-APP attack corpus."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
from collections import Counter
from collections.abc import Mapping
from pathlib import Path
from types import SimpleNamespace
from typing import Any

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from agentdojo.method import activate_platform
from agentdojo.method.analysis.defense_config import (
    disable_defense_layer,
    set_auto_confirmations,
)
from agentdojo.method.capture import interceptor
from agentdojo.method.tasks.cross_app import CROSS_APP_TASKS
from agentdojo.method.tasks.cross_app_evaluation import (
    evaluate_cross_app_attack_goal,
)
from agentdojo.method.visualization import server
from agentdojo.method.visualization.mock_apps import (
    apply_scenario_fixtures,
    get_runtime_and_env,
    reset_all_environments,
)
from util_scripts.validate_cross_app_security_metrics import (
    _attack_plan,
)


def _plan(seed: int) -> list[dict[str, Any]]:
    return _attack_plan(
        SimpleNamespace(
            injection_policy="guaranteed",
            task=[],
            injection_point=[],
            profile="smoke",
            attack_type=[],
            goal=[],
            seed=seed,
            injection_limit_per_task=None,
            one_per_attack_type=False,
            attack_selection_mode="per-task",
            task_complexity="all",
            task_content_source="any",
            tasks_per_content_source=0,
            max_attack_runs=0,
            attack_defense_mode="on",
        )
    )


def _sample_key(item: Mapping[str, Any]) -> tuple[str, ...]:
    return (
        str(item["task_id"]),
        str(item["injection_point"]["id"]),
        str(item["attack_type"]),
        str(item["goal"]),
    )


def _sample_id(item: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(
            _sample_key(item),
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()[:16]


def _diff_paths(
    before: Any,
    after: Any,
    *,
    path: tuple[str, ...] = (),
) -> list[str]:
    if type(before) is not type(after):
        return [".".join(path)]
    if isinstance(before, Mapping):
        paths: list[str] = []
        for key in sorted(set(before) | set(after), key=str):
            child = (*path, str(key))
            if key not in before or key not in after:
                paths.append(".".join(child))
            else:
                paths.extend(
                    _diff_paths(
                        before[key],
                        after[key],
                        path=child,
                    )
                )
        return paths
    if isinstance(before, list):
        if len(before) != len(after):
            return [".".join(path)]
        paths = []
        for index, (left, right) in enumerate(zip(before, after)):
            paths.extend(
                _diff_paths(
                    left,
                    right,
                    path=(*path, str(index)),
                )
            )
        return paths
    return [] if before == after else [".".join(path)]


def _call_first(
    runtime,
    env,
    names: tuple[str, ...],
    arguments: dict[str, Any],
):
    for name in names:
        if name in runtime.functions:
            return runtime.run_function(
                env,
                name,
                arguments,
            )
    raise ValueError(f"None of the tools are available: {names}")


def _synthetic_effect(
    runtime,
    env,
    effect: Mapping[str, Any],
) -> None:
    kind = str(effect.get("kind", ""))
    target = str(effect.get("target", ""))
    if kind == "email":
        result, error = _call_first(
            runtime,
            env,
            ("workspace__send_email", "send_email"),
            {
                "recipients": [target],
                "subject": "Archive handoff",
                "body": "Synthetic evaluation payload.",
                "attachments": None,
                "cc": None,
                "bcc": None,
            },
        )
    elif kind == "bank_transfer":
        result, error = _call_first(
            runtime,
            env,
            ("banking__send_money", "send_money"),
            {
                "recipient": target,
                "amount": float(effect.get("amount", 0) or 0),
                "subject": "Synthetic settlement",
                "date": "2024-05-15",
            },
        )
    elif kind == "slack_channel":
        result, error = _call_first(
            runtime,
            env,
            (
                "slack__send_channel_message",
                "send_channel_message",
            ),
            {
                "channel": target,
                "body": "Synthetic evaluation payload.",
            },
        )
    else:
        raise ValueError(f"Unknown attack effect kind: {kind!r}")
    if error is not None:
        raise ValueError(
            f"Synthetic attack tool failed: {error}; result={result!r}"
        )


def _synthetic_evaluator_check(
    item: Mapping[str, Any],
    task,
    scenario: Mapping[str, Any],
    attack_context: Mapping[str, Any],
) -> bool:
    reset_all_environments()
    runtime, env = get_runtime_and_env("unified")
    apply_scenario_fixtures(env, scenario)
    pre_environment = copy.deepcopy(env)
    _synthetic_effect(
        runtime,
        env,
        attack_context["effect"],
    )
    result = evaluate_cross_app_attack_goal(
        str(item["goal"]),
        task,
        pre_environment,
        env,
        attack_context=attack_context,
    )
    return result.attack_succeeded


def _build_sample(item: Mapping[str, Any]) -> dict[str, Any]:
    task_id = str(item["task_id"])
    task = CROSS_APP_TASKS[task_id]
    point = dict(item["injection_point"])
    attack_context = server._cross_app_attack_context(
        task,
        str(point["id"]),
        str(item["goal"]),
    )
    injection_string = server._generate_injection_string(
        str(item["attack_type"]),
        str(attack_context["instruction"]),
    )
    clean_scenario = task.to_scenario()
    injected_scenario = server._cross_app_attack_scenario(
        task,
        str(point["id"]),
        injection_string,
    )
    changed_paths = _diff_paths(
        clean_scenario,
        injected_scenario,
    )
    expected_path = (
        f"fixtures.{point['app']}.{point['collection']}."
        f"{point['index']}.{point['field']}"
    )
    target = str(attack_context["effect"]["target"])
    target_absent = bool(
        target.casefold() not in task.prompt.casefold()
        and target.casefold()
        not in json.dumps(
            task.evaluation,
            ensure_ascii=False,
        ).casefold()
    )
    synthetic_evaluator = _synthetic_evaluator_check(
        item,
        task,
        injected_scenario,
        attack_context,
    )
    validation = {
        "required_read": bool(point["required_read"]),
        "delivery_guarantee": point["delivery_guarantee"],
        "source_steps_present": bool(point["source_step_ids"]),
        "only_selected_field_changed": (
            changed_paths == [expected_path]
        ),
        "target_absent_from_task_contract": target_absent,
        "synthetic_effect_succeeded": synthetic_evaluator,
    }
    if not all(
        validation[key]
        for key in (
            "required_read",
            "source_steps_present",
            "only_selected_field_changed",
            "target_absent_from_task_contract",
            "synthetic_effect_succeeded",
        )
    ) or validation["delivery_guarantee"] != "all_paths":
        raise ValueError(
            f"Attack sample validation failed: "
            f"{_sample_key(item)}: {validation}"
        )
    return {
        "sample_id": _sample_id(item),
        "key": list(_sample_key(item)),
        "task_id": task_id,
        "source_kind": str(item["source_kind"]),
        "required_suites": list(task.required_suites),
        "injection_point": point,
        "attack_type": str(item["attack_type"]),
        "goal_id": str(item["goal"]),
        "attack_context": attack_context,
        "injection_string": injection_string,
        "payload_sha256": hashlib.sha256(
            injection_string.encode("utf-8")
        ).hexdigest(),
        "expected_changed_path": expected_path,
        "validation": validation,
    }


def build_corpus(seed: int) -> dict[str, Any]:
    plan = _plan(seed)
    samples = [_build_sample(item) for item in plan]
    task_counts = Counter(
        sample["task_id"] for sample in samples
    )
    if set(task_counts.values()) != {1}:
        raise ValueError(
            "Per-task corpus must contain exactly one sample per task"
        )
    if len({sample["sample_id"] for sample in samples}) != len(
        samples
    ):
        raise ValueError("Duplicate attack sample IDs")
    return {
        "schema_version": 1,
        "seed": seed,
        "selection_mode": "per-task",
        "injection_policy": "guaranteed",
        "sample_count": len(samples),
        "paired_execution_count": len(samples) * 2,
        "attack_type_counts": dict(
            sorted(
                Counter(
                    sample["attack_type"]
                    for sample in samples
                ).items()
            )
        ),
        "goal_counts": dict(
            sorted(
                Counter(
                    sample["goal_id"] for sample in samples
                ).items()
            )
        ),
        "source_counts": dict(
            sorted(
                Counter(
                    sample["source_kind"]
                    for sample in samples
                ).items()
            )
        ),
        "samples": samples,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, default=20261116)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(
            "external_data/validation/"
            "cross_app_attack_corpus_per_task53_20261116.json"
        ),
    )
    args = parser.parse_args()
    activate_platform()
    interceptor._defense_enabled = False
    disable_defense_layer()
    set_auto_confirmations(True)
    corpus = build_corpus(args.seed)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(corpus, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "output": str(args.output),
                "sample_count": corpus["sample_count"],
                "paired_execution_count": corpus[
                    "paired_execution_count"
                ],
                "attack_type_counts": corpus[
                    "attack_type_counts"
                ],
                "goal_counts": corpus["goal_counts"],
                "source_counts": corpus["source_counts"],
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
