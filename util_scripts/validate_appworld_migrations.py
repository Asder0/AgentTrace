"""Run migrated AppWorld tasks through the real AgentDojo pipeline."""

from __future__ import annotations

import argparse
import json
import os
import threading
import time
from pathlib import Path
from typing import Any

from agentdojo.method import activate_platform
from agentdojo.method.analysis.defense_config import reset_config
from agentdojo.method.analysis.l2_chain import ConfirmationBroker
from agentdojo.method.tasks.appworld_migrations import get_appworld_migration_specs
from agentdojo.method.tasks.cross_app import CROSS_APP_TASKS
from agentdojo.method.visualization import server


def _retryable(result: dict[str, Any]) -> bool:
    text = " ".join(
        str(result.get(key, "")) for key in ("error", "execution_error", "block_reason", "stop_reason")
    ).lower()
    return any(
        marker in text
        for marker in (
            "503",
            "502",
            "429",
            "timeout",
            "temporarily unavailable",
            "empty response",
            "connection reset",
        )
    )


def _compact_result(scenario_id: str, result: dict[str, Any]) -> dict[str, Any]:
    plan_usage = result.get("plan_usage") or {}
    task_evaluation = result.get("task_evaluation") or {}
    risk_cards = result.get("risk_cards") or []
    return {
        "scenario_id": scenario_id,
        "source_task_id": CROSS_APP_TASKS[scenario_id].source.get("task_id"),
        "migration_quality": CROSS_APP_TASKS[scenario_id].source.get("migration_quality"),
        "passed": bool(task_evaluation.get("passed"))
        and not bool(result.get("blocked"))
        and not bool(result.get("execution_error")),
        "error": result.get("error", ""),
        "execution_error": result.get("execution_error", ""),
        "blocked": bool(result.get("blocked")),
        "block_reason": result.get("block_reason", ""),
        "task_stopped": bool(result.get("task_stopped")),
        "stop_reason": result.get("stop_reason", ""),
        "status": result.get("status", ""),
        "plan_revision": (result.get("task_data_plan") or {}).get("plan_revision"),
        "planned_action_counts": plan_usage.get("planned_action_counts", {}),
        "completed_steps": plan_usage.get("completed_steps", []),
        "l2_cardinality_resolutions": plan_usage.get(
            "l2_cardinality_resolutions",
            {},
        ),
        "task_evaluation": task_evaluation,
        "risk_cards": [
            {
                "risk_type": card.get("risk_type"),
                "content": card.get("user_content"),
                "reason": card.get("user_reason"),
                "decision": card.get("decision"),
            }
            for card in risk_cards
        ],
        "trace_id": result.get("trace_id", ""),
    }


def _watch_confirmations(
    stop: threading.Event,
    observed: list[dict[str, Any]],
) -> None:
    broker = ConfirmationBroker()
    seen: set[str] = set()
    while not stop.wait(0.5):
        for pending in broker.list_pending():
            request_id = str(pending.get("request_id", ""))
            if not request_id or request_id in seen:
                continue
            seen.add(request_id)
            item = {
                "request_id": request_id,
                "tool_name": pending.get("tool_name", ""),
                "app": pending.get("app", ""),
                "confirmation_kind": pending.get("confirmation_kind", ""),
                "decision_kind": pending.get("decision_kind", ""),
                "options": pending.get("options", []),
                "payload": pending.get("payload", {}),
            }
            observed.append(item)
            print(f"  pending confirmation: {item}", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run reviewed AppWorld migrations through a real model.")
    parser.add_argument(
        "--task",
        action="append",
        default=[],
        help="Scenario ID to run; may be repeated.",
    )
    parser.add_argument(
        "--new-batch",
        action="store_true",
        help="Run only instances compiled by appworld_migrations.py.",
    )
    parser.add_argument("--model", default="deepseek-chat")
    parser.add_argument("--retries", type=int, default=2)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    if args.task:
        scenario_ids = list(dict.fromkeys(args.task))
    elif args.new_batch:
        scenario_ids = [spec.scenario_id for spec in get_appworld_migration_specs()]
    else:
        scenario_ids = [
            scenario_id for scenario_id, task in CROSS_APP_TASKS.items() if task.source.get("benchmark") == "AppWorld"
        ]

    missing = [scenario_id for scenario_id in scenario_ids if scenario_id not in CROSS_APP_TASKS]
    if missing:
        raise SystemExit(f"Unknown scenarios: {missing}")
    non_appworld = [
        scenario_id
        for scenario_id in scenario_ids
        if CROSS_APP_TASKS[scenario_id].source.get("benchmark") != "AppWorld"
    ]
    if non_appworld:
        raise SystemExit(f"Not AppWorld migrations: {non_appworld}")

    api_key = os.getenv("DEEPSEEK_API_KEY", "").strip()
    if not api_key:
        raise SystemExit("DEEPSEEK_API_KEY is required")

    activate_platform()
    reset_config()
    server._set_llm_config(
        {
            "provider": "deepseek",
            "model": args.model,
            "api_key": api_key,
        }
    )

    results = []
    for index, scenario_id in enumerate(scenario_ids, start=1):
        print(f"[{index}/{len(scenario_ids)}] {scenario_id}", flush=True)
        result: dict[str, Any] = {}
        pending_confirmations: list[dict[str, Any]] = []
        watcher_stop = threading.Event()
        watcher = threading.Thread(
            target=_watch_confirmations,
            args=(watcher_stop, pending_confirmations),
            daemon=True,
        )
        watcher.start()
        for attempt in range(max(1, args.retries + 1)):
            result = server._execute_action_with_pipeline(scenario_id)
            if not _retryable(result):
                break
            if attempt < args.retries:
                time.sleep(min(5.0, 1.5 * (attempt + 1)))
        watcher_stop.set()
        watcher.join(timeout=1)
        compact = _compact_result(scenario_id, result)
        compact["attempts"] = attempt + 1
        compact["retryable_external_error"] = _retryable(result)
        compact["pending_confirmations"] = pending_confirmations
        results.append(compact)
        print(
            f"  passed={compact['passed']} "
            f"blocked={compact['blocked']} "
            f"error={compact['execution_error'] or compact['error']}",
            flush=True,
        )

    report = {
        "schema_version": 1,
        "model": args.model,
        "case_count": len(results),
        "passed_count": sum(item["passed"] for item in results),
        "failed_count": sum(not item["passed"] for item in results),
        "retryable_external_error_count": sum(item["retryable_external_error"] for item in results),
        "results": results,
    }
    output = json.dumps(report, ensure_ascii=False, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output + "\n", encoding="utf-8")
    print(output)
    if report["failed_count"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
