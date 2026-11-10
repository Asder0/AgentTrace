"""Validate migrated cross-APP tasks without invoking an LLM."""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any

from agentdojo.method import activate_platform
from agentdojo.method.analysis.defense_config import set_method_enabled
from agentdojo.method.analysis.execution_contract import (
    build_task_execution_contract,
)
from agentdojo.method.capture.interceptor import TrackingContext
from agentdojo.method.modeling.graph_db import reset_graph
from agentdojo.method.tasks.cross_app import CROSS_APP_TASKS, CrossAppTask
from agentdojo.method.visualization.mock_apps import (
    apply_scenario_fixtures,
    get_runtime_and_env,
    reset_all_environments,
)


def _expected_answer(task: CrossAppTask) -> str:
    for requirement in task.evaluation.get("requirements", []):
        if requirement.get("kind") == "answer_number":
            return str(requirement["value"])
    return ""


def validate_ground_truth(task: CrossAppTask) -> dict[str, Any]:
    """Run no-op and ground-truth checks for one migrated task."""
    reset_all_environments()
    reset_graph()
    TrackingContext().reset()
    runtime, environment = get_runtime_and_env("unified")
    task.validate(runtime.functions)
    execution_contract = build_task_execution_contract(task)
    contract_failures = list(execution_contract.contract_errors)
    apply_scenario_fixtures(environment, task.to_scenario())
    pre_environment = copy.deepcopy(environment)

    no_op = task.evaluate(
        "",
        pre_environment,
        environment,
    ).to_dict()

    step_errors: list[dict[str, str]] = []
    for step in task.execution_order():
        _, error = runtime.run_function(
            environment,
            step.exposed_tool_name(runtime),
            dict(step.arguments),
        )
        if error:
            step_errors.append(
                {
                    "step_id": step.step_id,
                    "error": str(error),
                }
            )

    ground_truth = task.evaluate(
        _expected_answer(task),
        pre_environment,
        environment,
    ).to_dict()
    no_op_failed_as_expected = not no_op["passed"]
    ground_truth_passed = ground_truth["passed"] and not step_errors
    return {
        "scenario_id": next(key for key, candidate in CROSS_APP_TASKS.items() if candidate is task),
        "task_id": task.task_id,
        "source_task_id": task.source.get("task_id"),
        "source_generator_id": task.source.get("generator_id"),
        "migration_quality": task.source.get("migration_quality"),
        "semantic_changes": task.source.get("semantic_changes", []),
        "source_api_evidence": task.source.get("source_api_evidence", []),
        "passed": (
            no_op_failed_as_expected
            and ground_truth_passed
            and not contract_failures
        ),
        "no_op_failed_as_expected": no_op_failed_as_expected,
        "ground_truth_passed": ground_truth_passed,
        "execution_contract_valid": not contract_failures,
        "execution_contract_failures": (
            contract_failures
        ),
        "step_errors": step_errors,
        "no_op_evaluation": no_op,
        "ground_truth_evaluation": ground_truth,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate migrated cross-APP task fixtures and ground truth.")
    parser.add_argument(
        "--task",
        action="append",
        default=[],
        help="Scenario ID to validate. May be repeated; defaults to all evaluated tasks.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional JSON output path.",
    )
    args = parser.parse_args()
    activate_platform()
    # This command validates task fixtures and ground truth, not LLM planning
    # or egress authorization. The corresponding defense tests exercise those
    # layers separately with a task contract produced by the real pipeline.
    set_method_enabled("ring_2", "task_scope", False)
    set_method_enabled("ring_3", "sensitive_egress", False)

    if args.task:
        missing = sorted(set(args.task) - set(CROSS_APP_TASKS))
        if missing:
            raise SystemExit(f"Unknown cross-APP scenario IDs: {missing}")
        tasks = [CROSS_APP_TASKS[task_id] for task_id in args.task]
    else:
        tasks = [task for task in CROSS_APP_TASKS.values() if task.evaluation]

    results = [validate_ground_truth(task) for task in tasks]
    report = {
        "schema_version": 1,
        "task_count": len(results),
        "passed_count": sum(result["passed"] for result in results),
        "failed_count": sum(not result["passed"] for result in results),
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
