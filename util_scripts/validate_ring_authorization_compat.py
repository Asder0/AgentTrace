"""Validate authorization-grounding changes against normal AgentDojo tasks."""

from __future__ import annotations

import argparse
import copy
import json
import os
from pathlib import Path
from typing import Any

import openai

from agentdojo.agent_pipeline.llms.deepseek_llm import DeepSeekLLM
from agentdojo.functions_runtime import FunctionsRuntime
from agentdojo.method import activate_platform
from agentdojo.method.analysis.data_need import (
    clear_task_plan_cache,
    generate_task_data_plan,
    make_pipeline_task_planner,
)
from agentdojo.method.capture.interceptor import (
    _build_tool_catalog,
    _trusted_identity_values,
)
from agentdojo.method.tasks.cross_app import CROSS_APP_TASKS
from agentdojo.method.visualization.mock_apps import (
    apply_scenario_fixtures,
    get_runtime_and_env,
    reset_all_environments,
)
from agentdojo.task_suite.load_suites import get_suite

DEFAULT_TASKS = (
    ("slack", "user_task_1"),
    ("slack", "user_task_4"),
    ("slack", "user_task_6"),
    ("slack", "user_task_11"),
    ("workspace", "user_task_6"),
    ("workspace", "user_task_27"),
    ("workspace", "user_task_29"),
    ("banking", "user_task_0"),
    ("banking", "user_task_3"),
    ("travel", "user_task_0"),
    ("travel", "user_task_2"),
    ("travel", "user_task_7"),
)


def _grounding_warnings(plan: dict[str, Any]) -> list[str]:
    warnings = [str(item) for item in plan.get("warnings", [])]
    return [
        warning
        for warning in warnings
        if any(
            marker in warning
            for marker in (
                "resource_value_not_grounded",
                "resource_access_value_not_grounded",
                "destination_value_not_grounded",
                "binding_source_outside_action_scope",
            )
        )
    ]


def _evaluate_plan(
    *,
    scenario_id: str,
    prompt: str,
    catalog: list[dict[str, Any]],
    environment: Any,
    planner: Any,
) -> dict[str, Any]:
    clear_task_plan_cache()
    trusted_identities = _trusted_identity_values(environment, prompt)
    plan = generate_task_data_plan(
        prompt,
        planner,
        catalog,
        trusted_identity_values=trusted_identities,
    )
    plan = plan or {}
    invalid_actions = list(plan.get("invalid_actions", []))
    grounding_warnings = _grounding_warnings(plan)
    return {
        "scenario_id": scenario_id,
        "trusted_identities": list(trusted_identities),
        "planner": str(plan.get("planner", "")),
        "planner_error": str(plan.get("error", "")),
        "valid": bool(plan.get("valid", False)),
        "usable": bool(plan.get("usable", False)),
        "fully_valid": bool(plan.get("valid", False) and not invalid_actions),
        "invalid_actions": invalid_actions,
        "grounding_warnings": grounding_warnings,
        "passed": bool(plan.get("usable", False) and not grounding_warnings),
        "warnings": list(plan.get("warnings", [])),
        "l2_grants": list(plan.get("l2_grants", [])),
        "actions": [
            {
                "step_id": str(step.get("id", "")),
                "name": str(action.get("name", "")),
                "max_calls": int(action.get("max_calls", 1) or 1),
            }
            for step in plan.get("steps", [])
            if isinstance(step, dict)
            for action in step.get("actions", [])
            if isinstance(action, dict)
        ],
    }


def _run_suite_task(
    suite_name: str,
    task_id: str,
    planner: Any,
) -> dict[str, Any]:
    suite = get_suite("v1.2.2", suite_name)
    task = suite.get_user_task_by_id(task_id)
    environment = task.init_environment(suite.load_and_inject_default_environment({}))
    runtime = FunctionsRuntime(list(suite.tools))
    return _evaluate_plan(
        scenario_id=f"{suite_name}::{task_id}",
        prompt=task.PROMPT,
        catalog=_build_tool_catalog(runtime, suite_hint=suite_name),
        environment=environment,
        planner=planner,
    )


def _run_cross_app_task(
    scenario_id: str,
    planner: Any,
) -> dict[str, Any]:
    reset_all_environments()
    task = CROSS_APP_TASKS[scenario_id]
    runtime, environment = get_runtime_and_env("unified")
    apply_scenario_fixtures(environment, task.to_scenario())
    return _evaluate_plan(
        scenario_id=scenario_id,
        prompt=task.prompt,
        catalog=_build_tool_catalog(runtime),
        environment=copy.deepcopy(environment),
        planner=planner,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default="deepseek-chat")
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--task",
        action="append",
        default=[],
        help="Scenario ID to validate; may be repeated.",
    )
    args = parser.parse_args()

    api_key = os.getenv("DEEPSEEK_API_KEY", "").strip()
    if not api_key:
        raise SystemExit("DEEPSEEK_API_KEY is required")

    activate_platform()
    llm = DeepSeekLLM(
        openai.OpenAI(
            api_key=api_key,
            base_url="https://api.deepseek.com/v1",
        ),
        args.model,
        temperature=0.0,
    )
    planner = make_pipeline_task_planner(llm)

    selected = set(args.task)
    suite_tasks = [
        (suite_name, task_id)
        for suite_name, task_id in DEFAULT_TASKS
        if not selected or f"{suite_name}::{task_id}" in selected
    ]
    cross_tasks = [
        scenario_id
        for scenario_id in (
            "cross_app::appworld_530b157_grocery_transfer",
            "cross_app::appworld_29caf6f_movie_recommendations",
            "cross_app::appworld_d0b1f43_roommate_spending",
            "cross_app::appworld_d0b1f43_coworker_received",
            "cross_app::appworld_37a8675_phone_identity_payment",
            "cross_app::appworld_3c13f5a_electricity_split",
            "cross_app::appworld_3c13f5a_multitarget_share_requests",
        )
        if not selected or scenario_id in selected
    ]
    unknown = selected - {
        *(f"{suite_name}::{task_id}" for suite_name, task_id in DEFAULT_TASKS),
        "cross_app::appworld_530b157_grocery_transfer",
        "cross_app::appworld_29caf6f_movie_recommendations",
        "cross_app::appworld_d0b1f43_roommate_spending",
        "cross_app::appworld_d0b1f43_coworker_received",
        "cross_app::appworld_37a8675_phone_identity_payment",
        "cross_app::appworld_3c13f5a_electricity_split",
        "cross_app::appworld_3c13f5a_multitarget_share_requests",
    }
    if unknown:
        raise SystemExit(f"Unknown tasks: {sorted(unknown)}")

    results = []
    for suite_name, task_id in suite_tasks:
        results.append(_run_suite_task(suite_name, task_id, planner))
    for scenario_id in cross_tasks:
        results.append(_run_cross_app_task(scenario_id, planner))

    report = {
        "model": args.model,
        "task_count": len(results),
        "passed_count": sum(item["passed"] for item in results),
        "failed_count": sum(not item["passed"] for item in results),
        "fully_valid_count": sum(item["fully_valid"] for item in results),
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
