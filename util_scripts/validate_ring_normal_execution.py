"""Run a small read-only normal-task smoke test with the live ring defenses."""

from __future__ import annotations

import argparse
import json
import os
import uuid
from pathlib import Path
from typing import Any

import openai

from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, PipelineConfig
from agentdojo.agent_pipeline.llms.deepseek_llm import DeepSeekLLM
from agentdojo.method import activate_platform
from agentdojo.method.analysis.data_need import clear_task_plan_cache
from agentdojo.method.analysis.defense_config import reset_config
from agentdojo.method.analysis.l2_chain import (
    ConfirmationBroker,
    stable_arguments_hash,
)
from agentdojo.method.capture.interceptor import TrackingContext
from agentdojo.method.modeling.graph_db import reset_graph
from agentdojo.task_suite.load_suites import get_suite

TASKS = (
    ("banking", "user_task_1"),
    ("slack", "user_task_6"),
    ("slack", "user_task_4"),
    ("workspace", "user_task_29"),
    ("workspace", "user_task_24"),
    ("slack", "user_task_0"),
)


def _build_pipeline(model: str, api_key: str) -> AgentPipeline:
    llm = DeepSeekLLM(
        openai.OpenAI(
            api_key=api_key,
            base_url="https://api.deepseek.com/v1",
        ),
        model,
        temperature=0.0,
    )
    return AgentPipeline.from_config(
        PipelineConfig(
            llm=llm,
            model_id=None,
            defense=None,
            system_message_name=None,
            system_message=None,
            tool_output_format=None,
        )
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--task", action="append", default=[])
    args = parser.parse_args()
    selected = set(args.task)
    tasks = [
        (suite_name, task_id) for suite_name, task_id in TASKS if not selected or f"{suite_name}::{task_id}" in selected
    ]
    unknown = selected - {f"{suite_name}::{task_id}" for suite_name, task_id in TASKS}
    if unknown:
        raise SystemExit(f"Unknown tasks: {sorted(unknown)}")

    model = os.getenv("AGENTDOJO_VALIDATION_MODEL", "deepseek-chat")
    api_key = os.getenv("DEEPSEEK_API_KEY", "").strip()
    if not api_key:
        raise SystemExit("DEEPSEEK_API_KEY is required")

    activate_platform()
    original_confirmation_request = ConfirmationBroker.request

    def auto_approve(
        self: ConfirmationBroker,
        **kwargs: Any,
    ) -> dict[str, Any]:
        plan = dict(kwargs.get("plan") or {})
        arguments = dict(kwargs.get("args") or {})
        return {
            "request_id": f"validation_confirm_{uuid.uuid4().hex[:12]}",
            "task_id": str(kwargs.get("task_id", "")),
            "tool_name": str(kwargs.get("tool_name", "")),
            "app": str(kwargs.get("app", "")),
            "risk_level": str(kwargs.get("risk_level", "")),
            "args": arguments,
            "args_hash": stable_arguments_hash(arguments),
            "plan_id": str(plan.get("plan_id", "")),
            "plan_revision": int(plan.get("plan_revision", 1) or 1),
            "plan_hash": str(plan.get("plan_hash", "")),
            "chain_check": dict(kwargs.get("chain_check") or {}),
            "flow_check": dict(kwargs.get("flow_check") or {}),
            "status": "approved",
            "approved": True,
        }

    # This script validates clean-task execution, not interactive UX. The
    # approval is explicit and local to this process.
    ConfirmationBroker.request = auto_approve
    results: list[dict[str, Any]] = []
    try:
        for suite_name, task_id in tasks:
            reset_config()
            clear_task_plan_cache()
            TrackingContext().reset()
            reset_graph()
            suite = get_suite("v1.2.2", suite_name)
            task = suite.get_user_task_by_id(task_id)
            task_error = ""
            try:
                utility, security = suite.run_task_with_pipeline(
                    _build_pipeline(model, api_key),
                    task,
                    None,
                    {},
                    verbose=False,
                )
            except Exception as exc:
                utility, security = False, False
                task_error = f"{type(exc).__name__}: {exc}"
            events = TrackingContext().events
            results.append(
                {
                    "scenario_id": f"{suite_name}::{task_id}",
                    "utility": bool(utility),
                    "security": bool(security),
                    "task_error": task_error,
                    "events": len(events),
                    "blocked_events": [
                        {
                            "tool": event.get("tool_intent", ""),
                            "reason": event.get("block_reason", ""),
                        }
                        for event in events
                        if event.get("status") == "blocked"
                    ],
                    "plan_update_warnings": [
                        warning
                        for event in events
                        for warning in event.get(
                            "plan_update_warnings",
                            [],
                        )
                    ],
                    "plan_updates": [update for event in events for update in event.get("plan_updates", [])],
                    "value_origins": [
                        {
                            "app": origin.app,
                            "entity": origin.entity,
                            "source_tool": origin.source_tool,
                            "source_path": origin.source_path,
                        }
                        for origin in TrackingContext().tool_value_origins
                    ],
                    "selector_origin_keys": [
                        key
                        for key in TrackingContext().tool_value_index
                        if str(key).lower().startswith(("http://", "https://", "www."))
                    ],
                    "source_refs": {
                        str(source_id): {
                            "app": source.get("app", ""),
                            "entity": source.get("entity", ""),
                            "source_action": source.get(
                                "source_action",
                                "",
                            ),
                        }
                        for source_id, source in (TrackingContext().task_data_plan or {}).get("source_refs", {}).items()
                        if isinstance(source, dict)
                    },
                    "tool_calls": [
                        {
                            "tool": event.get("tool_intent", ""),
                            "status": event.get("status", ""),
                            "error": event.get("error", ""),
                            "parameter_resolutions": [
                                {
                                    "parameter": item.get(
                                        "parameter",
                                        "",
                                    ),
                                    "status": item.get("status", ""),
                                    "source_refs": item.get(
                                        "source_refs",
                                        [],
                                    ),
                                }
                                for item in event.get(
                                    "parameter_resolutions",
                                    [],
                                )
                                if isinstance(item, dict)
                            ],
                            "resource_access_failures": event.get(
                                "resource_access_failures",
                                [],
                            ),
                            "parameter_resolution_errors": event.get(
                                "parameter_resolution_errors",
                                [],
                            ),
                            "data_access_contract": (event.get("ring2_check", {}) or {}).get("data_access"),
                        }
                        for event in events
                        if event.get("type") == "api_call_end"
                    ],
                    "passed": bool(utility),
                }
            )
    finally:
        ConfirmationBroker.request = original_confirmation_request

    report = {
        "model": model,
        "task_count": len(results),
        "passed_count": sum(item["passed"] for item in results),
        "results": results,
    }
    output = json.dumps(report, ensure_ascii=False, indent=2)
    output_path = Path("external_data/validation/ring_normal_execution_deepseek.json")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(output + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "model": model,
                "task_count": len(results),
                "passed_count": sum(item["passed"] for item in results),
                "results": [
                    {
                        "scenario_id": item["scenario_id"],
                        "utility": item["utility"],
                        "security": item["security"],
                        "task_error": item.get("task_error", ""),
                        "blocked_events": item["blocked_events"],
                    }
                    for item in results
                ],
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    if report["passed_count"] != report["task_count"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
