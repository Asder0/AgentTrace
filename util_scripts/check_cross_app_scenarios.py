#!/usr/bin/env python
"""Validate cross-APP scenario definitions and RouterRuntime tool routes."""

from __future__ import annotations

import json

from agentdojo.method.tasks.cross_app import CROSS_APP_TASKS
from agentdojo.method.visualization.mock_apps import _get_router_runtime


def main() -> int:
    available_tools = set(_get_router_runtime().functions)
    report = []
    failed = False
    for scenario_id, task in CROSS_APP_TASKS.items():
        errors = []
        try:
            task.validate(available_tools)
        except Exception as exc:
            errors.append(str(exc))
        if len(task.required_suites) < 2:
            errors.append("scenario does not span multiple APP domains")
        if not task.data_links():
            errors.append("scenario has no cross-step data dependency")
        report.append(
            {
                "scenario": scenario_id,
                "required_suites": list(task.required_suites),
                "steps": len(task.steps),
                "data_links": len(task.data_links()),
                "errors": errors,
            }
        )
        failed = failed or bool(errors)

    print(json.dumps({"scenarios": report, "valid": not failed}, indent=2))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
