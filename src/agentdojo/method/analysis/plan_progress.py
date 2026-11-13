"""Derive task-plan progress from the current revision and action evidence."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ..modeling.policy import base_tool_name


def _same_action(left: str, right: str) -> bool:
    """Compare tool aliases without collapsing qualified namespaces."""
    if left == right:
        return True
    if "__" in left or "__" in right:
        return False
    return base_tool_name(left) == base_tool_name(right)


def _required_actions(step: Mapping[str, Any]) -> list[str]:
    """Return actions whose successful execution is needed to finish a step."""
    actions: list[str] = []
    for action in step.get("actions", []) or []:
        if not isinstance(action, Mapping):
            continue
        name = str(action.get("name", "") or "").strip()
        if not name:
            continue
        if str(action.get("necessity", "") or "").lower() in {
            "fallback",
            "optional",
        }:
            continue
        actions.append(name)
    return actions


def derive_completed_plan_steps(
    plan: Mapping[str, Any] | None,
    plan_usage: Mapping[str, Any] | None,
) -> set[str]:
    """Return completed current-revision steps backed by successful calls.

    Plan revisions may add a step after its read has already executed.  The
    historical ``completed_steps`` list cannot detect that change, so action
    results are the source of truth whenever they exist.  The recorded list is
    retained only as a compatibility fallback for callers that provide no
    action-result history.
    """
    if not isinstance(plan, Mapping) or not isinstance(
        plan_usage,
        Mapping,
    ):
        return set()
    raw_steps = plan.get("steps", [])
    steps = [
        step
        for step in (raw_steps if isinstance(raw_steps, list) else [])
        if isinstance(step, Mapping) and str(step.get("id", "") or "")
    ]
    current_step_ids = {
        str(step.get("id"))
        for step in steps
    }
    raw_results = plan_usage.get("action_results")
    if not isinstance(raw_results, list):
        raw_completed = plan_usage.get("completed_steps", [])
        return {
            str(item)
            for item in (
                raw_completed
                if isinstance(raw_completed, list)
                else []
            )
            if str(item) in current_step_ids
        }

    evidenced_by_step: dict[str, set[str]] = {}
    for result in raw_results:
        if not isinstance(result, Mapping):
            continue
        step_id = str(
            result.get("step_id")
            or result.get("plan_step_id")
            or ""
        )
        action_name = str(result.get("action", "") or "")
        if (
            step_id
            and action_name
            and result.get("status") == "success"
            and result.get("has_result_evidence", True)
        ):
            evidenced_by_step.setdefault(step_id, set()).add(
                action_name
            )

    completed: set[str] = set()
    for step in steps:
        step_id = str(step.get("id"))
        required = _required_actions(step)
        evidenced = evidenced_by_step.get(step_id, set())
        if required and all(
            any(
                _same_action(action, candidate)
                for candidate in evidenced
            )
            for action in required
        ):
            completed.add(step_id)
    return completed


def reconcile_completed_plan_steps(
    plan: Mapping[str, Any] | None,
    plan_usage: dict[str, Any] | None,
) -> set[str]:
    """Synchronize the mutable progress list with current plan evidence."""
    if not isinstance(plan_usage, dict):
        return derive_completed_plan_steps(plan, None)
    completed = derive_completed_plan_steps(plan, plan_usage)
    raw_steps = plan.get("steps", []) if isinstance(plan, Mapping) else []
    ordered = [
        str(step.get("id"))
        for step in (raw_steps if isinstance(raw_steps, list) else [])
        if isinstance(step, Mapping)
        and str(step.get("id", "") or "") in completed
    ]
    plan_usage["completed_steps"] = ordered
    return set(ordered)
