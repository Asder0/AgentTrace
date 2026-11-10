"""Resolve planned actions without collapsing cross-APP identities."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ..app_domains import domain_for_tool
from ..modeling.policy import (
    split_qualified_tool_name,
    tool_identity,
)


def _step_suite(
    step: Mapping[str, Any],
    action: Mapping[str, Any],
) -> str:
    for contract_name in (
        "data_access",
        "resource_access",
        "flow_contract",
    ):
        contract = action.get(contract_name)
        if not isinstance(contract, Mapping):
            continue
        app = str(contract.get("app", "") or "")
        if app:
            return app.lower()
    explicit_suite = str(
        action.get("suite")
        or step.get("suite")
        or ""
    ).lower()
    if explicit_suite:
        return explicit_suite
    return domain_for_tool(
        split_qualified_tool_name(
            str(action.get("name", "") or "")
        )[1]
    ) or ""


def plan_action_identity(
    step: Mapping[str, Any],
    action: Mapping[str, Any],
) -> str:
    return tool_identity(
        str(action.get("name", "") or ""),
        _step_suite(step, action),
    )


def find_plan_actions(
    plan: Mapping[str, Any] | None,
    tool_name: str,
    *,
    step_id: str = "",
    suite_hint: str = "",
) -> list[tuple[Mapping[str, Any], Mapping[str, Any]]]:
    """Return every planned action compatible with a concrete invocation."""

    if not isinstance(plan, Mapping):
        return []
    requested_name = str(tool_name or "").strip()
    if not requested_name:
        return []
    requested_suite, requested_base = (
        split_qualified_tool_name(requested_name)
    )
    requested_suite = str(
        requested_suite or suite_hint or ""
    ).lower()
    matches: list[
        tuple[Mapping[str, Any], Mapping[str, Any]]
    ] = []
    for step in plan.get("steps", []) or []:
        if not isinstance(step, Mapping):
            continue
        current_step_id = str(step.get("id", "") or "")
        if step_id and current_step_id != str(step_id):
            continue
        for action in step.get("actions", []) or []:
            if not isinstance(action, Mapping):
                continue
            action_name = str(action.get("name", "") or "")
            if not action_name:
                continue
            action_suite, action_base = (
                split_qualified_tool_name(action_name)
            )
            if action_base != requested_base:
                continue
            action_suite = str(
                action_suite
                or _step_suite(step, action)
                or ""
            ).lower()
            if (
                requested_suite
                and requested_suite != action_suite
            ):
                continue
            matches.append((step, action))
    return matches


def find_plan_action(
    plan: Mapping[str, Any] | None,
    tool_name: str,
    *,
    step_id: str = "",
    suite_hint: str = "",
) -> Mapping[str, Any] | None:
    """Return one unambiguous action, otherwise fail closed."""

    matches = find_plan_actions(
        plan,
        tool_name,
        step_id=step_id,
        suite_hint=suite_hint,
    )
    identities = {
        plan_action_identity(step, action)
        for step, action in matches
    }
    if len(matches) != 1 or len(identities) != 1:
        return None
    return matches[0][1]
