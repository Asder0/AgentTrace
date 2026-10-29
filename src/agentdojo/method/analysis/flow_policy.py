"""Lightweight, deterministic runtime policies for the thesis platform.

The platform focuses on traceability and visual audit rather than trying to
replace the Agent with a second reasoning system. The checks here only use
explicit task grants, declared tool metadata and propagated information-flow
labels.
"""

from __future__ import annotations

import copy
from typing import Any, Mapping

from ..app_domains import domain_for_tool
from ..modeling.labels import (
    CONFIDENTIALITY_LEVELS,
    join_confidentiality,
)
from ..modeling.policy import base_tool_name, is_egress_tool, tool_effect
from .defense_config import effective_method_enabled, effective_ring_enabled
from .parameter_binding import (
    action_flow_contract,
    contains_placeholder,
)
from .risk_types import (
    DECISION_ADVISORY,
    DECISION_BLOCK,
    DECISION_HOLD,
    make_risk,
)


def same_tool_name(left: str, right: str) -> bool:
    """Compare unqualified aliases while requiring exact namespaced matches."""
    left_name = str(left)
    right_name = str(right)
    if left_name == right_name:
        return True
    if "__" in left_name or "__" in right_name:
        return False
    return base_tool_name(left_name) == base_tool_name(right_name)


def _successful_action_count(
    plan_usage: Any,
    tool_name: str,
) -> int:
    """Return committed calls, excluding failed attempts that may be retried."""
    if not isinstance(plan_usage, Mapping):
        return 0
    counts = plan_usage.get("planned_action_counts", {})
    recorded = 0
    if isinstance(counts, Mapping):
        recorded = sum(
            max(0, int(value or 0))
            for action, value in counts.items()
            if same_tool_name(tool_name, str(action))
        )
    evidenced = sum(
        1
        for item in plan_usage.get("action_results", [])
        if isinstance(item, Mapping)
        and same_tool_name(tool_name, str(item.get("action", "")))
        and item.get("status") == "success"
        and item.get("has_result_evidence", True)
    )
    return max(recorded, evidenced)


def _label_value(label: Any, section: str, key: str, default: Any) -> Any:
    if not isinstance(label, Mapping):
        return default
    value = label.get(section)
    if not isinstance(value, Mapping):
        return default
    return value.get(key, default)


def _control_arguments(event: Mapping[str, Any]) -> list[str]:
    tool_name = str(event.get("tool_intent", ""))
    policy = tool_effect(tool_name)
    inputs = event.get("inputs")
    if not isinstance(inputs, Mapping):
        return []
    controlled = set(policy.control_fields) | set(policy.destination_fields)
    return sorted(
        str(name)
        for name, value in inputs.items()
        if str(name) in controlled and value not in (None, "", [], {})
    )


def _risky_control_arguments(
    event: Mapping[str, Any],
    control_arguments: list[str],
) -> tuple[list[str], list[str], list[str]]:
    """Return only control arguments tied to directly risky entities."""
    argument_labels = event.get("argument_flow_labels")
    if not isinstance(argument_labels, Mapping):
        return [], [], []
    risky_arguments: list[str] = []
    risky_entities: list[str] = []
    evidence_refs: list[str] = []
    for name in control_arguments:
        label = argument_labels.get(name)
        if not isinstance(label, Mapping):
            continue
        injection = label.get("injection")
        if not isinstance(injection, Mapping):
            continue
        entities = [
            str(item)
            for item in injection.get("risky_entities", [])
            if item
        ]
        evidence = [
            str(item)
            for item in injection.get("evidence_refs", [])
            if item
        ]
        if not bool(injection.get("source_flagged", False)) and not entities:
            continue
        risky_arguments.append(name)
        risky_entities.extend(entities)
        evidence_refs.extend(evidence)
    return (
        list(dict.fromkeys(risky_arguments)),
        list(dict.fromkeys(risky_entities)),
        list(dict.fromkeys(evidence_refs)),
    )


def check_untrusted_control(
    event: Mapping[str, Any],
    *,
    options: dict | None = None,
) -> dict[str, Any]:
    """Mark an action when external data influences a control argument.

    This is an advisory check. The execution remains enabled so the audit view
    can expose legitimate email-to-bank and email-to-travel workflows.
    """
    result = {
        "passed": True,
        "executed": False,
        "skipped": False,
        "tainted": False,
        "control_arguments": [],
        "taint_roots": [],
        "risk": None,
    }
    if not effective_ring_enabled("ring_1", options):
        result.update(skipped=True, skipped_reason="ring_disabled")
        return result
    if not effective_method_enabled("ring_1", "untrusted_flow", options):
        result.update(skipped=True, skipped_reason="method_disabled")
        return result

    result["executed"] = True
    label = event.get("input_flow_label", {})
    injection = (
        label.get("injection", {})
        if isinstance(label, Mapping)
        and isinstance(label.get("injection"), Mapping)
        else {}
    )
    control_arguments = _control_arguments(event)
    taint_roots = [
        str(item)
        for item in _label_value(label, "integrity", "taint_roots", [])
        if item
    ]
    result["control_arguments"] = control_arguments
    result["taint_roots"] = taint_roots
    risky_arguments, risky_entities, evidence_refs = _risky_control_arguments(
        event,
        control_arguments,
    )
    source_flagged = bool(risky_arguments)
    result["source_flagged"] = source_flagged
    result["risky_control_arguments"] = risky_arguments
    result["risky_entities"] = risky_entities
    result["injection_score"] = float(injection.get("max_score", 0.0) or 0.0)
    result["quarantined_fields"] = list(
        injection.get("quarantined_fields", [])
    )
    if not risky_arguments:
        return result

    result["tainted"] = False
    reason = (
        "The directly risky data entity has an isolated injection chunk and "
        f"supplied control arguments {', '.join(risky_arguments)}. "
        "The entity retains a source-risk label; the remaining content is "
        "not treated as directly tainted."
    )
    result["risk"] = make_risk(
        1,
        DECISION_ADVISORY,
        reason,
        severity="medium",
        event_kind="security",
        policy_id="ring1.untrusted_control",
        activity_id=event.get("activity_id"),
        source_ids=evidence_refs,
        taint_roots=[*taint_roots, *risky_entities],
        sink_ids=[str(event.get("tool_intent", ""))],
        fsm_before="ACTION_PROPOSED",
        fsm_after="ADVISED",
        confidence=result["injection_score"] or None,
    )
    return result

def check_task_scope(
    event: Mapping[str, Any],
    *,
    options: dict | None = None,
) -> dict[str, Any]:
    """Check a tool call against the compiled task authorization contract."""
    result = {
        "passed": True,
        "executed": False,
        "skipped": False,
        "reason": "task_scope_not_evaluated",
        "risk": None,
        "matched_step": "",
        "authorization_mode": "task_scope",
    }
    if not effective_ring_enabled("ring_2", options):
        result.update(skipped=True, skipped_reason="ring_disabled")
        return result
    if not effective_method_enabled("ring_2", "task_scope", options):
        result.update(skipped=True, skipped_reason="method_disabled")
        return result

    result["executed"] = True
    if not event.get("tool_intent"):
        result["reason"] = "no_tool_action"
        return result
    tool_name = str(event.get("tool_intent", ""))
    policy = tool_effect(tool_name)
    effect = policy.effect
    plan = event.get("task_data_plan")
    if not isinstance(plan, Mapping) or not plan.get("valid", True):
        if effect == "read":
            result.update(
                reason="task_scope_unavailable",
                advisory=True,
            )
            return result
        result.update(
            passed=False,
            reason="task_scope_unavailable",
        )
        result["risk"] = make_risk(
            2,
            DECISION_BLOCK,
            "The task authorization contract is unavailable for a "
            "write, privilege, egress or unknown-effect action.",
            severity="high",
            event_kind="policy",
            policy_id="ring2.task_scope_unavailable",
            activity_id=event.get("activity_id"),
            sink_ids=[tool_name],
            fsm_before="ACTION_PROPOSED",
            fsm_after="BLOCKED",
        )
        return result

    allowed_actions = [
        str(item) for item in plan.get("allowed_actions", []) if item
    ]
    allowed_effects = {
        str(item) for item in plan.get("allowed_effects", []) if item
    }
    forbidden_effects = {
        str(item) for item in plan.get("forbidden_effects", []) if item
    }
    allowed_suites = {
        str(item) for item in plan.get("allowed_suites", []) if item
    }
    planned = any(
        same_tool_name(tool_name, allowed)
        for allowed in allowed_actions
    )
    matched_allowed_action = next(
        (
            allowed
            for allowed in allowed_actions
            if same_tool_name(tool_name, allowed)
        ),
        "",
    )
    plan_suite = (
        matched_allowed_action.split("__", 1)[0]
        if "__" in matched_allowed_action
        and matched_allowed_action.split("__", 1)[0] in allowed_suites
        else (
            next(iter(allowed_suites))
            if planned and len(allowed_suites) == 1
            else ""
        )
    )
    tool_suite = (
        str(event.get("tool_suite") or "")
        or (tool_name.split("__", 1)[0] if "__" in tool_name else "")
        or str(event.get("app_domain") or "")
        or (
            str(event.get("target_app") or "")
            if str(event.get("target_app") or "") in allowed_suites
            else ""
        )
        or plan_suite
        or (domain_for_tool(tool_name) or "")
    )
    action_steps = (
        plan.get("action_steps", {})
        if isinstance(plan.get("action_steps"), Mapping)
        else {}
    )
    result["authorization"] = {
        "allowed_actions": allowed_actions,
        "allowed_effects": sorted(allowed_effects),
        "forbidden_effects": sorted(forbidden_effects),
        "allowed_suites": sorted(allowed_suites),
        "plan_id": str(plan.get("plan_id", "")),
        "plan_hash": str(plan.get("plan_hash", "")),
        "action": tool_name,
        "tool_suite": tool_suite,
        "effect": effect,
        "risk_level": policy.risk_level,
    }
    result["capability_decision"] = result["authorization"]
    injection = (
        event.get("input_flow_label", {}).get("injection", {})
        if isinstance(event.get("input_flow_label"), Mapping)
        else {}
    )
    control_arguments = _control_arguments(event)
    risky_control_arguments, risky_entities, source_risk_evidence = (
        _risky_control_arguments(event, control_arguments)
    )
    source_flagged = bool(risky_control_arguments)
    result["source_flagged"] = source_flagged
    result["control_arguments"] = control_arguments
    result["risky_control_arguments"] = risky_control_arguments
    result["risky_entities"] = risky_entities
    result["source_risk_evidence"] = source_risk_evidence
    result["injection_score"] = float(injection.get("max_score", 0.0) or 0.0)
    result["injection_evidence"] = list(injection.get("evidence_refs", []))

    if effect in forbidden_effects:
        result.update(
            passed=False,
            reason="forbidden_effect",
        )
        return _ring2_decision(
            event,
            result,
            plan,
            tool_name=tool_name,
            decision=DECISION_BLOCK,
        )

    if planned and allowed_suites and tool_suite not in allowed_suites:
        result.update(
            passed=False,
            reason="suite_not_bound_to_task_scope",
        )
        return _ring2_decision(
            event,
            result,
            plan,
            tool_name=tool_name,
            decision=DECISION_BLOCK,
        )
    if not planned:
        result.update(
            passed=False,
            reason="action_not_bound_to_task_scope",
        )
        return _ring2_decision(
            event,
            result,
            plan,
            tool_name=tool_name,
            decision=DECISION_BLOCK,
        )

    if effect not in allowed_effects:
        result.update(
            passed=False,
            reason="effect_not_bound_to_task_scope",
        )
        return _ring2_decision(
            event,
            result,
            plan,
            tool_name=tool_name,
            decision=DECISION_BLOCK,
        )

    result.update(
        reason="action_authorized",
        matched_step=str(event.get("plan_step_id", "")) or next(
            (
                str(step)
                for action, step in action_steps.items()
                if same_tool_name(tool_name, str(action))
            ),
            "",
        ),
    )
    if policy.risk_level == "L2":
        l2_actions = {
            str(item)
            for item in plan.get("l2_actions", [])
            if item
        }
        if not any(same_tool_name(tool_name, item) for item in l2_actions):
            result.update(
                passed=False,
                reason="l2_not_in_initial_plan",
            )
            return _ring2_decision(
                event,
                result,
                plan,
                tool_name=tool_name,
                decision=DECISION_BLOCK,
            )
        completed_steps = {
            str(item)
            for item in (
                event.get("plan_usage", {}).get(
                    "completed_steps",
                    [],
                )
                if isinstance(event.get("plan_usage"), Mapping)
                else []
            )
            if item
        }
        matched_step_id = str(event.get("plan_step_id", "")) or next(
            (
                str(step)
                for action, step in action_steps.items()
                if same_tool_name(tool_name, str(action))
            ),
            "",
        )
        matched_step = next(
            (
                step
                for step in plan.get("steps", [])
                if isinstance(step, Mapping)
                and str(step.get("id")) == matched_step_id
            ),
            {},
        )
        missing_dependencies = [
            str(dependency)
            for dependency in matched_step.get("depends_on", [])
            if str(dependency) not in completed_steps
        ]
        if missing_dependencies:
            result.update(
                passed=False,
                reason="l2_dependencies_unmet",
                missing_dependencies=missing_dependencies,
            )
            return _ring2_decision(
                event,
                result,
                plan,
                tool_name=tool_name,
                decision=DECISION_BLOCK,
            )
        if source_flagged:
            result.update(
                source_risk=True,
                source_risk_reason="l2_from_source_risk",
            )
        grant = next(
            (
                item
                for item in plan.get("l2_grants", [])
                if isinstance(item, Mapping)
                and same_tool_name(
                    tool_name,
                    str(item.get("action", "")),
                )
            ),
            {},
        )
        max_calls = int(grant.get("max_calls", 1) or 1)
        current_count = _successful_action_count(
            event.get("plan_usage"),
            tool_name,
        )
        if current_count >= max_calls:
            result.update(
                passed=False,
                reason="l2_call_limit_exceeded",
            )
            return _ring2_decision(
                event,
                result,
                plan,
                tool_name=tool_name,
                decision=DECISION_BLOCK,
            )
        result.update(
            reason="l2_confirmation_required",
            confirmation_required=True,
            l2_grant=grant,
        )
        return _ring2_decision(
            event,
            result,
            plan,
            tool_name=tool_name,
            decision=DECISION_HOLD,
            event_kind="policy",
            policy_id="ring2.l2_confirmation",
        )
    if source_flagged:
        result.update(
            source_risk=True,
            source_risk_reason="planned_action_from_source_risk",
        )
    return result


def _ring2_decision(
    event: Mapping[str, Any],
    result: dict[str, Any],
    plan: Mapping[str, Any],
    *,
    tool_name: str,
    decision: str,
    event_kind: str = "policy",
    policy_id: str = "ring2.task_scope",
) -> dict[str, Any]:
    reason_code = str(result.get("reason", ""))
    reason_descriptions = {
        "forbidden_effect": "the requested effect is explicitly forbidden by the task",
        "action_not_bound_to_task_scope": "the tool is not included in the current task plan",
        "effect_not_bound_to_task_scope": "the tool effect is not authorized by the current task plan",
        "l2_not_in_initial_plan": "the L2 action was not authorized in the initial task plan",
        "l2_dependencies_unmet": "required earlier task steps have not completed",
        "l2_call_limit_exceeded": "the L2 call limit from the initial grant was exceeded",
        "task_scope_unavailable": "the task authorization plan is unavailable or invalid",
    }
    if decision == DECISION_ADVISORY:
        reason = (
            f"Tool {tool_name} is allowed with an audit advisory "
            f"({reason_code})."
        )
        severity = "medium"
        fsm_before = "ACTION_PROPOSED"
        fsm_after = "ADVISED"
    elif decision == DECISION_HOLD:
        reason = (
            f"L2 tool {tool_name} is in the authorized call chain "
            "and requires explicit user confirmation."
        )
        if result.get("source_risk"):
            risky = ", ".join(result.get("risky_control_arguments", []))
            reason += (
                " A directly risky source entity also supplied the control "
                f"parameters {risky}; this is recorded as source risk, not as "
                "an automatic scope violation."
            )
        severity = "high"
        fsm_before = "ACTION_PROPOSED"
        fsm_after = "HELD"
    else:
        detail = reason_descriptions.get(
            reason_code,
            reason_code or "an unspecified Ring 2 policy condition",
        )
        reason = (
            f"Ring 2 blocked {tool_name}: {detail} "
            f"({reason_code or 'unspecified'})."
        )
        severity = "high"
        fsm_before = "ACTION_PROPOSED"
        fsm_after = "BLOCKED"
    risk = make_risk(
        2,
        decision,
        reason,
        severity=severity,
        event_kind=event_kind,
        policy_id=policy_id,
        activity_id=event.get("activity_id"),
        source_ids=(
            (
                result.get("source_risk_evidence", [])
                or result.get("injection_evidence", [])
            )
            if result.get("source_flagged")
            else []
        ),
        taint_roots=(
            (
                result.get("source_risk_evidence", [])
                or result.get("injection_evidence", [])
            )
            if result.get("source_flagged")
            else []
        ),
        sink_ids=[tool_name],
        fsm_before=fsm_before,
        fsm_after=fsm_after,
        confidence=(
            float(plan.get("confidence"))
            if plan.get("confidence") is not None
            else None
        ),
    )
    risk.update(
        {
            "plan_id": str(plan.get("plan_id", "")),
            "plan_hash": str(plan.get("plan_hash", "")),
            "matched_step": result.get("matched_step", ""),
            "actual_action": tool_name,
            "actual_effect": result.get("authorization", {}).get("effect", ""),
            "source_flagged": bool(result.get("source_flagged", False)),
            "control_arguments": list(result.get("control_arguments", [])),
            "risky_control_arguments": list(
                result.get("risky_control_arguments", [])
            ),
            "risky_entities": list(result.get("risky_entities", [])),
        }
    )
    result["risk"] = risk
    return result


def _flatten_scalars(value: Any) -> list[str]:
    if isinstance(value, Mapping):
        result: list[str] = []
        for child in value.values():
            result.extend(_flatten_scalars(child))
        return result
    if isinstance(value, (list, tuple, set)):
        result = []
        for child in value:
            result.extend(_flatten_scalars(child))
        return result
    if value is None:
        return []
    return [str(value)]


def _has_egress_value(value: Any) -> bool:
    if value is None or value == "":
        return False
    if isinstance(value, (list, tuple, set, dict)):
        return bool(value)
    return True


def _normalise(value: str) -> str:
    return " ".join(str(value).casefold().split())


def check_sensitive_egress(
    event: Mapping[str, Any],
    *,
    options: dict | None = None,
) -> dict[str, Any]:
    """Check only the final egress arguments and their authorized receivers."""
    tool_name = str(event.get("tool_intent", ""))
    result: dict[str, Any] = {
        "passed": True,
        "executed": False,
        "skipped": False,
        "egress_tool": is_egress_tool(tool_name),
        "sink": tool_name,
        "categories": [],
        "confidentiality": "public",
        "destinations": [],
        "destination_state": "not_evaluated",
        "data_sources": [],
        "provenance_ancestors": [],
        "field_sources": [],
        "data_fields": [],
        "provenance_refs": [],
        "parameter_provenance": {},
        "parameter_generation": {},
        "data_field_refs": [],
        "allowed_data_sources": [],
        "unverified_arguments": [],
        "implicit_egress": [],
        "provenance_state": "not_evaluated",
        "provenance_warnings": list(
            event.get("parameter_resolution_warnings", [])
        ),
        "reason": "not_egress",
        "risk": None,
    }
    if not result["egress_tool"]:
        return result
    if not effective_ring_enabled("ring_3", options):
        result.update(skipped=True, skipped_reason="ring_disabled")
        return result
    if not effective_method_enabled("ring_3", "sensitive_egress", options):
        result.update(skipped=True, skipped_reason="method_disabled")
        return result

    result["executed"] = True
    task_plan = event.get("task_data_plan")
    contract = action_flow_contract(
        task_plan,
        tool_name,
        step_id=str(event.get("plan_step_id", "")),
    )
    if not isinstance(contract, Mapping) or not contract.get("valid", False):
        result.update(
            passed=False,
            reason="egress_flow_contract_unavailable",
            destination_state="unauthorized",
        )
    else:
        policy = tool_effect(tool_name)
        inputs = event.get("inputs")
        inputs = dict(inputs) if isinstance(inputs, Mapping) else {}
        implicit_egress = [
            dict(item)
            for item in event.get("implicit_egress", [])
            if isinstance(item, Mapping)
        ]
        implicit_destinations = sorted(
            {
                str(recipient)
                for item in implicit_egress
                for recipient in item.get("recipients", [])
                if recipient
            }
        )
        implicit_content_labels = [
            item.get("flow_label")
            for item in implicit_egress
            if isinstance(item.get("flow_label"), Mapping)
        ]
        implicit_errors = [
            str(item.get("error", ""))
            for item in implicit_egress
            if not item.get("resolved") and item.get("error")
        ]
        contract_destination_parameters = [
            str(item)
            for item in (
                (contract.get("destination") or {}).get("parameters", [])
                if isinstance(contract.get("destination"), Mapping)
                else []
            )
            if item
        ] or sorted(policy.destination_fields)
        actual_destination_parameters = [
            field
            for field in sorted(policy.destination_fields)
            if _has_egress_value(inputs.get(field))
        ]
        destination_parameters = sorted(
            {
                *contract_destination_parameters,
                *actual_destination_parameters,
            }
        )
        parameter_destinations = sorted(
            {
                value
                for field in destination_parameters
                for value in _flatten_scalars(inputs.get(field))
                if value
            }
        )
        destinations = sorted(
            set(parameter_destinations) | set(implicit_destinations)
        )
        destination = (
            contract.get("destination")
            if isinstance(contract.get("destination"), Mapping)
            else {}
        )
        mode = str(destination.get("mode", "literal")).lower()
        resolution_map = {
            str(item.get("parameter", "")): item
            for item in event.get("parameter_resolutions", [])
            if isinstance(item, Mapping)
        }
        implicit_resource_ok = all(
            bool(item.get("resolved"))
            for item in implicit_egress
        )
        implicit_resolution_ok = all(
            resolution_map.get(
                str(item.get("id_parameter", "")),
                {},
            ).get("status")
            == "resolved"
            for item in implicit_egress
        )
        if mode == "derived":
            destination_ok = (
                bool(destinations)
                and implicit_resource_ok
                and implicit_resolution_ok
                and all(
                    resolution_map.get(parameter, {}).get("status") == "resolved"
                    for parameter in actual_destination_parameters
                )
            )
            destination_state = (
                "derived_authorized" if destination_ok else "unauthorized"
            )
        else:
            allowed_destinations = {
                _normalise(item)
                for item in destination.get("allowed_values", [])
                if item
            }
            destination_ok = (
                bool(parameter_destinations)
                and all(
                    _normalise(item) in allowed_destinations
                    for item in parameter_destinations
                )
                and implicit_resource_ok
            )
            destination_state = "fixed_authorized" if destination_ok else "unauthorized"

        argument_labels = event.get("argument_flow_labels")
        argument_labels = (
            argument_labels if isinstance(argument_labels, Mapping) else {}
        )
        content_labels = [
            label
            for field, label in argument_labels.items()
            if field not in destination_parameters and isinstance(label, Mapping)
        ]
        content_labels.extend(implicit_content_labels)
        if not content_labels:
            content_labels = [event.get("input_flow_label", {})]
        confidentiality = join_confidentiality(
            [
                label.get("confidentiality", {})
                for label in content_labels
                if isinstance(label, Mapping)
            ]
        )
        categories = list(confidentiality.get("categories", []))
        ancestor_source_entities = sorted(
            str(item)
            for item in confidentiality.get("source_entities", [])
            if item
        )
        field_sources = []
        provenance_refs: list[dict[str, Any]] = []
        parameter_provenance: dict[str, list[str]] = {}
        parameter_generation: dict[str, dict[str, Any]] = {}
        for resolution in event.get("parameter_resolutions", []):
            if not isinstance(resolution, Mapping):
                continue
            parameter = str(resolution.get("parameter", ""))
            if resolution.get("generation_kind"):
                parameter_generation[parameter] = {
                    "generation_kind": str(
                        resolution.get("generation_kind", "")
                    ),
                    "validation_mode": str(
                        resolution.get("validation_mode", "structured")
                    ),
                    "semantic_type": str(
                        resolution.get("semantic_type", "")
                    ),
                    "parameter_role": str(
                        resolution.get("parameter_role", "")
                    ),
                    "constraints": copy.deepcopy(
                        resolution.get("constraints", {})
                    ),
                    "explanation": str(
                        resolution.get("explanation", "")
                    ),
                    "confidence": resolution.get("confidence"),
                    "semantic_supported": resolution.get(
                        "semantic_supported"
                    ),
                }
            resolution_refs = [
                dict(item)
                for item in resolution.get("provenance_refs", [])
                if isinstance(item, Mapping) and item.get("ref_id")
            ]
            provenance_refs.extend(resolution_refs)
            parameter_provenance[parameter] = sorted(
                {
                    str(item["ref_id"])
                    for item in resolution_refs
                }
            )
            evidence_items = [
                dict(item)
                for item in resolution.get("source_evidence", [])
                if isinstance(item, Mapping)
            ]
            if not evidence_items:
                source_paths = [
                    str(item)
                    for item in resolution.get("source_paths", [])
                    if item
                ]
                for source_ref in resolution.get("source_refs", []):
                    if not isinstance(source_ref, Mapping):
                        continue
                    for source_path in source_paths:
                        evidence_items.append(
                            {
                                **dict(source_ref),
                                "source_path": source_path,
                                "start": None,
                                "end": None,
                                "extracted_text": "",
                                "authoritative": bool(
                                    resolution.get("authoritative", False)
                                ),
                                "value_hash": str(
                                    resolution.get("value_hash", "")
                                ),
                            }
                        )
            for evidence in evidence_items:
                if not isinstance(evidence, Mapping):
                    continue
                matching_ref = next(
                    (
                        item
                        for item in provenance_refs
                        if str(item.get("app", ""))
                        == str(evidence.get("app", ""))
                        and str(item.get("entity", ""))
                        == str(evidence.get("entity", ""))
                        and str(item.get("entity_id", ""))
                        == str(evidence.get("entity_id", ""))
                        and str(item.get("source_action", ""))
                        == str(evidence.get("source_action", ""))
                        and str(item.get("source_path", ""))
                        == str(evidence.get("source_path", ""))
                        and item.get("start") == evidence.get("start")
                        and item.get("end") == evidence.get("end")
                    ),
                    {},
                )
                field_sources.append(
                    {
                        "parameter": parameter,
                        "ref_id": str(
                            matching_ref.get("ref_id", "")
                        ),
                        "source_id": str(
                            matching_ref.get("source_id", "")
                        ),
                        "source": f"{evidence.get('app', '')}:"
                        f"{evidence.get('entity', '')}",
                        "source_entity_id": str(
                            evidence.get("entity_id", "")
                        ),
                        "source_action": str(
                            evidence.get("source_action", "")
                        ),
                        "source_activity_id": str(
                            matching_ref.get("activity_id", "")
                        ),
                        "source_path": str(
                            evidence.get("source_path", "")
                        ),
                        "start": evidence.get("start"),
                        "end": evidence.get("end"),
                        "extracted_text": str(
                            evidence.get("extracted_text", "")
                        ),
                        "authoritative": bool(
                            evidence.get("authoritative", False)
                        ),
                        "value_hash": str(
                            evidence.get("value_hash", "")
                        ),
                    }
                )
        provenance_refs = list(
            {
                str(item["ref_id"]): item
                for item in provenance_refs
            }.values()
        )
        data_field_refs = [
            {
                "ref_id": str(item.get("ref_id", "")),
                "parameters": sorted(
                    parameter
                    for parameter, ref_ids in parameter_provenance.items()
                    if item.get("ref_id") in ref_ids
                ),
                "source_id": str(item.get("source_id", "")),
                "source": f"{item.get('app', '')}:"
                f"{item.get('entity', '')}",
                "source_action": str(
                    item.get("source_action", "")
                ),
                "source_path": str(item.get("source_path", "")),
            }
            for item in provenance_refs
        ]
        direct_source_entities = sorted(
            {
                str(item.get("source", ""))
                for item in field_sources
                if item.get("source")
                and str(item.get("parameter", ""))
                not in destination_parameters
            }
            | {
                str(source)
                for label in implicit_content_labels
                if isinstance(label, Mapping)
                for source in (
                    label.get("confidentiality", {})
                    if isinstance(label.get("confidentiality"), Mapping)
                    else {}
                ).get("source_entities", [])
                if source
            }
        )
        if not direct_source_entities:
            direct_source_entities = list(ancestor_source_entities)
        allowed_sources = {
            str(item)
            for item in contract.get("data_sources", [])
            if item
        }
        level = str(confidentiality.get("level", "secret")).lower()
        max_level = str(contract.get("max_confidentiality", "secret")).lower()
        resolution_errors = [
            str(item)
            for item in event.get("parameter_resolution_errors", [])
            if item
        ]
        provenance_state = (
            "invalid"
            if resolution_errors
            else (
                "incomplete"
                if result.get("provenance_warnings")
                else "complete"
            )
        )
        result.update(
            destinations=destinations,
            destination_state=destination_state,
            categories=categories,
            confidentiality=level,
            data_sources=direct_source_entities,
            provenance_ancestors=ancestor_source_entities,
            field_sources=field_sources,
            provenance_refs=provenance_refs,
            parameter_provenance=parameter_provenance,
            parameter_generation=parameter_generation,
            data_field_refs=data_field_refs,
            data_fields=sorted(
                {
                    f"{item['parameter']}:{item['source_path']}"
                    for item in field_sources
                    if item.get("source_path")
                }
            ),
            implicit_egress=implicit_egress,
            allowed_data_sources=sorted(allowed_sources),
            max_confidentiality=max_level,
            provenance_state=provenance_state,
        )

        failures: list[str] = []
        if not destination_ok:
            failures.append("destination_not_authorized")
        failures.extend(implicit_errors)
        binding_errors = [
            str(item)
            for item in event.get("parameter_resolution_errors", [])
            if item
        ]
        if binding_errors:
            failures.extend(binding_errors)
        if contains_placeholder(inputs):
            failures.append("unresolved_placeholder_in_payload")
        unverified_arguments: list[str] = []
        for field, value in inputs.items():
            field_name = str(field)
            if (
                not _has_egress_value(value)
                or field_name in destination_parameters
            ):
                continue
            label = argument_labels.get(field_name)
            confidentiality = (
                label.get("confidentiality", {})
                if isinstance(label, Mapping)
                else {}
            )
            source_entities = [
                str(item)
                for item in confidentiality.get("source_entities", [])
                if item
            ] if isinstance(confidentiality, Mapping) else []
            source_ids = [
                str(item)
                for item in confidentiality.get("source_ids", [])
                if item
            ] if isinstance(confidentiality, Mapping) else []
            if not source_entities and not source_ids:
                unverified_arguments.append(field_name)
        result["unverified_arguments"] = unverified_arguments
        if (
            unverified_arguments
            and result.get("provenance_state") == "complete"
        ):
            result["provenance_state"] = "incomplete"
            result["provenance_warnings"].extend(
                f"egress_argument_without_provenance:{field}"
                for field in unverified_arguments
            )
            result["provenance_warnings"] = list(
                dict.fromkeys(result["provenance_warnings"])
            )
        if unverified_arguments:
            failures.extend(
                f"egress_argument_without_provenance:{field}"
                for field in unverified_arguments
            )
        if (
            CONFIDENTIALITY_LEVELS.get(level, 3)
            > CONFIDENTIALITY_LEVELS["internal"]
            and not ancestor_source_entities
            and not field_sources
        ):
            failures.append("data_source_unresolved")
            if result.get("provenance_state") == "complete":
                result["provenance_state"] = "incomplete"
                result["provenance_warnings"].append(
                    "data_source_unresolved"
                )
        if direct_source_entities and not set(
            direct_source_entities
        ).issubset(allowed_sources):
            failures.append("data_source_not_authorized")
        if CONFIDENTIALITY_LEVELS.get(level, 3) > CONFIDENTIALITY_LEVELS.get(
            max_level, 0
        ):
            failures.append("confidentiality_exceeds_sink_limit")
        if not failures:
            result.update(
                passed=True,
                reason="authorized_sensitive_egress",
            )
            result["authorization"] = {
                "passed": True,
                "reason": result["reason"],
                "destinations": destinations,
                "destination_state": destination_state,
                "categories": categories,
                "confidentiality": level,
                "max_confidentiality": max_level,
                "provenance_state": result.get("provenance_state", "complete"),
                "data_sources": direct_source_entities,
                "provenance_ancestors": ancestor_source_entities,
                "field_sources": field_sources,
                "provenance_refs": provenance_refs,
                "parameter_provenance": parameter_provenance,
                "parameter_generation": parameter_generation,
                "data_field_refs": data_field_refs,
                "data_fields": result["data_fields"],
                "unverified_arguments": unverified_arguments,
                "implicit_egress": implicit_egress,
                "allowed_data_sources": sorted(allowed_sources),
                "sink": tool_name,
            }
        else:
            result.update(
                passed=False,
                reason=";".join(dict.fromkeys(failures)),
            )

    if not result["passed"]:
        result["authorization"] = {
            "passed": False,
            "reason": result["reason"],
            "destinations": result["destinations"],
            "destination_state": result["destination_state"],
            "categories": result["categories"],
            "confidentiality": result["confidentiality"],
            "provenance_state": result.get("provenance_state", "unknown"),
            "data_sources": result.get("data_sources", []),
            "field_sources": result.get("field_sources", []),
            "provenance_refs": result.get("provenance_refs", []),
            "parameter_provenance": result.get(
                "parameter_provenance",
                {},
            ),
            "parameter_generation": result.get(
                "parameter_generation",
                {},
            ),
            "data_field_refs": result.get("data_field_refs", []),
            "data_fields": result.get("data_fields", []),
            "unverified_arguments": result.get(
                "unverified_arguments",
                [],
            ),
            "implicit_egress": result.get("implicit_egress", []),
            "allowed_data_sources": result.get("allowed_data_sources", []),
            "sink": tool_name,
        }
        result["risk"] = make_risk(
            3,
            DECISION_BLOCK,
            (
                f"Sensitive egress through {tool_name} is not authorized "
                f"({result['reason']})."
            ),
            severity="high",
            event_kind="security",
            policy_id="ring3.sensitive_egress",
            activity_id=event.get("activity_id"),
            source_ids=result.get("data_sources", []),
            sink_ids=[tool_name],
            fsm_before="ACTION_PROPOSED",
            fsm_after="BLOCKED",
        )
    return result
