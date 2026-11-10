"""Lightweight, deterministic runtime policies for the thesis platform.

The platform focuses on traceability and visual audit rather than trying to
replace the Agent with a second reasoning system. The checks here only use
explicit task grants, declared tool metadata and propagated information-flow
labels.
"""

from __future__ import annotations

import copy
from collections.abc import Mapping, Sequence
from typing import Any

from ..app_domains import domain_for_tool
from ..modeling.data_sensitivity import (
    canonical_entity_name,
    normalize_data_path,
    source_level,
)
from ..modeling.labels import (
    CONFIDENTIALITY_LEVELS,
    join_confidentiality,
)
from ..modeling.policy import base_tool_name, is_egress_tool, tool_effect
from ..modeling.sensitive_ner import ensure_sensitivity_detector_ready
from .data_access import (
    action_data_access,
    action_resource_access,
    canonicalize_resource_value,
    validate_resource_access,
)
from .defense_config import effective_method_enabled, effective_ring_enabled
from .parameter_binding import (
    action_flow_contract,
    contains_placeholder,
    parameter_values_equal,
)
from .risk_types import (
    BLOCK_CATEGORY_AUTHORIZATION,
    BLOCK_CATEGORY_CONFIDENTIALITY,
    BLOCK_CATEGORY_CONFIRMATION,
    BLOCK_CATEGORY_INVALID_ACTION,
    BLOCK_CATEGORY_OUT_OF_SCOPE,
    BLOCK_CATEGORY_PROVENANCE,
    BLOCK_CATEGORY_SYSTEM_UNAVAILABLE,
    DECISION_ADVISORY,
    DECISION_BLOCK,
    DECISION_HOLD,
    BlockCategory,
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


def _matching_action_grant(
    plan: Mapping[str, Any],
    tool_name: str,
    step_id: str = "",
) -> Mapping[str, Any] | None:
    """Resolve the action-level grant for a concrete tool invocation."""
    for step in plan.get("steps", []):
        if not isinstance(step, Mapping):
            continue
        current_step_id = str(step.get("id", ""))
        if step_id and current_step_id != str(step_id):
            continue
        for action in step.get("actions", []):
            if not isinstance(action, Mapping):
                continue
            name = str(action.get("name", ""))
            if same_tool_name(name, tool_name):
                return action
    return None


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
            max(0, int(value or 0)) for action, value in counts.items() if same_tool_name(tool_name, str(action))
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


def _planned_action_call_limit(
    plan: Mapping[str, Any],
    tool_name: str,
) -> int:
    """Return the total successful-call budget for a side-effect action."""
    total = 0
    for step in plan.get("steps", []) or []:
        if not isinstance(step, Mapping):
            continue
        for action in step.get("actions", []) or []:
            if (
                not isinstance(action, Mapping)
                or not same_tool_name(
                    tool_name,
                    str(action.get("name", "")),
                )
            ):
                continue
            try:
                total += max(
                    1,
                    int(action.get("max_calls", 1) or 1),
                )
            except (TypeError, ValueError):
                total += 1
    return max(1, total)


def _successful_action_targets(
    plan_usage: Any,
    tool_name: str,
) -> dict[str, int]:
    """Return successfully consumed targets for an L2 action."""
    if not isinstance(plan_usage, Mapping):
        return {}
    recorded = plan_usage.get("successful_l2_targets", {})
    if not isinstance(recorded, Mapping):
        return {}
    for action, values in recorded.items():
        if same_tool_name(tool_name, str(action)) and isinstance(
            values,
            Mapping,
        ):
            return {str(target): max(0, int(count or 0)) for target, count in values.items()}
    return {}


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
        str(name) for name, value in inputs.items() if str(name) in controlled and value not in (None, "", [], {})
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
        entities = [str(item) for item in injection.get("risky_entities", []) if item]
        evidence = [str(item) for item in injection.get("evidence_refs", []) if item]
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
        label.get("injection", {}) if isinstance(label, Mapping) and isinstance(label.get("injection"), Mapping) else {}
    )
    control_arguments = _control_arguments(event)
    taint_roots = [str(item) for item in _label_value(label, "integrity", "taint_roots", []) if item]
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
    result["quarantined_fields"] = list(injection.get("quarantined_fields", []))
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
        result.update(
            passed=False,
            reason="task_scope_unavailable",
            block_category=BLOCK_CATEGORY_SYSTEM_UNAVAILABLE,
        )
        result["risk"] = make_risk(
            2,
            DECISION_BLOCK,
            "The task authorization contract is unavailable for a tool action.",
            severity="high",
            event_kind="policy",
            policy_id="ring2.task_scope_unavailable",
            activity_id=event.get("activity_id"),
            sink_ids=[tool_name],
            fsm_before="ACTION_PROPOSED",
            fsm_after="BLOCKED",
        )
        result["risk"]["block_category"] = (
            BLOCK_CATEGORY_SYSTEM_UNAVAILABLE
        )
        return result

    matched_action_grant = _matching_action_grant(
        plan,
        tool_name,
        str(event.get("plan_step_id", "")),
    )
    allowed_actions = [str(item) for item in plan.get("allowed_actions", []) if item]
    allowed_effects = {str(item) for item in plan.get("allowed_effects", []) if item}
    forbidden_effects = {str(item) for item in plan.get("forbidden_effects", []) if item}
    allowed_suites = {str(item) for item in plan.get("allowed_suites", []) if item}
    planned = matched_action_grant is not None or any(same_tool_name(tool_name, allowed) for allowed in allowed_actions)
    matched_allowed_action = next(
        (allowed for allowed in allowed_actions if same_tool_name(tool_name, allowed)),
        (str(matched_action_grant.get("name", "")) if isinstance(matched_action_grant, Mapping) else ""),
    )
    plan_suite = (
        matched_allowed_action.split("__", 1)[0]
        if "__" in matched_allowed_action and matched_allowed_action.split("__", 1)[0] in allowed_suites
        else (next(iter(allowed_suites)) if planned and len(allowed_suites) == 1 else "")
    )
    tool_suite = (
        str(event.get("tool_suite") or "")
        or (tool_name.split("__", 1)[0] if "__" in tool_name else "")
        or str(event.get("app_domain") or "")
        or (str(event.get("target_app") or "") if str(event.get("target_app") or "") in allowed_suites else "")
        or plan_suite
        or (domain_for_tool(tool_name) or "")
    )
    action_steps = plan.get("action_steps", {}) if isinstance(plan.get("action_steps"), Mapping) else {}
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
        "grant_valid": (
            matched_action_grant.get("grant_valid", True) if isinstance(matched_action_grant, Mapping) else False
        ),
        "grant_errors": list(
            matched_action_grant.get("grant_errors", []) if isinstance(matched_action_grant, Mapping) else []
        ),
    }
    result["capability_decision"] = result["authorization"]
    if isinstance(matched_action_grant, Mapping) and matched_action_grant.get("grant_valid", True) is False:
        grant_errors = [str(item) for item in matched_action_grant.get("grant_errors", []) if str(item).strip()]
        result.update(
            passed=False,
            reason=("action_grant_invalid:" + (",".join(grant_errors) or "unspecified")),
            grant_errors=grant_errors,
        )
        return _ring2_decision(
            event,
            result,
            plan,
            tool_name=tool_name,
            decision=DECISION_BLOCK,
        )
    injection = (
        event.get("input_flow_label", {}).get("injection", {})
        if isinstance(event.get("input_flow_label"), Mapping)
        else {}
    )
    control_arguments = _control_arguments(event)
    risk_arguments = list(control_arguments)
    if effect in {"write", "privilege"}:
        inputs = event.get("inputs")
        if isinstance(inputs, Mapping):
            risk_arguments = sorted(str(name) for name, value in inputs.items() if _has_egress_value(value))
    risky_control_arguments, risky_entities, source_risk_evidence = _risky_control_arguments(event, risk_arguments)
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

    data_access_required = int(plan.get("schema_version", 1) or 1) >= 4
    parameter_resolution_errors = [
        str(item) for item in event.get("parameter_resolution_errors", []) if str(item).strip()
    ]
    if parameter_resolution_errors:
        result.update(
            passed=False,
            reason=parameter_resolution_errors[0],
            parameter_resolution_errors=(parameter_resolution_errors),
        )
        return _ring2_decision(
            event,
            result,
            plan,
            tool_name=tool_name,
            decision=DECISION_BLOCK,
        )
    access_contract = action_data_access(
        plan,
        tool_name,
        str(event.get("plan_step_id", "")),
    )
    resource_failures = validate_resource_access(
        access_contract,
        event,
        source_registry=(
            plan.get("source_refs", {})
            if isinstance(plan.get("source_refs", {}), Mapping)
            else {}
        ),
    )
    result["data_access"] = access_contract
    result["resource_access_failures"] = resource_failures
    if data_access_required and (
        not isinstance(access_contract, Mapping) or not access_contract.get("valid", False) or resource_failures
    ):
        result.update(
            passed=False,
            reason=(resource_failures[0] if resource_failures else "data_access_contract_invalid"),
        )
        return _ring2_decision(
            event,
            result,
            plan,
            tool_name=tool_name,
            decision=DECISION_BLOCK,
        )
    access = access_contract if isinstance(access_contract, Mapping) else {}
    if effect != "read" and access.get("visible_fields"):
        try:
            ensure_sensitivity_detector_ready()
        except Exception as exc:
            result.update(
                passed=False,
                reason=f"sensitivity_detector_unavailable:{exc}",
            )
            return _ring2_decision(
                event,
                result,
                plan,
                tool_name=tool_name,
                decision=DECISION_BLOCK,
            )
    if effect != "read" and policy.resource_fields:
        access_contract = action_resource_access(
            plan,
            tool_name,
            str(event.get("plan_step_id", "")),
        )
        resource_failures = validate_resource_access(
            access_contract,
            event,
            source_registry=(
                plan.get("source_refs", {})
                if isinstance(plan.get("source_refs", {}), Mapping)
                else {}
            ),
        )
        result["resource_access"] = access_contract
        result["resource_access_failures"] = resource_failures
        if data_access_required and (
            not isinstance(access_contract, Mapping) or not access_contract.get("valid", False) or resource_failures
        ):
            result.update(
                passed=False,
                reason=(resource_failures[0] if resource_failures else "resource_access_contract_invalid"),
            )
            return _ring2_decision(
                event,
                result,
                plan,
                tool_name=tool_name,
                decision=DECISION_BLOCK,
            )

    if (
        effect in {"read", "write"}
        and policy.risk_level != "L2"
        and access.get(
            "requires_exposure_authorization",
            False,
        )
    ):
        exposure_check = {
            "action": tool_name,
            "inspection_fields": list(
                access.get(
                    "protected_visible_fields",
                    [],
                )
            ),
            "opaque_fields": list(access.get("opaque_fields", [])),
            "max_exposure_level": str(
                access.get(
                    "max_exposure_level",
                    "internal",
                )
            ),
            "field_policies": copy.deepcopy(access.get("exposure_modes", {})),
        }
        result.update(
            reason="sensitive_data_exposure_authorization_required",
            confirmation_required=True,
            confirmation_kind="sensitive_data_exposure",
            exposure_check=exposure_check,
            exposure_authorization_required=True,
        )
        return _ring2_decision(
            event,
            result,
            plan,
            tool_name=tool_name,
            decision=DECISION_HOLD,
            event_kind="policy",
            policy_id="ring2.sensitive_data_exposure_confirmation",
        )

    result.update(
        reason="action_authorized",
        matched_step=str(event.get("plan_step_id", ""))
        or next(
            (str(step) for action, step in action_steps.items() if same_tool_name(tool_name, str(action))),
            "",
        ),
    )
    if policy.risk_level == "L2":
        l2_actions = {str(item) for item in plan.get("l2_actions", []) if item}
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
            (str(step) for action, step in action_steps.items() if same_tool_name(tool_name, str(action))),
            "",
        )
        matched_step = next(
            (
                step
                for step in plan.get("steps", [])
                if isinstance(step, Mapping) and str(step.get("id")) == matched_step_id
            ),
            {},
        )
        plan_steps = {
            str(step.get("id", "")): step
            for step in plan.get("steps", [])
            if isinstance(step, Mapping) and step.get("id")
        }
        missing_dependencies = [
            str(dependency)
            for dependency in matched_step.get("depends_on", [])
            if str(dependency) not in completed_steps
            and any(
                isinstance(action, Mapping) and str(action.get("name", "")).strip()
                for action in (
                    plan_steps.get(str(dependency), {}).get(
                        "actions",
                        [],
                    )
                    if isinstance(
                        plan_steps.get(str(dependency)),
                        Mapping,
                    )
                    else []
                )
            )
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
        if grant.get("max_calls_mode") == "derived_cardinality":
            resolutions = (
                event.get("plan_usage", {}).get(
                    "l2_cardinality_resolutions",
                    {},
                )
                if isinstance(event.get("plan_usage"), Mapping)
                else {}
            )
            resolution = (
                next(
                    (
                        value
                        for action, value in resolutions.items()
                        if same_tool_name(tool_name, str(action)) and isinstance(value, Mapping)
                    ),
                    {},
                )
                if isinstance(resolutions, Mapping)
                else {}
            )
            if resolution.get("status") != "resolved":
                result.update(
                    passed=False,
                    reason="l2_cardinality_unresolved",
                )
                return _ring2_decision(
                    event,
                    result,
                    plan,
                    tool_name=tool_name,
                    decision=DECISION_BLOCK,
                )
            target_parameter = str(resolution.get("target_parameter", ""))
            semantic_type = str(resolution.get("semantic_type", ""))
            targets = {
                canonicalize_resource_value(item, semantic_type)
                for item in resolution.get("targets", [])
                if item not in (None, "")
            }
            inputs = event.get("inputs", {}) if isinstance(event.get("inputs"), Mapping) else {}
            requested_targets = [
                canonicalize_resource_value(item, semantic_type)
                for item in _flatten_scalars(inputs.get(target_parameter))
            ]
            if not requested_targets or any(item not in targets for item in requested_targets):
                result.update(
                    passed=False,
                    reason="l2_target_not_authorized",
                )
                return _ring2_decision(
                    event,
                    result,
                    plan,
                    tool_name=tool_name,
                    decision=DECISION_BLOCK,
                )
            per_target_limit = int(resolution.get("per_target_max_calls", 1) or 1)
            used_targets = _successful_action_targets(
                event.get("plan_usage"),
                tool_name,
            )
            if any(used_targets.get(item, 0) >= per_target_limit for item in requested_targets):
                result.update(
                    passed=False,
                    reason="l2_target_already_used",
                )
                return _ring2_decision(
                    event,
                    result,
                    plan,
                    tool_name=tool_name,
                    decision=DECISION_BLOCK,
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
    if effect in {"write", "privilege", "egress"}:
        allowed_calls = _planned_action_call_limit(
            plan,
            tool_name,
        )
        current_count = _successful_action_count(
            event.get("plan_usage"),
            tool_name,
        )
        if current_count >= allowed_calls:
            result.update(
                passed=False,
                reason="action_call_limit_exceeded",
                allowed_calls=allowed_calls,
                current_count=current_count,
            )
            return _ring2_decision(
                event,
                result,
                plan,
                tool_name=tool_name,
                decision=DECISION_BLOCK,
            )
    if source_flagged and effect == "write":
        result.update(
            reason="source_risk_confirmation_required",
            confirmation_required=True,
            source_risk=True,
            source_risk_reason="write_from_source_risk",
        )
        return _ring2_decision(
            event,
            result,
            plan,
            tool_name=tool_name,
            decision=DECISION_HOLD,
            event_kind="policy",
            policy_id="ring2.source_risk_confirmation",
        )
    if source_flagged:
        result.update(
            source_risk=True,
            source_risk_reason="planned_action_from_source_risk",
        )
    return result


def _ring2_block_category(reason_key: str) -> BlockCategory:
    if reason_key in {
        "forbidden_effect",
        "action_not_bound_to_task_scope",
        "suite_not_bound_to_task_scope",
        "effect_not_bound_to_task_scope",
        "l2_not_in_initial_plan",
        "l2_dependencies_unmet",
        "l2_call_limit_exceeded",
        "l2_target_already_used",
        "l2_target_not_authorized",
        "action_call_limit_exceeded",
        "resource_not_authorized",
        "resource_source_not_authorized",
        "resource_value_missing",
    }:
        return BLOCK_CATEGORY_OUT_OF_SCOPE
    if reason_key == "resource_required_source_missing":
        return BLOCK_CATEGORY_PROVENANCE
    if reason_key in {
        "action_grant_invalid",
        "task_scope_unavailable",
        "data_access_contract_invalid",
        "resource_access_contract_invalid",
        "l2_cardinality_unresolved",
    } or reason_key.startswith("sensitivity_detector_unavailable"):
        return BLOCK_CATEGORY_SYSTEM_UNAVAILABLE
    if reason_key.startswith("placeholder"):
        return BLOCK_CATEGORY_INVALID_ACTION
    if reason_key.startswith("parameter_"):
        return BLOCK_CATEGORY_PROVENANCE
    return BLOCK_CATEGORY_SYSTEM_UNAVAILABLE


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
    reason_key = reason_code.split(":", 1)[0]
    block_category = _ring2_block_category(reason_key)
    reason_descriptions = {
        "forbidden_effect": "the requested effect is explicitly forbidden by the task",
        "action_not_bound_to_task_scope": "the tool is not included in the current task plan",
        "action_grant_invalid": "the planned tool action has an invalid authorization grant",
        "effect_not_bound_to_task_scope": "the tool effect is not authorized by the current task plan",
        "l2_not_in_initial_plan": "the L2 action was not authorized in the initial task plan",
        "l2_dependencies_unmet": "required earlier task steps have not completed",
        "l2_call_limit_exceeded": "the L2 call limit from the initial grant was exceeded",
        "action_call_limit_exceeded": (
            "the non-read action call limit from the task plan was exceeded"
        ),
        "task_scope_unavailable": "the task authorization plan is unavailable or invalid",
        "data_access_contract_invalid": ("the read action has no valid resource or field exposure grant"),
        "resource_access_contract_invalid": ("the action has no valid resource-scope grant"),
        "resource_not_authorized": ("the requested resource identifier is outside the task grant"),
        "resource_value_missing": ("a resource selector required by the action is missing"),
        "resource_source_not_authorized": ("the resource selector was derived from an unauthorized source"),
        "resource_required_source_missing": ("the required source for the resource selector was not evidenced"),
    }
    if decision == DECISION_ADVISORY:
        reason = f"Tool {tool_name} is allowed with an audit advisory ({reason_code})."
        severity = "medium"
        fsm_before = "ACTION_PROPOSED"
        fsm_after = "ADVISED"
    elif decision == DECISION_HOLD:
        if result.get("confirmation_kind") == "sensitive_data_exposure":
            exposure = result.get("exposure_check", {})
            protected_fields = (
                ", ".join(
                    str(item)
                    for item in exposure.get(
                        "inspection_fields",
                        [],
                    )
                )
                or "计划声明的敏感字段"
            )
            reason = (
                f"Tool {tool_name} would expose {protected_fields} to the "
                "Agent for task-required comparison or analysis; explicit "
                "user authorization is required before the read executes."
            )
            severity = "high"
            fsm_before = "ACTION_PROPOSED"
            fsm_after = "HELD"
            hold_risk = make_risk(
                2,
                decision,
                reason,
                severity=severity,
                event_kind=event_kind,
                policy_id=policy_id,
                activity_id=event.get("activity_id"),
                sink_ids=[tool_name],
                fsm_before=fsm_before,
                fsm_after=fsm_after,
            )
            hold_risk.update(
                {
                    "plan_id": str(plan.get("plan_id", "")),
                    "plan_hash": str(plan.get("plan_hash", "")),
                    "matched_step": result.get(
                        "matched_step",
                        "",
                    ),
                    "actual_action": tool_name,
                    "actual_effect": result.get(
                        "authorization",
                        {},
                    ).get("effect", ""),
                    "exposure_fields": list(exposure.get("inspection_fields", [])),
                    "block_category": BLOCK_CATEGORY_CONFIRMATION,
                }
            )
            return {
                **result,
                "passed": True,
                "decision": decision,
                "reason": reason,
                "reason_code": reason_code,
                "severity": severity,
                "fsm_before": fsm_before,
                "fsm_after": fsm_after,
                "confirmation_required": True,
                "confirmation_kind": "sensitive_data_exposure",
                "exposure_check": exposure,
                "event_kind": event_kind,
                "policy_id": policy_id,
                "block_category": BLOCK_CATEGORY_CONFIRMATION,
                "risk": hold_risk,
            }
        risk_level = str(
            result.get("authorization", {}).get(
                "risk_level",
                "L2",
            )
        )
        reason = (
            f"{risk_level} tool {tool_name} is in the authorized call chain and requires explicit user confirmation."
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
            reason_key,
            reason_code or "an unspecified Ring 2 policy condition",
        )
        reason = f"Ring 2 blocked {tool_name}: {detail} ({reason_code or 'unspecified'})."
        severity = "high"
        fsm_before = "ACTION_PROPOSED"
        fsm_after = "BLOCKED"
    if decision == DECISION_HOLD:
        block_category = BLOCK_CATEGORY_CONFIRMATION
    plan_confidence = plan.get("confidence")
    risk = make_risk(
        2,
        decision,
        reason,
        severity=severity,
        event_kind=event_kind,
        policy_id=policy_id,
        activity_id=event.get("activity_id"),
        source_ids=(
            (result.get("source_risk_evidence", []) or result.get("injection_evidence", []))
            if result.get("source_flagged")
            else []
        ),
        taint_roots=(
            (result.get("source_risk_evidence", []) or result.get("injection_evidence", []))
            if result.get("source_flagged")
            else []
        ),
        sink_ids=[tool_name],
        fsm_before=fsm_before,
        fsm_after=fsm_after,
        confidence=(float(plan_confidence) if isinstance(plan_confidence, int | float | str) else None),
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
            "risky_control_arguments": list(result.get("risky_control_arguments", [])),
            "risky_entities": list(result.get("risky_entities", [])),
            "block_category": block_category,
        }
    )
    result["block_category"] = block_category
    result["risk"] = risk
    return result


def _flatten_scalars(value: Any) -> list[str]:
    if isinstance(value, Mapping):
        result: list[str] = []
        for child in value.values():
            result.extend(_flatten_scalars(child))
        return result
    if isinstance(value, list | tuple | set):
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
    if isinstance(value, list | tuple | set | dict):
        return bool(value)
    return True


def _normalise(value: str) -> str:
    return " ".join(str(value).casefold().split())


def _egress_block_category(
    failures: Sequence[str],
) -> BlockCategory:
    reason_codes = {
        str(failure).split(":", 1)[0]
        for failure in failures
        if str(failure).strip()
    }
    if reason_codes & {
        "data_source_not_authorized",
        "destination_not_authorized",
        "parameter_source_ref_not_allowed",
    }:
        return BLOCK_CATEGORY_AUTHORIZATION
    if "confidentiality_exceeds_sink_limit" in reason_codes:
        return BLOCK_CATEGORY_CONFIDENTIALITY
    if reason_codes & {
        "implicit_egress_input_invalid",
        "implicit_egress_resource_not_found",
        "unresolved_placeholder_in_payload",
    }:
        return BLOCK_CATEGORY_INVALID_ACTION
    if "implicit_egress_sensitivity_unavailable" in reason_codes:
        return BLOCK_CATEGORY_SYSTEM_UNAVAILABLE
    if reason_codes & {
        "data_source_unresolved",
        "egress_argument_without_provenance",
        "parameter_source_action_missing",
        "parameter_source_path_missing",
        "parameter_source_path_scope_missing",
    }:
        return BLOCK_CATEGORY_PROVENANCE
    return BLOCK_CATEGORY_SYSTEM_UNAVAILABLE


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
        "data_field_levels": [],
        "provenance_refs": [],
        "parameter_provenance": {},
        "parameter_generation": {},
        "data_field_refs": [],
        "allowed_data_sources": [],
        "unverified_arguments": [],
        "implicit_egress": [],
        "provenance_state": "not_evaluated",
        "provenance_warnings": list(event.get("parameter_resolution_warnings", [])),
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
    binding_paths: dict[str, set[str]] = {}
    binding_source_refs: dict[
        str,
        set[tuple[str, str, str, str]],
    ] = {}
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
            block_category=BLOCK_CATEGORY_SYSTEM_UNAVAILABLE,
        )
    else:
        policy = tool_effect(tool_name)
        inputs = event.get("inputs")
        inputs = dict(inputs) if isinstance(inputs, Mapping) else {}
        implicit_egress = [dict(item) for item in event.get("implicit_egress", []) if isinstance(item, Mapping)]
        implicit_destinations = sorted(
            {str(recipient) for item in implicit_egress for recipient in item.get("recipients", []) if recipient}
        )
        implicit_content_labels = [
            item.get("flow_label") for item in implicit_egress if isinstance(item.get("flow_label"), Mapping)
        ]
        implicit_errors = [
            str(item.get("error", "")) for item in implicit_egress if not item.get("resolved") and item.get("error")
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
            field for field in sorted(policy.destination_fields) if _has_egress_value(inputs.get(field))
        ]
        destination_parameters = sorted(
            {
                *contract_destination_parameters,
                *actual_destination_parameters,
            }
        )
        destination_values_by_parameter = {
            field: [value for value in _flatten_scalars(inputs.get(field)) if value] for field in destination_parameters
        }
        parameter_destinations = sorted(
            {value for values in destination_values_by_parameter.values() for value in values}
        )
        destinations = sorted(set(parameter_destinations) | set(implicit_destinations))
        raw_destination = contract.get("destination")
        destination = dict(raw_destination) if isinstance(raw_destination, Mapping) else {}
        mode = str(destination.get("mode", "literal")).lower()
        resolution_map = {
            str(item.get("parameter", "")): item
            for item in event.get("parameter_resolutions", [])
            if isinstance(item, Mapping)
        }
        implicit_resource_ok = all(bool(item.get("resolved")) for item in implicit_egress)

        def resolution_status(parameter: str) -> str:
            resolution = resolution_map.get(parameter, {})
            return str(resolution.get("status", "")) if isinstance(resolution, Mapping) else ""

        implicit_resolution_ok = all(
            resolution_status(str(item.get("id_parameter", ""))) == "resolved" for item in implicit_egress
        )
        if mode == "derived":
            destination_ok = (
                bool(destinations)
                and implicit_resource_ok
                and implicit_resolution_ok
                and all(resolution_status(parameter) == "resolved" for parameter in actual_destination_parameters)
            )
            destination_state = "derived_authorized" if destination_ok else "unauthorized"
        else:
            allowed_values = [item for item in destination.get("allowed_values", []) if item]
            raw_semantic_types = destination.get("semantic_types", {})
            semantic_types = dict(raw_semantic_types) if isinstance(raw_semantic_types, Mapping) else {}

            def destination_value_allowed(
                parameter: str,
                value: Any,
            ) -> bool:
                semantic_type = str(semantic_types.get(parameter, ""))
                if not semantic_type:
                    allowed = {_normalise(item) for item in allowed_values}
                    return _normalise(value) in allowed
                canonical_value = canonicalize_resource_value(
                    value,
                    semantic_type,
                )
                return any(
                    canonicalize_resource_value(
                        item,
                        semantic_type,
                    )
                    == canonical_value
                    for item in allowed_values
                )

            destination_ok = (
                bool(parameter_destinations)
                and all(
                    destination_value_allowed(parameter, value)
                    for parameter, values in (destination_values_by_parameter.items())
                    for value in values
                )
                and implicit_resource_ok
            )
            destination_state = "fixed_authorized" if destination_ok else "unauthorized"

        argument_labels = event.get("argument_flow_labels")
        argument_labels = argument_labels if isinstance(argument_labels, Mapping) else {}
        content_labels = [
            label
            for field, label in argument_labels.items()
            if field not in destination_parameters and isinstance(label, Mapping)
        ]
        content_labels.extend(label for label in implicit_content_labels if isinstance(label, Mapping))
        if not content_labels:
            content_labels = [event.get("input_flow_label", {})]
        confidentiality = join_confidentiality(
            [label.get("confidentiality", {}) for label in content_labels if isinstance(label, Mapping)]
        )
        categories = list(confidentiality.get("categories", []))
        ancestor_source_entities = sorted(str(item) for item in confidentiality.get("source_entities", []) if item)
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
                    "generation_kind": str(resolution.get("generation_kind", "")),
                    "validation_mode": str(resolution.get("validation_mode", "structured")),
                    "semantic_type": str(resolution.get("semantic_type", "")),
                    "parameter_role": str(resolution.get("parameter_role", "")),
                    "constraints": copy.deepcopy(resolution.get("constraints", {})),
                    "explanation": str(resolution.get("explanation", "")),
                    "confidence": resolution.get("confidence"),
                    "semantic_supported": resolution.get("semantic_supported"),
                }
            resolution_refs = [
                dict(item)
                for item in resolution.get("provenance_refs", [])
                if isinstance(item, Mapping) and item.get("ref_id")
            ]
            provenance_refs.extend(resolution_refs)
            parameter_provenance[parameter] = sorted({str(item["ref_id"]) for item in resolution_refs})
            evidence_items = [dict(item) for item in resolution.get("source_evidence", []) if isinstance(item, Mapping)]
            if not evidence_items:
                source_paths = [str(item) for item in resolution.get("source_paths", []) if item]
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
                                "authoritative": bool(resolution.get("authoritative", False)),
                                "value_hash": str(resolution.get("value_hash", "")),
                            }
                        )
            for evidence in evidence_items:
                if not isinstance(evidence, Mapping):
                    continue
                matching_ref = next(
                    (
                        item
                        for item in provenance_refs
                        if str(item.get("app", "")) == str(evidence.get("app", ""))
                        and str(item.get("entity", "")) == str(evidence.get("entity", ""))
                        and str(item.get("entity_id", "")) == str(evidence.get("entity_id", ""))
                        and str(item.get("source_action", "")) == str(evidence.get("source_action", ""))
                        and str(item.get("source_path", "")) == str(evidence.get("source_path", ""))
                        and item.get("start") == evidence.get("start")
                        and item.get("end") == evidence.get("end")
                    ),
                    {},
                )
                field_sources.append(
                    {
                        "parameter": parameter,
                        "ref_id": str(matching_ref.get("ref_id", "")),
                        "source_id": str(matching_ref.get("source_id", "")),
                        "source": f"{evidence.get('app', '')}:{evidence.get('entity', '')}",
                        "source_entity_id": str(evidence.get("entity_id", "")),
                        "source_action": str(evidence.get("source_action", "")),
                        "source_activity_id": str(matching_ref.get("activity_id", "")),
                        "source_path": str(evidence.get("source_path", "")),
                        "start": evidence.get("start"),
                        "end": evidence.get("end"),
                        "extracted_text": str(evidence.get("extracted_text", "")),
                        "authoritative": bool(evidence.get("authoritative", False)),
                        "value_hash": str(evidence.get("value_hash", "")),
                        "confidentiality": str(
                            matching_ref.get(
                                "confidentiality",
                                evidence.get("confidentiality", ""),
                            )
                        ),
                        "categories": list(
                            matching_ref.get(
                                "categories",
                                evidence.get("categories", []),
                            )
                        ),
                        "sensitivity_policy": copy.deepcopy(
                            matching_ref.get(
                                "sensitivity_policy",
                                evidence.get("sensitivity_policy", {}),
                            )
                        ),
                    }
                )
        provenance_refs = list({str(item["ref_id"]): item for item in provenance_refs}.values())
        data_field_refs = [
            {
                "ref_id": str(item.get("ref_id", "")),
                "parameters": sorted(
                    parameter for parameter, ref_ids in parameter_provenance.items() if item.get("ref_id") in ref_ids
                ),
                "source_id": str(item.get("source_id", "")),
                "source": f"{item.get('app', '')}:{item.get('entity', '')}",
                "source_action": str(item.get("source_action", "")),
                "source_path": str(item.get("source_path", "")),
            }
            for item in provenance_refs
        ]
        data_field_levels = [
            {
                "parameter": str(item.get("parameter", "")),
                "source": str(item.get("source", "")),
                "source_entity_id": str(item.get("source_entity_id", "")),
                "source_path": str(item.get("source_path", "")),
                "level": str(
                    item.get(
                        "confidentiality",
                        source_level(str(item.get("source", ""))),
                    )
                ),
                "categories": list(item.get("categories", [])),
            }
            for item in field_sources
        ]
        implicit_data_fields: list[str] = []
        for item in implicit_egress:
            source = item.get("source", {}) if isinstance(item.get("source"), Mapping) else {}
            content_levels = (
                item.get("content_field_levels", {})
                if isinstance(
                    item.get("content_field_levels"),
                    Mapping,
                )
                else {}
            )
            content_policies = (
                item.get("content_field_policies", {})
                if isinstance(
                    item.get("content_field_policies"),
                    Mapping,
                )
                else {}
            )
            for field, field_confidentiality in content_levels.items():
                source_path = f"$.{field}"
                parameter = str(item.get("id_parameter", ""))
                implicit_data_fields.append(f"{parameter}:{source_path}")
                policy = (
                    content_policies.get(field, {})
                    if isinstance(
                        content_policies.get(field),
                        Mapping,
                    )
                    else {}
                )
                data_field_levels.append(
                    {
                        "parameter": parameter,
                        "source": (f"{source.get('app', '')}:{source.get('entity', '')}"),
                        "source_entity_id": str(source.get("entity_id", "")),
                        "source_path": source_path,
                        "level": str(field_confidentiality),
                        "categories": list(policy.get("categories", [])),
                        "implicit_resource": True,
                    }
                )
        parameter_bindings = contract.get("parameter_bindings", {})
        if isinstance(parameter_bindings, Mapping):
            contract_source_bindings = contract.get("source_bindings", {})
            contract_source_bindings = contract_source_bindings if isinstance(contract_source_bindings, Mapping) else {}
            for parameter, raw_binding in parameter_bindings.items():
                if not isinstance(raw_binding, Mapping):
                    continue
                paths = {
                    normalize_data_path(item)
                    for item in raw_binding.get(
                        "allowed_source_paths",
                        [],
                    )
                    if str(item).strip()
                }
                copy_path = raw_binding.get("source_path")
                if copy_path and str(copy_path) != "sources":
                    paths.add(normalize_data_path(str(copy_path)))
                for source_ref in raw_binding.get(
                    "allowed_source_refs",
                    [],
                ):
                    if isinstance(source_ref, Mapping) and source_ref.get("source_path"):
                        paths.add(normalize_data_path(str(source_ref["source_path"])))
                if paths:
                    binding_paths[str(parameter)] = paths
                allowed_refs = {
                    (
                        str(source_ref.get("app", "")).lower(),
                        canonical_entity_name(
                            str(source_ref.get("app", "")),
                            str(source_ref.get("entity", "")),
                        ),
                        base_tool_name(str(source_ref.get("source_action", ""))),
                        normalize_data_path(str(source_ref.get("source_path", ""))),
                    )
                    for source_ref in raw_binding.get(
                        "allowed_source_refs",
                        [],
                    )
                    if isinstance(source_ref, Mapping)
                    and source_ref.get("source_action")
                    and source_ref.get("source_path")
                }
                copy_action = str(
                    raw_binding.get(
                        "source_action",
                        raw_binding.get("source_tool", ""),
                    )
                ).strip()
                copy_source = contract_source_bindings.get(
                    str(raw_binding.get("source_id", "")),
                    {},
                )
                copy_source = copy_source if isinstance(copy_source, Mapping) else {}
                copy_app = str(copy_source.get("app") or raw_binding.get("app", ""))
                copy_entity = str(copy_source.get("entity") or raw_binding.get("entity", ""))
                copy_action = str(copy_source.get("source_action") or copy_action)
                raw_copy_path = str(raw_binding.get("source_path", "")).strip()
                copy_path = normalize_data_path(raw_copy_path)
                if copy_action and raw_copy_path and raw_copy_path != "sources":
                    allowed_refs.add(
                        (
                            copy_app.lower(),
                            canonical_entity_name(
                                copy_app,
                                copy_entity,
                            ),
                            base_tool_name(copy_action),
                            copy_path,
                        )
                    )
                if allowed_refs:
                    binding_source_refs[str(parameter)] = allowed_refs
        direct_source_entities = sorted(
            {
                str(item.get("source", ""))
                for item in field_sources
                if item.get("source") and str(item.get("parameter", "")) not in destination_parameters
            }
            | {
                str(source)
                for label in implicit_content_labels
                if isinstance(label, Mapping)
                for source in (
                    label.get("confidentiality", {}) if isinstance(label.get("confidentiality"), Mapping) else {}
                ).get("source_entities", [])
                if source
            }
        )
        if not direct_source_entities:
            direct_source_entities = list(ancestor_source_entities)
        allowed_sources = {str(item) for item in contract.get("data_sources", []) if item}
        level = str(confidentiality.get("level", "secret")).lower()
        max_level = str(contract.get("max_confidentiality", "secret")).lower()
        resolution_errors = [str(item) for item in event.get("parameter_resolution_errors", []) if item]
        provenance_state = (
            "invalid" if resolution_errors else ("incomplete" if result.get("provenance_warnings") else "complete")
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
                {f"{item['parameter']}:{item['source_path']}" for item in field_sources if item.get("source_path")}
                | set(implicit_data_fields)
            ),
            data_field_levels=data_field_levels,
            implicit_egress=implicit_egress,
            allowed_data_sources=sorted(allowed_sources),
            payload_sources=sorted(
                {
                    str(item)
                    for item in contract.get(
                        "payload_sources",
                        [],
                    )
                    if str(item).strip()
                }
            ),
            control_sources=sorted(
                {
                    str(item)
                    for item in contract.get(
                        "control_sources",
                        [],
                    )
                    if str(item).strip()
                }
            ),
            max_confidentiality=max_level,
            provenance_state=provenance_state,
        )

        failures: list[str] = []
        if not destination_ok:
            failures.append("destination_not_authorized")
        failures.extend(implicit_errors)
        binding_errors = [str(item) for item in event.get("parameter_resolution_errors", []) if item]
        if binding_errors:
            failures.extend(binding_errors)
        field_path_failures = []
        for source in field_sources:
            parameter = str(source.get("parameter", ""))
            allowed_paths = binding_paths.get(parameter)
            allowed_refs = binding_source_refs.get(parameter, set())
            source_path = normalize_data_path(str(source.get("source_path", "")))
            source_action = str(source.get("source_action", "")).strip()
            actual_ref = (
                str(source.get("source", "")).split(":", 1)[0].lower(),
                canonical_entity_name(
                    str(source.get("source", "")).split(":", 1)[0],
                    str(source.get("source", "")).partition(":")[2],
                ),
                base_tool_name(source_action),
                source_path,
            )
            binding = parameter_bindings.get(parameter, {})
            binding = binding if isinstance(binding, Mapping) else {}
            presentation_binding = (
                str(binding.get("generation_kind", "")).lower() == "presentation"
                or str(binding.get("parameter_role", "")).lower() == "presentation"
            )
            presentation_entity_allowed = presentation_binding and any(
                actual_ref[:3] == allowed_ref[:3] for allowed_ref in allowed_refs
            )
            if not source_path:
                field_path_failures.append(f"parameter_source_path_missing:{parameter}")
            elif not allowed_paths:
                field_path_failures.append(f"parameter_source_path_scope_missing:{parameter}")
            elif not source_action:
                field_path_failures.append(f"parameter_source_action_missing:{parameter}")
            elif actual_ref not in allowed_refs and not presentation_entity_allowed:
                field_path_failures.append(
                    f"parameter_source_ref_not_allowed:{parameter}:{source_action}:{source_path}"
                )
        failures.extend(field_path_failures)
        if contains_placeholder(inputs):
            failures.append("unresolved_placeholder_in_payload")
        unverified_arguments: list[str] = []
        for field, value in inputs.items():
            field_name = str(field)
            if not _has_egress_value(value) or field_name in destination_parameters:
                continue
            parameter_binding = parameter_bindings.get(field_name, {})
            if (
                isinstance(parameter_binding, Mapping)
                and str(parameter_binding.get("mode", "")).lower() == "literal"
                and str(parameter_binding.get("source_kind", "")).lower() == "user_prompt"
                and parameter_values_equal(
                    value,
                    parameter_binding.get("value"),
                )
            ):
                continue
            label = argument_labels.get(field_name)
            confidentiality = label.get("confidentiality", {}) if isinstance(label, Mapping) else {}
            source_entities = (
                [str(item) for item in confidentiality.get("source_entities", []) if item]
                if isinstance(confidentiality, Mapping)
                else []
            )
            source_ids = (
                [str(item) for item in confidentiality.get("source_ids", []) if item]
                if isinstance(confidentiality, Mapping)
                else []
            )
            if not source_entities and not source_ids:
                unverified_arguments.append(field_name)
        result["unverified_arguments"] = unverified_arguments
        if unverified_arguments and result.get("provenance_state") == "complete":
            result["provenance_state"] = "incomplete"
            result["provenance_warnings"].extend(
                f"egress_argument_without_provenance:{field}" for field in unverified_arguments
            )
            result["provenance_warnings"] = list(dict.fromkeys(result["provenance_warnings"]))
        if unverified_arguments:
            failures.extend(f"egress_argument_without_provenance:{field}" for field in unverified_arguments)
        if (
            CONFIDENTIALITY_LEVELS.get(level, 3) > CONFIDENTIALITY_LEVELS["internal"]
            and not ancestor_source_entities
            and not field_sources
        ):
            failures.append("data_source_unresolved")
            if result.get("provenance_state") == "complete":
                result["provenance_state"] = "incomplete"
                result["provenance_warnings"].append("data_source_unresolved")
        if direct_source_entities and not set(direct_source_entities).issubset(allowed_sources):
            failures.append("data_source_not_authorized")
        if CONFIDENTIALITY_LEVELS.get(level, 3) > CONFIDENTIALITY_LEVELS.get(max_level, 0):
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
                "data_field_levels": data_field_levels,
                "allowed_parameter_source_paths": {
                    parameter: sorted(paths) for parameter, paths in binding_paths.items()
                },
                "unverified_arguments": unverified_arguments,
                "implicit_egress": implicit_egress,
                "allowed_data_sources": sorted(allowed_sources),
                "payload_sources": result.get(
                    "payload_sources",
                    [],
                ),
                "control_sources": result.get(
                    "control_sources",
                    [],
                ),
                "sink": tool_name,
            }
            confidentiality_sync = event.get("egress_confidentiality_sync")
            if isinstance(confidentiality_sync, Mapping):
                previous_limit = str(
                    confidentiality_sync.get(
                        "previous_max_confidentiality",
                        "internal",
                    )
                )
                current_limit = str(
                    confidentiality_sync.get(
                        "max_confidentiality",
                        level,
                    )
                )
                result["reason"] = "authorized_sensitive_egress_after_runtime_sync"
                result["authorization"]["runtime_confidentiality_sync"] = dict(confidentiality_sync)
                result["risk"] = make_risk(
                    3,
                    DECISION_ADVISORY,
                    (
                        f"Sensitive egress through {tool_name} passed the "
                        f"final payload review with a scoped confidentiality "
                        f"limit update ({previous_limit} -> {current_limit}); "
                        "L2 action confirmation remains required."
                    ),
                    severity="high",
                    event_kind="security",
                    policy_id="ring3.sensitive_egress",
                    activity_id=event.get("activity_id"),
                    source_ids=result.get("data_sources", []),
                    sink_ids=[tool_name],
                    fsm_before="ACTION_PROPOSED",
                    fsm_after="ADMITTED",
                    confidence=1.0,
                )
        else:
            result.update(
                passed=False,
                reason=";".join(dict.fromkeys(failures)),
            )

    if not result["passed"]:
        result["block_category"] = (
            result.get("block_category")
            or _egress_block_category(
                [
                    str(item)
                    for item in result.get("reason", "").split(";")
                    if str(item).strip()
                ]
            )
        )
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
            "data_field_levels": result.get("data_field_levels", []),
            "allowed_parameter_source_paths": {parameter: sorted(paths) for parameter, paths in binding_paths.items()},
            "unverified_arguments": result.get(
                "unverified_arguments",
                [],
            ),
            "implicit_egress": result.get("implicit_egress", []),
            "allowed_data_sources": result.get("allowed_data_sources", []),
            "payload_sources": result.get("payload_sources", []),
            "control_sources": result.get("control_sources", []),
            "sink": tool_name,
        }
        result["risk"] = make_risk(
            3,
            DECISION_BLOCK,
            (f"Sensitive egress through {tool_name} is not authorized ({result['reason']})."),
            severity="high",
            event_kind="security",
            policy_id="ring3.sensitive_egress",
            activity_id=event.get("activity_id"),
            source_ids=result.get("data_sources", []),
            sink_ids=[tool_name],
            fsm_before="ACTION_PROPOSED",
            fsm_after="BLOCKED",
        )
        result["risk"]["block_category"] = result["block_category"]
    return result
