"""Data-capture completeness and semantic flow restoration metrics."""

from __future__ import annotations

import copy
import re
from collections import defaultdict, deque
from collections.abc import Mapping, Sequence
from typing import Any

from ..modeling.data_sensitivity import (
    canonical_entity_name,
    tool_output_entity,
)
from ..modeling.policy import (
    base_tool_name,
    split_qualified_tool_name,
    tool_effect,
    tool_identity,
)
from .artifact_semantics import resolve_artifact_target_parameters
from .execution_contract import validate_plan_against_contract
from .plan_actions import plan_action_identity
from .plan_identity import plan_hash_valid
from .source_refs import (
    normalize_source_path,
    source_ref_identity,
    source_ref_instance_key,
    source_refs_match,
)


def _get(value: Any, key: str, default: Any = None) -> Any:
    if isinstance(value, Mapping):
        return value.get(key, default)
    return getattr(value, key, default)


def _tool_identity(tool_name: Any, suite_hint: Any = "") -> str:
    return tool_identity(str(tool_name or ""), suite_hint)


def _tool_call_records(messages: Sequence[Any]) -> list[dict[str, str]]:
    """Extract one identity record per tool call requested by the Agent."""
    observed: list[dict[str, str]] = []

    def append_call(call: Any) -> None:
        function = _get(call, "function", "")
        if isinstance(function, Mapping):
            function = function.get("name", "")
        name = str(function or _get(call, "name", "") or "")
        if not name:
            return
        call_id = _get(call, "id", None)
        if call_id is None:
            call_id = _get(call, "tool_call_id", None)
        suite = str(_get(call, "suite", "") or "")
        observed.append(
            {
                "name": base_tool_name(name),
                "tool_name": name,
                "identity": _tool_identity(name, suite),
                "suite": split_qualified_tool_name(name)[0] or suite,
                "call_id": str(call_id or ""),
            }
        )

    for message in messages:
        if str(_get(message, "role", "")) != "assistant":
            continue
        tool_calls = _get(message, "tool_calls")
        if (
            isinstance(tool_calls, Sequence)
            and not isinstance(
                tool_calls,
                str | bytes,
            )
            and len(tool_calls) > 0
        ):
            for call in tool_calls:
                append_call(call)
            continue
        tool_call = _get(message, "tool_call")
        if tool_call is not None:
            append_call(tool_call)
    return observed


def _tool_call_count(messages: Sequence[Any]) -> int:
    return len(_tool_call_records(messages))


def evaluate_capture_completeness(
    messages: Sequence[Any],
    events: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Match each requested tool call to one complete captured event bundle."""
    observed_calls = _tool_call_records(messages)
    starts: dict[str, Mapping[str, Any]] = {}
    ends: dict[str, Mapping[str, Any]] = {}
    for event in events:
        activity_id = str(event.get("activity_id", "") or "")
        if not activity_id:
            continue
        if event.get("type") == "api_call_start":
            starts[activity_id] = event
        elif event.get("type") == "api_call_end":
            ends[activity_id] = event

    complete_ids = set(starts) & set(ends)
    complete_by_identity: dict[str, deque[str]] = defaultdict(deque)
    complete_by_base: dict[str, deque[str]] = defaultdict(deque)
    no_id_by_identity: dict[str, deque[str]] = defaultdict(deque)
    no_id_by_base: dict[str, deque[str]] = defaultdict(deque)
    complete_by_call_id: dict[str, str] = {}
    complete_base_by_call_id: dict[str, str] = {}
    ordered_complete_ids = sorted(
        complete_ids,
        key=lambda item: (
            float(starts[item].get("timestamp", 0.0) or 0.0),
            item,
        ),
    )
    for activity_id in ordered_complete_ids:
        start = starts[activity_id]
        end = ends[activity_id]
        raw_tool_name = str(start.get("tool_intent", "") or "")
        suite = str(
            start.get("tool_suite")
            or start.get("target_app")
            or start.get("app_domain")
            or ""
        )
        identity = _tool_identity(raw_tool_name, suite)
        complete_by_identity[identity].append(activity_id)
        complete_by_base[base_tool_name(raw_tool_name)].append(activity_id)
        call_id = str(start.get("tool_call_id") or end.get("tool_call_id") or "")
        if call_id:
            complete_by_call_id[call_id] = activity_id
            complete_base_by_call_id[call_id] = base_tool_name(
                raw_tool_name
            )
        else:
            no_id_by_identity[identity].append(activity_id)
            no_id_by_base[base_tool_name(raw_tool_name)].append(
                activity_id
            )

    matched_ids: list[str] = []
    unmatched_calls: list[dict[str, str]] = []
    for call in observed_calls:
        activity_id = ""
        id_was_provided = bool(call["call_id"])
        if call["call_id"]:
            activity_id = complete_by_call_id.get(call["call_id"], "")
            if (
                activity_id
                and complete_base_by_call_id.get(call["call_id"])
                != call["name"]
            ):
                activity_id = ""
        if call["suite"]:
            queue = (
                no_id_by_identity.get(call["identity"])
                if id_was_provided
                else complete_by_identity.get(call["identity"])
            )
        else:
            queue = (
                no_id_by_base.get(call["name"])
                if id_was_provided
                else complete_by_base.get(call["name"])
            )
        if not activity_id and queue:
            activity_id = queue.popleft()
        if activity_id:
            for pending in (
                complete_by_identity.get(call["identity"]),
                complete_by_base.get(call["name"]),
                no_id_by_identity.get(call["identity"]),
                no_id_by_base.get(call["name"]),
            ):
                if pending is None:
                    continue
                try:
                    pending.remove(activity_id)
                except ValueError:
                    pass
        if not activity_id:
            unmatched_calls.append(call)
            continue
        matched_ids.append(activity_id)

    complete_fields = 0
    for activity_id in matched_ids:
        start = starts[activity_id]
        end = ends[activity_id]
        status = str(end.get("status", "") or "")
        has_identity = bool(
            str(start.get("tool_intent", "") or "")
            and str(end.get("tool_intent", "") or "")
            and str(start.get("tool_intent", "")) == str(end.get("tool_intent", ""))
        )
        has_activity_id = bool(
            str(start.get("activity_id", "") or "")
            and str(start.get("activity_id", "")) == str(end.get("activity_id", ""))
        )
        has_inputs = isinstance(start.get("inputs"), Mapping)
        has_status = status in {"success", "blocked", "error"}
        has_start_time = bool(start.get("timestamp"))
        has_end_time = bool(end.get("timestamp"))
        if status == "success":
            has_outcome = "outputs" in end and isinstance(
                end.get("output_flow_label"),
                Mapping,
            )
        elif status == "blocked":
            has_outcome = bool(
                end.get("block_reason")
                or end.get("risk_assessments")
            )
        else:
            has_outcome = bool(str(end.get("error") or "").strip())
        if (
            has_identity
            and has_activity_id
            and has_inputs
            and has_status
            and has_start_time
            and has_end_time
            and has_outcome
        ):
            complete_fields += 1

    complete_bundles = len(matched_ids)
    return {
        "observed_tool_calls": len(observed_calls),
        "captured_start_events": len(starts),
        "captured_end_events": len(ends),
        "complete_event_bundles": complete_bundles,
        "complete_field_bundles": complete_fields,
        "uncaptured_tool_calls": len(unmatched_calls),
        "unmatched_tool_calls": unmatched_calls,
        "orphan_start_events": len(set(starts) - complete_ids),
        "orphan_end_events": len(set(ends) - complete_ids),
        "unmatched_event_bundles": len(complete_ids - set(matched_ids)),
        "capture_completeness": (complete_bundles / len(observed_calls) if observed_calls else 1.0),
        "event_field_completeness": (
            complete_fields / complete_bundles if complete_bundles else (1.0 if not observed_calls else 0.0)
        ),
    }


def evaluate_plan_execution_conformance(
    graph: Mapping[str, Any] | None,
    *,
    final_plan: Mapping[str, Any] | None = None,
    execution_contract: Mapping[str, Any] | None = None,
    events: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """Compare actual data and control edges with each action's frozen plan."""
    graph = graph if isinstance(graph, Mapping) else {}
    plan_binding_issues: list[dict[str, Any]] = []
    nodes = [
        node
        for node in graph.get("nodes", []) or []
        if isinstance(node, Mapping)
        and str(node.get("type", "")) == "AgentTool"
    ]
    nodes_by_id = {
        str(node.get("id", "") or ""): node
        for node in graph.get("nodes", []) or []
        if isinstance(node, Mapping)
        and str(node.get("id", "") or "")
    }
    waived_verification_targets: set[tuple[str, str]] = set()
    for node in nodes:
        node_audit = node.get("requirement_audit")
        if not isinstance(node_audit, Mapping):
            continue
        target_action = _tool_identity(
            node.get("tool_alias")
            or node.get("tool_base_name")
            or node.get("label")
            or "",
            node.get("app")
            or node.get("target_app")
            or node.get("suite")
            or "",
        )
        if not target_action:
            continue
        target_base = base_tool_name(target_action)
        for requirement in node_audit.get(
            "requirements",
            [],
        ) or []:
            if (
                not isinstance(requirement, Mapping)
                or str(requirement.get("status", ""))
                != "waived"
            ):
                continue
            for applies_to in requirement.get(
                "applies_to",
                [],
            ) or []:
                applies_to = str(applies_to)
                if applies_to in {
                    target_action,
                    target_base,
                }:
                    waived_verification_targets.add(
                        (target_action, "__verification__")
                    )
                    continue
                prefix = next(
                    (
                        candidate
                        for candidate in (
                            target_action,
                            target_base,
                        )
                        if candidate
                        and applies_to.startswith(
                            f"{candidate}."
                        )
                    ),
                    "",
                )
                if not prefix:
                    continue
                parameter = applies_to[
                    len(prefix) + 1 :
                ]
                if parameter:
                    waived_verification_targets.add(
                        (
                            target_action,
                            f"__verification__:{parameter}",
                        )
                    )

    def action_identity(
        step: Mapping[str, Any],
        action: Mapping[str, Any],
    ) -> str:
        return plan_action_identity(step, action)

    def source_registry(
        plan: Mapping[str, Any],
        action: Mapping[str, Any],
    ) -> dict[str, Mapping[str, Any]]:
        result: dict[str, Mapping[str, Any]] = {}
        for value in (
            plan.get("source_refs"),
            (action.get("flow_contract") or {}).get("source_bindings")
            if isinstance(action.get("flow_contract"), Mapping)
            else None,
            (action.get("data_flow_bindings") or {}).get("source_bindings")
            if isinstance(action.get("data_flow_bindings"), Mapping)
            else None,
            (action.get("data_access") or {}).get("source_bindings")
            if isinstance(action.get("data_access"), Mapping)
            else None,
        ):
            if not isinstance(value, Mapping):
                continue
            for source_id, source in value.items():
                if isinstance(source, Mapping):
                    result[str(source_id)] = source
        for outcome in plan.get("required_outcomes", []) or []:
            if not isinstance(outcome, Mapping):
                continue
            for source in outcome.get(
                "required_source_refs",
                [],
            ) or []:
                if not isinstance(source, Mapping):
                    continue
                source_id = str(
                    source.get("source_id")
                    or source.get("id")
                    or ""
                )
                if source_id:
                    result.setdefault(source_id, source)
        return result

    def ref_from_id(
        source_id: str,
        registry: Mapping[str, Mapping[str, Any]],
    ) -> dict[str, Any]:
        source = registry.get(source_id)
        if isinstance(source, Mapping):
            return {
                **dict(source),
                "source_id": source_id,
            }
        return {"source_id": source_id}

    def refs_from_binding(
        binding: Mapping[str, Any],
        registry: Mapping[str, Mapping[str, Any]],
    ) -> tuple[
        list[dict[str, Any]],
        list[dict[str, Any]],
        list[dict[str, Any]],
    ]:
        allowed = [
            dict(item)
            for item in binding.get("allowed_source_refs", [])
            if isinstance(item, Mapping)
        ]
        required = [
            dict(item)
            for item in binding.get("required_source_refs", [])
            if isinstance(item, Mapping)
        ]
        raw_allowed_ids = binding.get("allowed_sources", [])
        allowed_ids = (
            raw_allowed_ids
            if isinstance(raw_allowed_ids, Sequence)
            and not isinstance(raw_allowed_ids, str | bytes)
            else []
        )
        raw_required_ids = binding.get("required_sources", [])
        required_ids = (
            raw_required_ids
            if isinstance(raw_required_ids, Sequence)
            and not isinstance(raw_required_ids, str | bytes)
            else []
        )
        for source_id in allowed_ids:
            if str(source_id).strip():
                allowed.append(ref_from_id(str(source_id), registry))
        for source_id in required_ids:
            if str(source_id).strip():
                reference = ref_from_id(str(source_id), registry)
                allowed.append(reference)
                required.append(dict(reference))
        direct_source_id = str(
            binding.get("source_id")
            or binding.get("id")
            or ""
        )
        direct_source_action = str(
            binding.get("source_action")
            or binding.get("source_tool")
            or ""
        )
        direct_source_path = str(
            binding.get("source_path")
            or ""
        )
        binding_mode = str(
            binding.get("mode", "") or ""
        ).lower()
        derived_source_binding = bool(
            binding_mode in {"derived", "derived_sources"}
            or base_tool_name(direct_source_action)
            == "derived_sources"
        )
        if (
            binding_mode != "literal"
            and not derived_source_binding
            and (
                direct_source_id
                or direct_source_action
                or direct_source_path
            )
        ):
            direct_reference: dict[str, Any] = {
                key: value
                for key, value in binding.items()
                if key
                in {
                    "source_id",
                    "id",
                    "app",
                    "entity",
                    "source_action",
                    "source_tool",
                    "source_path",
                    "producer_step",
                }
            }
            if direct_source_id and direct_source_id in registry:
                direct_reference = {
                    **dict(registry[direct_source_id]),
                    **direct_reference,
                }
            if direct_source_id:
                direct_reference["source_id"] = direct_source_id
            if direct_reference:
                allowed.append(direct_reference)
                required.append(dict(direct_reference))

        def enrich_reference(
            reference: dict[str, Any],
            candidates_pool: Sequence[Mapping[str, Any]] = (),
        ) -> dict[str, Any]:
            source_id = str(
                reference.get("source_id")
                or reference.get("id")
                or ""
            )
            candidates: list[Mapping[str, Any]] = []
            if source_id and source_id in registry:
                candidates = [registry[source_id]]
            if not candidates and reference:
                app = str(reference.get("app", "") or "").lower()
                entity = canonical_entity_name(
                    app,
                    str(reference.get("entity", "") or ""),
                )
                action = base_tool_name(
                    str(
                        reference.get("source_action")
                        or reference.get("source_tool")
                        or ""
                    )
                )
                candidates = [
                    candidate
                    for candidate in registry.values()
                    if str(candidate.get("app", "") or "").lower()
                    == app
                    and canonical_entity_name(
                        app,
                        str(candidate.get("entity", "") or ""),
                    )
                    == entity
                    and base_tool_name(
                        str(candidate.get("source_action", "") or "")
                    )
                    == action
                ]
            if len(candidates) != 1:
                if not candidates and candidates_pool:
                    candidates = [
                        candidate
                        for candidate in candidates_pool
                        if _plan_ref_identity_matches(
                            reference,
                            candidate,
                        )
                        and str(
                            candidate.get("source_path", "") or ""
                        ).strip()
                    ]
            if len(candidates) != 1:
                return reference
            candidate = candidates[0]
            path_candidates = [
                pooled
                for pooled in candidates_pool
                if _plan_ref_identity_matches(
                    reference,
                    pooled,
                )
                and str(
                    pooled.get("source_path", "") or ""
                ).strip()
            ]
            enriched_path = str(
                reference.get("source_path")
                or candidate.get("source_path")
                or (
                    path_candidates[0].get("source_path")
                    if len(path_candidates) == 1
                    else ""
                )
                or ""
            )
            return {
                **dict(candidate),
                **reference,
                "source_id": (
                    source_id
                    or str(candidate.get("source_id", "") or "")
                    or str(candidate.get("id", "") or "")
                ),
                **(
                    {"source_path": enriched_path}
                    if enriched_path
                    else {}
                ),
            }

        allowed = [enrich_reference(item) for item in allowed]
        required = [
            enrich_reference(item, allowed)
            for item in required
        ]
        allowed_keys = {_plan_ref_key(item) for item in allowed}
        if not allowed:
            allowed = [dict(item) for item in required]
            allowed_keys = {
                _plan_ref_key(item)
                for item in allowed
            }
        else:
            for item in required:
                if _plan_ref_key(item) not in allowed_keys:
                    allowed.append(item)
                    allowed_keys.add(_plan_ref_key(item))
        binding_allowed_identities = {
            _plan_ref_identity(item)
            for item in allowed
        }

        raw_groups_value = binding.get("required_source_groups", [])
        raw_groups_present = "required_source_groups" in binding
        raw_groups = raw_groups_value
        raw_groups = (
            raw_groups
            if isinstance(raw_groups, Sequence)
            and not isinstance(raw_groups, str | bytes)
            else []
        )
        if (
            raw_groups_present
            and (
                not isinstance(raw_groups_value, Sequence)
                or isinstance(raw_groups_value, str | bytes)
            )
        ):
            plan_binding_issues.append(
                {
                    "stage": "required_group",
                    "reason": "invalid_required_source_groups",
                }
            )
        groups: list[dict[str, Any]] = []
        seen_group_ids: set[str] = set()
        for group_index, raw_group in enumerate(raw_groups):
            if not isinstance(raw_group, Mapping):
                plan_binding_issues.append(
                    {
                        "stage": "required_group",
                        "reason": "invalid_required_source_group",
                        "group_index": group_index,
                    }
                )
                continue
            group_id = str(
                raw_group.get("id") or f"group_{group_index}"
            )
            mode = str(raw_group.get("mode", "all") or "all").lower()
            if mode not in {"any", "all"}:
                plan_binding_issues.append(
                    {
                        "stage": "required_group",
                        "reason": "invalid_required_source_group_mode",
                        "group_id": group_id,
                        "mode": mode,
                    }
                )
                continue
            if group_id in seen_group_ids:
                plan_binding_issues.append(
                    {
                        "stage": "required_group",
                        "reason": "duplicate_required_source_group_id",
                        "group_id": group_id,
                    }
                )
                continue
            seen_group_ids.add(group_id)
            raw_sources = raw_group.get(
                "sources",
                raw_group.get(
                    "source_refs",
                    raw_group.get("source_ids", []),
                ),
            )
            if not isinstance(raw_sources, Sequence) or isinstance(
                raw_sources,
                str | bytes,
            ):
                plan_binding_issues.append(
                    {
                        "stage": "required_group",
                        "reason": "invalid_required_source_group_sources",
                        "group_id": group_id,
                    }
                )
                continue
            sources: list[dict[str, Any]] = []
            for raw_source in raw_sources:
                if isinstance(raw_source, Mapping):
                    reference = enrich_reference(
                        dict(raw_source),
                        [*allowed, *required],
                    )
                else:
                    source_id = str(raw_source).strip()
                    if not source_id:
                        continue
                    reference = enrich_reference(
                        ref_from_id(source_id, registry),
                        [*allowed, *required],
                    )
                if not (
                    reference.get("source_id")
                    or _plan_ref_identity(reference)
                ):
                    continue
                if not str(
                    reference.get("source_path", "") or ""
                ).strip():
                    path_candidates = {
                        str(candidate.get("source_path", "") or "")
                        for candidate in [*allowed, *required]
                        if _plan_ref_identity_matches(
                            reference,
                            candidate,
                        )
                        and str(
                            candidate.get("source_path", "") or ""
                        ).strip()
                    }
                    if len(path_candidates) == 1:
                        reference["source_path"] = path_candidates.pop()
                sources.append(reference)
            if not sources:
                plan_binding_issues.append(
                    {
                        "stage": "required_group",
                        "reason": "required_source_group_without_sources",
                        "group_id": group_id,
                    }
                )
                continue
            groups.append(
                {
                    "group_id": group_id,
                    "mode": mode,
                    "sources": list(
                        {
                            _plan_ref_key(source): source
                            for source in sources
                        }.values()
                    ),
                }
            )
            group_keys = {
                _plan_ref_key(source)
                for source in sources
            }
            for source in sources:
                source_identity = _plan_ref_identity(source)
                source_path = normalize_source_path(
                    str(source.get("source_path", "") or "")
                )
                source_id = str(
                    source.get("source_id")
                    or source.get("id")
                    or ""
                )
                registry_ids_for_identity = {
                    str(source_id_candidate)
                    for source_id_candidate, candidate in registry.items()
                    if _plan_ref_identity(candidate)
                    == source_identity
                }
                binding_scope_matches = any(
                    _plan_ref_identity(candidate)
                    == source_identity
                    and (
                        not str(
                            candidate.get("source_id")
                            or candidate.get("id")
                            or ""
                        )
                        or (
                            source_id
                            and (
                                str(
                                    candidate.get("source_id")
                                    or candidate.get("id")
                                    or ""
                                )
                                == source_id
                                or (
                                    not str(
                                        candidate.get("source_id")
                                        or candidate.get("id")
                                        or ""
                                    )
                                    and registry_ids_for_identity
                                    == {source_id}
                                )
                            )
                        )
                        or not source_id
                    )
                    and (
                        not source_path
                        or not str(
                            candidate.get("source_path", "") or ""
                        ).strip()
                        or normalize_source_path(
                            str(candidate.get("source_path", ""))
                        )
                        == source_path
                    )
                    for candidate in allowed
                )
                if (
                    source_identity not in binding_allowed_identities
                    or not binding_scope_matches
                ):
                    plan_binding_issues.append(
                        {
                            "stage": "required_group",
                            "source_ref": copy.deepcopy(source),
                            "reason": "group_source_outside_binding",
                        }
                    )
                    continue
                if _plan_ref_key(source) not in allowed_keys:
                    allowed.append(source)
                    allowed_keys.add(_plan_ref_key(source))
            if group_keys:
                required = [
                    item
                    for item in required
                    if not any(
                        _plan_refs_equivalent(item, source)
                        for source in sources
                    )
                ]
        return allowed, required, groups

    def plan_bindings(
        plan: Mapping[str, Any],
        action: Mapping[str, Any],
        *,
        step_id: str = "",
    ) -> dict[str, dict[str, Any]]:
        registry = source_registry(plan, action)
        result: dict[str, dict[str, Any]] = {}

        def edge_kind_for_binding(
            binding: Mapping[str, Any],
            default: str = "data",
        ) -> str:
            role = str(
                binding.get("parameter_role", "") or ""
            ).lower()
            generation_kind = str(
                binding.get("generation_kind", "") or ""
            ).lower()
            if role == "control" or generation_kind in {
                "selection",
                "calculation",
                "summary",
            }:
                return "control"
            return default

        for contract_name in ("flow_contract", "data_flow_bindings"):
            flow_contract = action.get(contract_name)
            if not isinstance(flow_contract, Mapping):
                continue
            bindings = flow_contract.get("parameter_bindings")
            if isinstance(bindings, Mapping):
                for parameter, binding in bindings.items():
                    if not isinstance(binding, Mapping):
                        continue
                    allowed, required, groups = refs_from_binding(
                        binding,
                        registry,
                    )
                    result[str(parameter)] = {
                        "allowed": allowed,
                        "required": required,
                        "groups": groups,
                        "edge_kind": edge_kind_for_binding(binding),
                    }
            if contract_name != "flow_contract":
                continue
            control_ids = flow_contract.get("control_sources", [])
            control_ids = (
                control_ids
                if isinstance(control_ids, Sequence)
                and not isinstance(control_ids, str | bytes)
                else []
            )
            control_binding: dict[str, Any] = {
                "edge_kind": "control",
                "allowed_source_refs": [
                    ref_from_id(str(source_id), registry)
                    for source_id in control_ids
                    if str(source_id).strip()
                ],
                "required_source_refs": [
                    ref_from_id(str(source_id), registry)
                    for source_id in control_ids
                    if str(source_id).strip()
                ],
                "required_source_groups": flow_contract.get(
                    "required_source_groups",
                    [],
                ),
            }
            allowed, required, groups = refs_from_binding(
                control_binding,
                registry,
            )
            if allowed or required or groups:
                target = result.setdefault(
                    "__action_control__",
                    {
                        "allowed": [],
                        "required": [],
                        "groups": [],
                        "edge_kind": "control",
                    },
                )
                target["allowed"].extend(allowed)
                target["required"].extend(required)
                target["groups"].extend(groups)
        for contract_name in (
            "data_access",
            "resource_access",
        ):
            data_access = action.get(contract_name)
            if not isinstance(data_access, Mapping):
                continue
            resources = data_access.get(
                "resource_parameters"
            )
            if isinstance(resources, Mapping):
                for parameter, binding in resources.items():
                    if not isinstance(binding, Mapping):
                        continue
                    allowed, required, groups = refs_from_binding(
                        binding,
                        registry,
                    )
                    target = result.setdefault(
                        str(parameter),
                        {
                            "allowed": [],
                            "required": [],
                            "groups": [],
                            "edge_kind": "data",
                        },
                    )
                    target["allowed"].extend(allowed)
                    target["required"].extend(required)
                    target["groups"].extend(groups)

        action_name = str(action.get("name", "") or "")
        if (
            step_id
            and action_name
            and tool_effect(action_name).risk_level == "L2"
        ):
            for outcome in plan.get("required_outcomes", []) or []:
                if not isinstance(outcome, Mapping):
                    continue
                if step_id not in {
                    str(item)
                    for item in outcome.get("step_ids", [])
                }:
                    continue
                outcome_binding = {
                    "allowed_source_refs": outcome.get(
                        "required_source_refs",
                        [],
                    ),
                    "required_source_refs": outcome.get(
                        "required_source_refs",
                        [],
                    ),
                    "required_sources": outcome.get(
                        "required_sources",
                        [],
                    ),
                    "required_source_groups": outcome.get(
                        "required_source_groups",
                        [],
                    ),
                }
                allowed, required, groups = refs_from_binding(
                    outcome_binding,
                    registry,
                )
                if not (allowed or required or groups):
                    continue
                verification_targets: list[str] = []
                for target_name in outcome.get("applies_to", []) or []:
                    target_name = str(target_name)
                    concrete_parameter = (
                        target_name.rsplit(".", 1)[1]
                        if "." in target_name
                        else ""
                    )
                    target_key = (
                        f"__verification__:{concrete_parameter}"
                        if concrete_parameter
                        else "__verification__"
                    )
                    if target_key not in verification_targets:
                        verification_targets.append(target_key)
                if not verification_targets:
                    verification_targets = ["__verification__"]
                for target_key in verification_targets:
                    target_allowed = allowed
                    target_required = required
                    target_groups = groups
                    if target_key.startswith("__verification__:"):
                        concrete_parameter = target_key.split(":", 1)[1]
                        parameter_binding = result.get(
                            concrete_parameter
                        )
                        if isinstance(parameter_binding, Mapping):
                            target_allowed = list(
                                parameter_binding.get("allowed", [])
                            )
                            target_required = list(
                                parameter_binding.get("required", [])
                            )
                            target_groups = list(
                                parameter_binding.get("groups", [])
                            )
                    target = result.setdefault(
                        target_key,
                        {
                            "allowed": [],
                            "required": [],
                            "groups": [],
                            "edge_kind": "verification",
                        },
                    )
                    target["allowed"].extend(target_allowed)
                    target["required"].extend(target_required)
                    target["groups"].extend(
                        [
                            {
                                **group,
                                "group_id": (
                                    f"{outcome.get('id', 'outcome')}:"
                                    f"{group.get('group_id', '')}"
                                ),
                            }
                            for group in target_groups
                        ]
                    )
        for binding in result.values():
            binding["allowed"] = list(
                {
                    _plan_ref_key(item): item
                    for item in binding["allowed"]
                }.values()
            )
            binding["required"] = list(
                {
                    _plan_ref_key(item): item
                    for item in binding["required"]
                }.values()
            )
            binding["groups"] = list(
                {
                    (
                        str(group.get("group_id", "")),
                        str(group.get("mode", "")),
                        tuple(
                            _plan_ref_key(source)
                            for source in group.get("sources", [])
                        ),
                    ): group
                    for group in binding.get("groups", [])
                }.values()
            )
            required_sources = [
                *binding["required"],
                *[
                    source
                    for group in binding.get("groups", [])
                    for source in group.get("sources", [])
                ],
            ]
            instance_keys: dict[
                tuple[tuple[str, ...], str],
                set[str],
            ] = defaultdict(set)
            for reference in required_sources:
                source_id = str(
                    reference.get("source_id")
                    or reference.get("id")
                    or ""
                )
                if not source_id:
                    identity = _plan_ref_identity(reference)
                    candidates = {
                        str(candidate_id)
                        for candidate_id, candidate in registry.items()
                        if _plan_ref_identity(candidate) == identity
                    }
                    producer_step = str(
                        reference.get("producer_step", "") or ""
                    )
                    if producer_step:
                        candidates = {
                            candidate_id
                            for candidate_id in candidates
                            if str(
                                registry.get(candidate_id, {}).get(
                                    "producer_step",
                                    "",
                                )
                                or ""
                            )
                            == producer_step
                        }
                    if len(candidates) > 1:
                        plan_binding_issues.append(
                            {
                                "stage": "required",
                                "source_ref": copy.deepcopy(reference),
                                "reason": "ambiguous_source_identity",
                                "candidate_source_ids": sorted(
                                    candidates
                                ),
                            }
                        )
                    continue
                instance_keys[
                    (
                        _plan_ref_identity(reference),
                        str(
                            reference.get("producer_step", "") or ""
                        ),
                    )
                ].add(source_id)
            for (
                identity,
                producer_step,
            ), source_ids in instance_keys.items():
                if len(source_ids) > 1 and not producer_step:
                    plan_binding_issues.append(
                        {
                            "stage": "required",
                            "reason": "ambiguous_source_instances",
                            "identity": list(identity),
                            "source_ids": sorted(source_ids),
                        }
                    )
            if binding.get("edge_kind") not in {
                "control",
                "verification",
            }:
                required_path_refs = [
                    *binding["required"],
                    *[
                        source
                        for group in binding.get("groups", [])
                        for source in group.get("sources", [])
                    ],
                ]
                for reference in required_path_refs:
                    if str(
                        reference.get("source_path", "") or ""
                    ).strip():
                        continue
                    if any(
                        source_refs_match(candidate, reference)
                        and str(
                            candidate.get("source_path", "") or ""
                        ).strip()
                        for candidate in binding.get("allowed", [])
                    ):
                        continue
                    plan_binding_issues.append(
                        {
                            "stage": "required",
                            "source_ref": copy.deepcopy(reference),
                            "reason": "source_path_missing",
                        }
                    )
        return result

    def find_action(
        plan: Mapping[str, Any],
        node: Mapping[str, Any],
    ) -> tuple[Mapping[str, Any], Mapping[str, Any]] | None:
        target_identity = _tool_identity(
            node.get("tool_alias")
            or node.get("tool_base_name")
            or node.get("label")
            or "",
            node.get("app")
            or node.get("target_app")
            or node.get("suite")
            or "",
        )
        step_id = str(
            node.get("plan_step_id")
            or node.get("subgoal_id")
            or ""
        )
        candidates: list[
            tuple[Mapping[str, Any], Mapping[str, Any]]
        ] = []
        for step in plan.get("steps", []) or []:
            if not isinstance(step, Mapping):
                continue
            if step_id and str(step.get("id", "")) != step_id:
                continue
            for action in step.get("actions", []) or []:
                if not isinstance(action, Mapping):
                    continue
                if action_identity(step, action) == target_identity:
                    candidates.append((step, action))
        return candidates[0] if len(candidates) == 1 else None

    def actual_edges(
        node: Mapping[str, Any],
        target_step_id: str,
    ) -> list[dict[str, Any]]:
        target_app = str(
            node.get("app")
            or node.get("target_app")
            or node.get("suite")
            or ""
        ).lower()
        target_tool = _tool_identity(
            node.get("tool_alias")
            or node.get("tool_base_name")
            or node.get("label")
            or "",
            target_app,
        )
        matched_action = (
            find_action(reference_plan, node)
            if isinstance(reference_plan, Mapping)
            else None
        )
        action_contract = (
            matched_action[1]
            if matched_action is not None
            else {}
        )

        def plan_parameter_is_literal(parameter: str) -> bool:
            for contract_name in (
                "data_access",
                "resource_access",
                "flow_contract",
                "data_flow_bindings",
            ):
                contract = action_contract.get(contract_name)
                if not isinstance(contract, Mapping):
                    continue
                mappings = (
                    contract.get("resource_parameters", {}),
                    contract.get("parameter_bindings", {}),
                )
                for mappings_by_parameter in mappings:
                    if not isinstance(
                        mappings_by_parameter,
                        Mapping,
                    ):
                        continue
                    binding = mappings_by_parameter.get(
                        parameter
                    )
                    if (
                        isinstance(binding, Mapping)
                        and str(
                            binding.get("mode", "")
                        ).lower()
                        == "literal"
                    ):
                        return True
                if contract_name != "flow_contract":
                    continue
                destination = contract.get("destination")
                if not isinstance(destination, Mapping):
                    continue
                destination_parameters = {
                    str(item)
                    for item in destination.get(
                        "parameters",
                        [],
                    )
                    if str(item).strip()
                }
                if (
                    parameter in destination_parameters
                    and str(
                        destination.get("mode", "")
                    ).lower()
                    == "literal"
                ):
                    return True
            return False

        result: list[dict[str, Any]] = []
        node_id = str(node.get("id", "") or "")
        event_by_activity = {
            str(event.get("activity_id", "") or ""): event
            for event in events
            if isinstance(event, Mapping)
            and str(event.get("activity_id", "") or "")
        }
        target_event = event_by_activity.get(node_id, {})
        parameter_resolutions = node.get("parameter_resolutions")
        if not isinstance(parameter_resolutions, Sequence) or isinstance(
            parameter_resolutions,
            str | bytes,
        ):
            parameter_resolutions = target_event.get(
                "parameter_resolutions",
                [],
            )
        resolutions_by_parameter = {
            str(item.get("parameter", "") or ""): item
            for item in parameter_resolutions
            if isinstance(item, Mapping) and item.get("parameter")
        }
        control_source_keys: set[tuple[str, str, str, str, str]] = set()
        for parameter, resolution in resolutions_by_parameter.items():
            for source in resolution.get("control_sources", []) or []:
                if not isinstance(source, Mapping):
                    continue
                control_source_keys.add(
                    (
                        parameter,
                        str(source.get("source_app", "") or "").lower(),
                        str(source.get("source_entity", "") or ""),
                        base_tool_name(
                            str(
                                source.get("source_tool")
                                or source.get("source_action")
                                or ""
                            )
                        ),
                        str(
                            source.get("source_activity_id", "")
                            or ""
                        ),
                    )
                )
        argument_sources = node.get("argument_sources", [])
        if not isinstance(argument_sources, Sequence) or isinstance(
            argument_sources,
            str | bytes,
        ):
            argument_sources = []
        for source in argument_sources:
            if not isinstance(source, Mapping):
                continue
            source_kind = str(source.get("source_kind", "") or "")
            source_tool = str(
                source.get("source_tool")
                or source.get("source_action")
                or ""
            )
            source_activity = str(
                source.get("source_activity_id") or ""
            )
            if source_kind != "tool_output" and not (
                source_tool or source_activity
            ):
                continue
            parameter = str(source.get("argument_root", "") or "")
            if not parameter:
                continue
            resolution = resolutions_by_parameter.get(
                parameter,
                {},
            )
            if (
                bool(resolution.get("literal", False))
                or str(
                    resolution.get("source_kind", "")
                )
                == "user_prompt"
                or plan_parameter_is_literal(parameter)
            ):
                continue
            source_app = str(source.get("source_app", "") or "").lower()
            source_entity = canonical_entity_name(
                source_app,
                str(source.get("source_entity", "") or ""),
            )
            source_path = normalize_source_path(
                str(source.get("source_path", "") or "")
            )
            source_node = nodes_by_id.get(source_activity, {})
            source_event = event_by_activity.get(source_activity, {})
            source_step_id = str(
                source.get("source_step_id")
                or source.get("producer_step")
                or source_node.get("plan_step_id")
                or source_node.get("subgoal_id")
                or source_event.get("plan_step_id")
                or ""
            )
            source_call_id = str(
                source.get("source_tool_call_id")
                or source.get("tool_call_id")
                or source_node.get("tool_call_id")
                or source_event.get("tool_call_id")
                or ""
            )
            source_id = str(
                source.get("source_id")
                or source.get("id")
                or ""
            )
            source_ids = {
                source_id
            } if source_id else set()
            source_ids.update(
                str(item)
                for item in resolution.get("used_source_ids", [])
                if str(item).strip()
            )
            control_key = (
                parameter,
                source_app,
                source_entity,
                base_tool_name(source_tool),
                source_activity,
            )
            provenance_role = str(
                source.get("provenance_role", "") or ""
            ).lower()
            if provenance_role in {"data", "control"}:
                influence_kind = provenance_role
            else:
                influence_kind = (
                    "control"
                    if (
                        (
                            not source_path
                            or (
                                source_path == "$"
                                and bool(
                                    source.get(
                                        "control_influence",
                                        False,
                                    )
                                )
                                and not source.get(
                                    "source_entity_id"
                                )
                            )
                        )
                        and (
                            bool(
                                source.get(
                                    "control_influence",
                                    False,
                                )
                            )
                            or control_key
                            in control_source_keys
                        )
                    )
                    else "data"
                )
            result.append(
                {
                    "source_app": source_app,
                    "source_entity": source_entity,
                    "source_action": source_tool,
                    "source_path": source_path,
                    "source_activity_id": source_activity,
                    "source_step_id": source_step_id,
                    "source_tool_call_id": source_call_id,
                    "source_ids": sorted(source_ids),
                    "influence_kind": influence_kind,
                    "target_app": target_app,
                    "target_step_id": target_step_id,
                    "target_action": target_tool,
                    "target_parameter": parameter,
                }
            )
        for parameter, resolution in resolutions_by_parameter.items():
            if (
                bool(resolution.get("literal", False))
                or str(
                    resolution.get("source_kind", "")
                )
                == "user_prompt"
                or plan_parameter_is_literal(parameter)
            ):
                continue
            for source in resolution.get("control_sources", []) or []:
                if not isinstance(source, Mapping):
                    continue
                source_activity = str(
                    source.get("source_activity_id", "") or ""
                )
                source_node = nodes_by_id.get(
                    source_activity,
                    {},
                )
                source_event = event_by_activity.get(
                    source_activity,
                    {},
                )
                source_tool = str(
                    source.get("source_tool")
                    or source.get("source_action")
                    or ""
                )
                source_app = str(
                    source.get("source_app")
                    or source.get("app")
                    or source_node.get("app")
                    or source_node.get("target_app")
                    or source_event.get("app_domain")
                    or source_event.get("target_app")
                    or ""
                ).lower()
                source_entity = canonical_entity_name(
                    source_app,
                    str(
                        source.get("source_entity")
                        or source.get("entity")
                        or tool_output_entity(source_tool)
                        or ""
                    ),
                )
                source_path = normalize_source_path(
                    str(source.get("source_path", "") or "")
                )
                result.append(
                    {
                        "source_app": source_app,
                        "source_entity": source_entity,
                        "source_action": source_tool,
                        "source_path": source_path,
                        "source_activity_id": source_activity,
                        "source_step_id": str(
                            source.get("source_step_id")
                            or source.get("producer_step")
                            or source_node.get("plan_step_id")
                            or source_node.get("subgoal_id")
                            or source_event.get("plan_step_id")
                            or ""
                        ),
                        "source_tool_call_id": str(
                            source.get("source_tool_call_id")
                            or source_node.get("tool_call_id")
                            or source_event.get("tool_call_id")
                            or ""
                        ),
                        "source_ids": sorted(
                            {
                                str(item)
                                for item in resolution.get(
                                    "used_source_ids",
                                    [],
                                )
                                if str(item).strip()
                            }
                        ),
                        "influence_kind": "control",
                        "target_app": target_app,
                        "target_step_id": target_step_id,
                        "target_action": target_tool,
                        "target_parameter": parameter,
                    }
                )

        verified_control_requirements: dict[
            str,
            list[str],
        ] = defaultdict(list)
        requirement_audit = node.get("requirement_audit")
        if not isinstance(requirement_audit, Mapping):
            requirement_audit = target_event.get(
                "requirement_audit",
            )
        if isinstance(requirement_audit, Mapping):
            for requirement in requirement_audit.get(
                "requirements",
                [],
            ) or []:
                if not isinstance(requirement, Mapping):
                    continue
                if str(requirement.get("status", "")) != "verified":
                    continue
                requirement_id = str(
                    requirement.get("id", "") or ""
                )
                for source_activity_id in requirement.get(
                    "source_activity_ids",
                    [],
                ) or []:
                    source_activity_id = str(
                        source_activity_id
                    )
                    if (
                        source_activity_id
                        and requirement_id
                        and requirement_id
                        not in verified_control_requirements[
                            source_activity_id
                        ]
                    ):
                        verified_control_requirements[
                            source_activity_id
                        ].append(requirement_id)
                applies_to = [
                    str(item)
                    for item in requirement.get("applies_to", [])
                    if str(item).strip()
                ]
                target_base_tool = base_tool_name(
                    target_tool
                )
                parameters = [
                    item.rsplit(".", 1)[1]
                    if (
                        item.startswith(f"{target_tool}.")
                        or (
                            target_base_tool
                            and item.startswith(
                                f"{target_base_tool}."
                            )
                        )
                    )
                    else item
                    for item in applies_to
                    if (
                        item.startswith(f"{target_tool}.")
                        or (
                            target_base_tool
                            and item.startswith(
                                f"{target_base_tool}."
                            )
                        )
                        or "." not in item
                    )
                ]
                concrete_parameters = {
                    item
                    for item in parameters
                    if item and item != target_tool
                }
                for source_activity in requirement.get(
                    "source_activity_ids",
                    [],
                ) or []:
                    source_activity = str(source_activity)
                    if not source_activity:
                        continue
                    existing_evidence_edges = [
                        edge
                        for edge in result
                        if edge.get("source_activity_id")
                        == source_activity
                        and edge.get("influence_kind")
                        in {"data", "control", "verification"}
                        and (
                            not concrete_parameters
                            or edge.get("target_parameter")
                            in concrete_parameters
                        )
                    ]
                    if existing_evidence_edges:
                        for edge in existing_evidence_edges:
                            edge["verification_evidence"] = True
                            edge["requirement_ids"] = list(
                                dict.fromkeys(
                                    [
                                        *edge.get(
                                            "requirement_ids",
                                            [],
                                        ),
                                        str(
                                            requirement.get(
                                                "id",
                                                "",
                                            )
                                        ),
                                    ]
                                )
                            )
                        continue
                    source_node = nodes_by_id.get(
                        source_activity,
                        {},
                    )
                    source_event = event_by_activity.get(
                        source_activity,
                        {},
                    )
                    source_tool = str(
                        source_node.get("tool_alias")
                        or source_node.get("tool_base_name")
                        or source_node.get("label")
                        or source_event.get("tool_intent")
                        or ""
                    )
                    source_app = str(
                        source_node.get("app")
                        or source_node.get("target_app")
                        or source_event.get("app_domain")
                        or source_event.get("target_app")
                        or ""
                    ).lower()
                    verification_targets = (
                        sorted(concrete_parameters)
                        if concrete_parameters
                        else ["__verification__"]
                    )
                    for target_parameter in verification_targets:
                        result.append(
                            {
                            "source_app": source_app,
                            "source_entity": canonical_entity_name(
                                source_app,
                                tool_output_entity(source_tool),
                            ),
                            "source_action": source_tool,
                            "source_path": "",
                            "source_activity_id": source_activity,
                            "source_step_id": str(
                                source_node.get("plan_step_id")
                                or source_node.get("subgoal_id")
                                or source_event.get("plan_step_id")
                                or ""
                            ),
                            "source_tool_call_id": str(
                                source_node.get("tool_call_id")
                                or source_event.get("tool_call_id")
                                or ""
                            ),
                            "source_ids": sorted(
                                {
                                    str(item)
                                    for item in requirement.get(
                                        "source_ids",
                                        [],
                                    )
                                    if str(item).strip()
                                }
                            ),
                            "influence_kind": "verification",
                            "target_app": target_app,
                            "target_step_id": target_step_id,
                            "target_action": target_tool,
                            "target_parameter": target_parameter,
                            "requirement_ids": [
                                str(requirement.get("id", ""))
                            ],
                            }
                        )
        for edge in result:
            if str(
                edge.get("influence_kind", "")
            ) != "control":
                continue
            requirement_ids = (
                verified_control_requirements.get(
                    str(
                        edge.get(
                            "source_activity_id",
                            "",
                        )
                        or ""
                    ),
                    [],
                )
            )
            if not requirement_ids:
                continue
            edge["verification_evidence"] = True
            edge["requirement_ids"] = list(
                dict.fromkeys(
                    [
                        *edge.get("requirement_ids", []),
                        *requirement_ids,
                    ]
                )
            )
        deduplicated = list(
            {
                _actual_edge_key(item): item
                for item in result
            }.values()
        )
        concrete_data_sources = {
            (
                str(edge.get("target_parameter", "")),
                str(edge.get("source_app", "")),
                str(edge.get("source_entity", "")),
                str(edge.get("source_action", "")),
                str(edge.get("source_step_id", "")),
            )
            for edge in deduplicated
            if (
                str(edge.get("influence_kind", "data"))
                == "data"
                and str(edge.get("source_path", "") or "")
                not in {"", "$"}
            )
        }
        return [
            edge
            for edge in deduplicated
            if not (
                str(edge.get("influence_kind", "data"))
                == "data"
                and str(edge.get("source_path", "") or "")
                == "$"
                and (
                    str(edge.get("target_parameter", "")),
                    str(edge.get("source_app", "")),
                    str(edge.get("source_entity", "")),
                    str(edge.get("source_action", "")),
                    str(edge.get("source_step_id", "")),
                )
                in concrete_data_sources
            )
        ]

    plan_revisions: dict[int, dict[str, Any]] = {}
    plan_hashes: set[str] = set()
    actions_without_plan = 0
    successful_step_ids: set[str] = set()
    successful_activity_ids: set[str] = set()
    successful_step_actions: set[tuple[str, str]] = set()
    for node in nodes:
        activity_id = str(node.get("id", "") or "")
        node_step_id = str(
            node.get("plan_step_id")
            or node.get("subgoal_id")
            or ""
        )
        node_status = str(
            node.get("status", "") or ""
        ).lower()
        node_app = str(
            node.get("app")
            or node.get("target_app")
            or node.get("suite")
            or ""
        ).lower()
        node_action = _tool_identity(
            node.get("tool_alias")
            or node.get("tool_base_name")
            or node.get("label")
            or "",
            node_app,
        )
        if (
            node_step_id
            and node_status == "success"
            and not bool(node.get("blocked", False))
        ):
            successful_step_ids.add(node_step_id)
            if activity_id:
                successful_activity_ids.add(activity_id)
            if node_action:
                successful_step_actions.add(
                    (node_step_id, node_action)
                )
        node_plan = node.get("task_data_plan")
        if not isinstance(node_plan, Mapping):
            actions_without_plan += 1
            continue
        revision = int(node_plan.get("plan_revision", 1) or 1)
        plan_revisions[revision] = copy.deepcopy(dict(node_plan))
        plan_hash = str(node_plan.get("plan_hash", "") or "")
        if plan_hash:
            plan_hashes.add(plan_hash)

    reference_plan = (
        dict(final_plan)
        if isinstance(final_plan, Mapping)
        else plan_revisions[max(plan_revisions)]
        if plan_revisions
        else None
    )
    reference_revision = (
        int(reference_plan.get("plan_revision", 1) or 1)
        if isinstance(reference_plan, Mapping)
        else 0
    )
    if isinstance(reference_plan, Mapping):
        plan_revisions[reference_revision] = copy.deepcopy(
            reference_plan
        )
        reference_hash = str(reference_plan.get("plan_hash", "") or "")
        if reference_hash:
            plan_hashes.add(reference_hash)

    required_edges: list[dict[str, Any]] = []
    allowed_by_parameter: dict[
        tuple[int, str, str, str],
        list[dict[str, Any]],
    ] = defaultdict(list)
    actual_edge_list: list[dict[str, Any]] = []
    unplanned_actions: list[dict[str, Any]] = []
    for node in nodes:
        if not isinstance(reference_plan, Mapping):
            continue
        matched_action = find_action(reference_plan, node)
        target_parameter = _tool_identity(
            node.get("tool_alias")
            or node.get("tool_base_name")
            or node.get("label")
            or "",
            node.get("app")
            or node.get("target_app")
            or node.get("suite")
            or "",
        )
        if matched_action is None:
            unplanned_actions.append(
                {
                    "activity_id": str(node.get("id", "")),
                    "action": target_parameter,
                    "plan_revision": reference_revision,
                }
            )
            continue
        action_step, action = matched_action
        target_step_id = str(
            action_step.get("id")
            or node.get("plan_step_id")
            or node.get("subgoal_id")
            or ""
        )
        bindings = plan_bindings(
            reference_plan,
            action,
            step_id=target_step_id,
        )
        for parameter, binding in bindings.items():
            for reference in binding["allowed"]:
                allowed_by_parameter[
                    (
                        reference_revision,
                        target_step_id,
                        target_parameter,
                        parameter,
                    )
                ].append(reference)
            for reference in binding["required"]:
                required_edges.append(
                    {
                        "target_step_id": target_step_id,
                        "target_action": target_parameter,
                        "target_parameter": parameter,
                        "source_ref": reference,
                        "plan_revision": reference_revision,
                        "edge_kind": binding.get(
                            "edge_kind",
                            "data",
                        ),
                        "required_group": "",
                        "group_mode": "",
                    }
                )
            for group in binding.get("groups", []):
                for reference in group.get("sources", []):
                    required_edges.append(
                        {
                            "target_step_id": target_step_id,
                            "target_action": target_parameter,
                            "target_parameter": parameter,
                            "source_ref": reference,
                            "plan_revision": reference_revision,
                            "edge_kind": binding.get(
                                "edge_kind",
                                "data",
                            ),
                            "required_group": str(
                                group.get("group_id", "") or ""
                            ),
                            "group_mode": str(
                                group.get("mode", "all") or "all"
                            ),
                        }
                    )
        node_status = str(
            node.get("status", "") or ""
        ).lower()
        if (
            not node_status
            or node_status == "success"
        ) and not bool(node.get("blocked", False)):
            for edge in actual_edges(node, target_step_id):
                edge["plan_revision"] = reference_revision
                actual_edge_list.append(edge)

    actual_edge_list = list(
        {
            _actual_edge_key(item): item
            for item in actual_edge_list
        }.values()
    )
    concrete_data_sources: set[tuple[str, ...]] = {
        (
            str(edge.get("plan_revision", "")),
            str(edge.get("target_step_id", "")),
            str(edge.get("target_action", "")),
            str(edge.get("target_parameter", "")),
            str(edge.get("source_app", "")).lower(),
            str(edge.get("source_entity", "")),
            tool_identity(
                str(edge.get("source_action", "") or ""),
                str(edge.get("source_app", "") or ""),
            ),
            str(edge.get("source_step_id", "") or ""),
        )
        for edge in actual_edge_list
        if (
            str(edge.get("influence_kind", "data"))
            in {"data", "verification"}
            and (
                str(edge.get("source_path", "") or "")
                or str(edge.get("influence_kind", ""))
                == "verification"
            )
        )
    }
    dependency_only_targets: dict[
        tuple[str, str],
        set[str],
    ] = defaultdict(set)
    if isinstance(execution_contract, Mapping):
        for expected in execution_contract.get(
            "expected_flow_edges",
            [],
        ) or []:
            if (
                not isinstance(expected, Mapping)
                or not bool(
                    expected.get("dependency_only", False)
                )
            ):
                continue
            source_step = str(
                expected.get("from", "") or ""
            )
            target_step = str(
                expected.get("to", "") or ""
            )
            target_action = str(
                expected.get("target_action", "") or ""
            )
            if not target_step or not target_action:
                continue
            dependency_only_targets[
                (target_step, target_action)
            ].add(source_step)
            required_edges.append(
                {
                    "target_step_id": target_step,
                    "target_action": target_action,
                    "target_parameter": "__dependency__",
                    "source_ref": {
                        "producer_step": source_step,
                        "source_action": str(
                            expected.get(
                                "source_action",
                                "",
                            )
                            or ""
                        ),
                    },
                    "plan_revision": reference_revision,
                    "edge_kind": "dependency",
                    "required_group": str(
                        expected.get(
                            "alternative_group",
                            "",
                        )
                        or ""
                    ),
                    "group_mode": "any",
                }
            )
    required_edges = list(
        {
            (
                item["target_action"],
                item["target_step_id"],
                item["target_parameter"],
                item["plan_revision"],
                item.get("edge_kind", "data"),
                item.get("required_group", ""),
                _plan_ref_key(item["source_ref"]),
            ): item
            for item in required_edges
        }.values()
    )
    required_edges = [
        requirement
        for requirement in required_edges
        if not (
            requirement.get("edge_kind") == "verification"
            and (
                str(
                    requirement.get(
                        "target_action",
                        "",
                    )
                ),
                str(
                    requirement.get(
                        "target_parameter",
                        "",
                    )
                ),
            )
            in waived_verification_targets
        )
    ]
    matched_required: list[dict[str, Any]] = []
    missing_required: list[dict[str, Any]] = []
    ambiguous_source_candidates: list[dict[str, Any]] = []

    def edge_satisfies_requirement(
        requirement: Mapping[str, Any],
        edge: Mapping[str, Any],
    ) -> bool:
        if (
            edge["plan_revision"] != requirement["plan_revision"]
            or edge["target_step_id"]
            != requirement["target_step_id"]
            or edge["target_action"]
            != requirement["target_action"]
        ):
            return False
        requirement_kind = str(
            requirement.get("edge_kind", "data")
        )
        actual_kind = str(edge.get("influence_kind", "data"))
        if requirement_kind == "data" and not (
            actual_kind == "data"
            or (
                actual_kind == "control"
                and bool(
                    edge.get(
                        "verification_evidence",
                        False,
                    )
                )
            )
        ):
            return False
        if requirement_kind == "verification" and not (
            actual_kind == "verification"
            or (
                actual_kind == "control"
                and bool(edge.get("verification_evidence", False))
            )
            or (
                actual_kind == "data"
                and str(
                    edge.get("source_activity_id", "") or ""
                )
                in successful_activity_ids
            )
        ):
            return False
        if (
            requirement_kind == "verification"
            and requirement["target_parameter"].startswith(
                "__verification__:"
            )
            and edge["target_parameter"]
            != requirement["target_parameter"].split(":", 1)[1]
        ):
            return False
        # A concrete argument value can carry both data and control influence.
        # Control obligations therefore accept the strongest available
        # evidence instead of requiring a separate synthetic edge kind.
        if (
            requirement_kind == "data"
            and edge["target_parameter"]
            != requirement["target_parameter"]
        ):
            return False
        if (
            requirement_kind == "control"
            and requirement["target_parameter"]
            != "__action_control__"
            and edge["target_parameter"]
            != requirement["target_parameter"]
        ):
            return False
        comparison_edge: Mapping[str, Any] = edge
        comparison_reference: Mapping[str, Any] = (
            requirement["source_ref"]
        )
        reference_path = str(
            requirement["source_ref"].get("source_path", "")
            or ""
        )
        if (
            requirement_kind == "verification"
            and reference_path
            and not str(edge.get("source_path", "") or "")
        ):
            comparison_edge = {
                **edge,
                "source_path": reference_path,
            }
        if (
            requirement_kind == "verification"
            and (
                actual_kind == "verification"
                or bool(
                    edge.get(
                        "verification_evidence",
                        False,
                    )
                )
            )
        ):
            comparison_reference = {
                key: value
                for key, value in requirement[
                    "source_ref"
                ].items()
                if key != "source_path"
            }
        return _plan_ref_matches_actual(
            comparison_reference,
            comparison_edge,
        )

    for requirement in required_edges:
        if requirement.get("edge_kind") == "dependency":
            source_step = str(
                requirement["source_ref"].get(
                    "producer_step",
                    "",
                )
                or ""
            )
            if (
                source_step in successful_step_ids
                and requirement["target_step_id"]
                in successful_step_ids
            ):
                matched_required.append(
                    {
                        **requirement,
                        "matched_activity_id": "",
                        "matched_influence_kind": (
                            "dependency"
                        ),
                    }
                )
            else:
                missing_required.append(requirement)
            continue
        source_ref = requirement["source_ref"]
        source_app = str(
            source_ref.get("app", "") or ""
        ).lower()
        source_action = tool_identity(
            str(
                source_ref.get("source_action")
                or source_ref.get("source_tool")
                or ""
            ),
            source_app,
        )
        if (
            requirement.get("edge_kind") == "verification"
            and str(
                source_ref.get("producer_step", "") or ""
            )
            == str(requirement["target_step_id"])
            and source_action
            == str(requirement["target_action"])
            and (
                str(requirement["target_step_id"]),
                str(requirement["target_action"]),
            )
            in successful_step_actions
        ):
            matched_required.append(
                {
                    **requirement,
                    "matched_activity_id": "",
                    "matched_influence_kind": (
                        "postcondition"
                    ),
                }
            )
            continue
        candidates = [
            edge
            for edge in actual_edge_list
            if edge_satisfies_requirement(requirement, edge)
        ]
        has_instance_constraint = bool(
            source_ref.get("source_activity_id")
            or source_ref.get("tool_call_id")
            or source_ref.get("source_tool_call_id")
        )
        candidate_instances = {
            (
                str(edge.get("source_activity_id", "") or ""),
                str(edge.get("source_tool_call_id", "") or ""),
            )
            for edge in candidates
        }
        candidate_source_steps = {
            str(edge.get("source_step_id", "") or "")
            for edge in candidates
            if str(edge.get("source_step_id", "") or "")
        }
        if (
            len(candidate_instances) > 1
            and not has_instance_constraint
            and len(candidate_source_steps) > 1
        ):
            ambiguous_source_candidates.append(
                {
                    **requirement,
                    "candidate_instances": [
                        {
                            "activity_id": activity_id,
                            "tool_call_id": call_id,
                        }
                        for activity_id, call_id in sorted(
                            candidate_instances
                        )
                    ],
                }
            )
            missing_required.append(requirement)
            continue
        matched = candidates[0] if candidates else None
        if matched is None:
            missing_required.append(requirement)
        else:
            matched_required.append(
                {
                    **requirement,
                    "matched_activity_id": matched[
                        "source_activity_id"
                    ],
                    "matched_influence_kind": matched.get(
                        "influence_kind",
                    ),
                }
            )

    group_records: list[dict[str, Any]] = []
    for group_key in {
        (
            requirement["plan_revision"],
            requirement["target_step_id"],
            requirement["target_action"],
            requirement["target_parameter"],
            requirement["required_group"],
            requirement["group_mode"],
        )
        for requirement in required_edges
        if requirement.get("required_group")
    }:
        (
            plan_revision,
            target_step_id,
            target_action,
            target_parameter,
            group_id,
            mode,
        ) = group_key
        requirements = [
            requirement
            for requirement in required_edges
            if (
                requirement["plan_revision"],
                requirement["target_step_id"],
                requirement["target_action"],
                requirement["target_parameter"],
                requirement["required_group"],
                requirement["group_mode"],
            )
            == group_key
        ]
        matched_keys = {
            (requirement["edge_kind"], _plan_ref_key(requirement["source_ref"]))
            for requirement in matched_required
            if (
                requirement["plan_revision"],
                requirement["target_step_id"],
                requirement["target_action"],
                requirement["target_parameter"],
                requirement["required_group"],
                requirement["group_mode"],
            )
            == group_key
        }
        matched_count = len(matched_keys)
        satisfied = (
            matched_count >= len(requirements)
            if mode == "all"
            else matched_count >= 1
        )
        group_records.append(
            {
                "group_id": group_id,
                "mode": mode,
                "plan_revision": plan_revision,
                "target_step_id": target_step_id,
                "target_action": target_action,
                "target_parameter": target_parameter,
                "required_count": len(requirements),
                "matched_count": matched_count,
                "satisfied": satisfied,
            }
        )
    satisfied_any_groups = {
        (
            group["plan_revision"],
            group["target_step_id"],
            group["target_action"],
            group["target_parameter"],
            group["group_id"],
        )
        for group in group_records
        if group["mode"] == "any" and group["satisfied"]
    }
    effective_missing_required = [
        requirement
        for requirement in missing_required
        if (
            not requirement.get("required_group")
            or requirement.get("group_mode") != "any"
            or (
                requirement["plan_revision"],
                requirement["target_step_id"],
                requirement["target_action"],
                requirement["target_parameter"],
                requirement["required_group"],
            )
            not in satisfied_any_groups
        )
    ]
    ambiguous_source_instances = [
        requirement
        for requirement in ambiguous_source_candidates
        if (
            not requirement.get("required_group")
            or requirement.get("group_mode") != "any"
            or (
                requirement["plan_revision"],
                requirement["target_step_id"],
                requirement["target_action"],
                requirement["target_parameter"],
                requirement["required_group"],
            )
            not in satisfied_any_groups
        )
    ]

    unexpected_edges: list[dict[str, Any]] = []
    allowed_parameter_pairs: set[tuple[int, str, str, str]] = set()
    unexpected_parameter_pairs: set[tuple[int, str, str, str]] = set()
    for edge in actual_edge_list:
        verification_like = bool(
            edge.get("influence_kind") == "verification"
            or (
                edge.get("influence_kind") == "control"
                and edge.get("verification_evidence", False)
            )
        )
        if (
            str(edge.get("influence_kind", ""))
            in {"control", "verification"}
            and edge.get("requirement_ids")
        ):
            # The requirement audit already validated this dependency
            # against the frozen task plan. It is authoritative evidence
            # even when it is not repeated in the parameter's resource
            # binding.
            allowed_parameter_pairs.add(
                (
                    edge["plan_revision"],
                    edge["target_step_id"],
                    edge["target_action"],
                    edge["target_parameter"],
                )
            )
            continue
        if (
            str(edge.get("influence_kind", ""))
            == "control"
            and (
                str(edge.get("plan_revision", "")),
                str(edge.get("target_step_id", "")),
                str(edge.get("target_action", "")),
                str(edge.get("target_parameter", "")),
                str(edge.get("source_app", "")).lower(),
                str(edge.get("source_entity", "")),
                tool_identity(
                    str(edge.get("source_action", "") or ""),
                    str(edge.get("source_app", "") or ""),
                ),
                str(edge.get("source_step_id", "") or ""),
            )
            in concrete_data_sources
        ):
            allowed_parameter_pairs.add(
                (
                    edge["plan_revision"],
                    edge["target_step_id"],
                    edge["target_action"],
                    edge["target_parameter"],
                )
            )
            continue
        allowed: list[dict[str, Any]] = []
        if verification_like:
            allowed = [
                *allowed_by_parameter.get(
                    (
                        edge["plan_revision"],
                        edge["target_step_id"],
                        edge["target_action"],
                        "__verification__:"
                        f"{edge['target_parameter']}",
                    ),
                    [],
                ),
                *allowed_by_parameter.get(
                    (
                        edge["plan_revision"],
                        edge["target_step_id"],
                        edge["target_action"],
                        "__verification__",
                    ),
                    [],
                ),
            ]
        if not allowed:
            allowed = allowed_by_parameter.get(
                (
                    edge["plan_revision"],
                    edge["target_step_id"],
                    edge["target_action"],
                    edge["target_parameter"],
                ),
                [],
            )
        if not allowed and edge.get("influence_kind") == "control":
            allowed = allowed_by_parameter.get(
                (
                    edge["plan_revision"],
                    edge["target_step_id"],
                    edge["target_action"],
                    "__action_control__",
                ),
                [],
            )
        if not allowed:
            dependency_sources = dependency_only_targets.get(
                (
                    str(edge.get("target_step_id", "")),
                    str(edge.get("target_action", "")),
                ),
                set(),
            )
            if (
                str(edge.get("source_step_id", "") or "")
                in dependency_sources
            ):
                allowed_parameter_pairs.add(
                    (
                        edge["plan_revision"],
                        edge["target_step_id"],
                        edge["target_action"],
                        edge["target_parameter"],
                    )
                )
                continue
        if not allowed:
            unexpected_parameter_pairs.add(
                (
                    edge["plan_revision"],
                    edge["target_step_id"],
                    edge["target_action"],
                    edge["target_parameter"],
                )
            )
            unexpected_edges.append(
                {
                    **edge,
                    "reason": "parameter_has_no_plan_binding",
                }
            )
            continue
        allowed_match = False
        for reference in allowed:
            comparison_edge: Mapping[str, Any] = edge
            comparison_reference: Mapping[str, Any] = reference
            reference_path = str(
                reference.get("source_path", "") or ""
            )
            if (
                edge.get("influence_kind") == "verification"
                and reference_path
                and not str(edge.get("source_path", "") or "")
            ):
                comparison_edge = {
                    **edge,
                    "source_path": reference_path,
                }
            if verification_like:
                comparison_reference = {
                    key: value
                    for key, value in reference.items()
                    if key != "source_path"
                }
            if _plan_ref_matches_actual(
                comparison_reference,
                comparison_edge,
            ):
                allowed_match = True
                break
        if not allowed_match:
            unexpected_parameter_pairs.add(
                (
                    edge["plan_revision"],
                    edge["target_step_id"],
                    edge["target_action"],
                    edge["target_parameter"],
                )
            )
            unexpected_edges.append(
                {
                    **edge,
                    "reason": "source_not_allowed_by_plan",
                }
            )
            continue
        allowed_parameter_pairs.add(
            (
                edge["plan_revision"],
                edge["target_step_id"],
                edge["target_action"],
                edge["target_parameter"],
            )
        )
    contaminated_parameters = {
        f"{plan_revision}:{target_step_id}:{target_action}:{parameter}"
        for plan_revision, target_step_id, target_action, parameter in (
            allowed_parameter_pairs & unexpected_parameter_pairs
        )
    }

    available = bool(
        isinstance(reference_plan, Mapping)
        and reference_plan.get("valid", True)
    )
    reference_plan_hash_verifiable = plan_hash_valid(
        reference_plan
    )
    execution_conformant = bool(
        available
        and not effective_missing_required
        and not unexpected_edges
        and not ambiguous_source_instances
        and not unplanned_actions
        and not plan_binding_issues
        and (
            execution_contract is None
            or reference_plan_hash_verifiable
        )
    )
    plan_contract_failures: list[str] | None = None
    plan_contract_conformant: bool | None = None
    plan_contract_evaluable = bool(
        isinstance(final_plan, Mapping)
        and execution_contract is not None
        and (
            not isinstance(execution_contract, Mapping)
            or bool(execution_contract)
        )
    )
    if plan_contract_evaluable:
        plan_contract_failures = validate_plan_against_contract(
            final_plan,
            execution_contract,
        )
        plan_contract_conformant = not plan_contract_failures
    contract_data: dict[str, Any] = {}
    if isinstance(execution_contract, Mapping):
        contract_data = dict(execution_contract)
    elif execution_contract is not None and hasattr(
        execution_contract,
        "to_dict",
    ):
        serialized_contract = execution_contract.to_dict()
        contract_data = (
            dict(serialized_contract)
            if isinstance(serialized_contract, Mapping)
            else {}
        )
    deferred_contract_checks = [
        f"evaluator_requirement:{kind}"
        for kind in contract_data.get(
            "deferred_evaluation_kinds",
            [],
        )
        or []
        if str(kind).strip()
    ]
    if contract_data.get("allowed_changes"):
        deferred_contract_checks.append(
            "environment_allowed_changes"
        )
    contract_identity_verifiable = bool(
        contract_data.get("task_id")
        and isinstance(final_plan, Mapping)
        and final_plan.get("task_id") == contract_data.get("task_id")
        and contract_data.get("prompt_digest")
        and final_plan.get("prompt_digest")
        == contract_data.get("prompt_digest")
        and contract_data.get("contract_digest")
        and final_plan.get("contract_digest")
        == contract_data.get("contract_digest")
    )
    process_certified = bool(
        execution_conformant
        and plan_contract_evaluable
        and plan_contract_conformant is True
        and contract_identity_verifiable
        and reference_plan_hash_verifiable
    )
    return {
        "available": available,
        "plan_hash_verifiable": (
            reference_plan_hash_verifiable
        ),
        "reference_plan_revision": reference_revision,
        "reference_plan_source": (
            "final_plan"
            if isinstance(final_plan, Mapping)
            else "last_action_snapshot"
        ),
        "plan_revisions": sorted(plan_revisions),
        "plan_hashes": sorted(plan_hashes),
        "actions_without_plan": actions_without_plan,
        "plan_snapshot_complete": actions_without_plan == 0,
        "unplanned_actions": unplanned_actions,
        "plan_binding_issues": plan_binding_issues,
        "required_edges": len(required_edges),
        "matched_required_edges": len(matched_required),
        "missing_required_edges": effective_missing_required,
        "ambiguous_source_instances": ambiguous_source_instances,
        "required_source_groups": group_records,
        "actual_edges": len(actual_edge_list),
        "data_edges": sum(
            edge.get("influence_kind") == "data"
            for edge in actual_edge_list
        ),
        "control_edges": sum(
            edge.get("influence_kind") == "control"
            for edge in actual_edge_list
        ),
        "verification_edges": sum(
            edge.get("influence_kind") == "verification"
            for edge in actual_edge_list
        ),
        "unexpected_edges": unexpected_edges,
        "contaminated_parameters": sorted(contaminated_parameters),
        "execution_conformant": execution_conformant,
        "plan_contract_evaluable": plan_contract_evaluable,
        "plan_contract_conformant": plan_contract_conformant,
        "plan_contract_failures": plan_contract_failures,
        "deferred_contract_checks": deferred_contract_checks,
        "contract_identity_verifiable": (
            contract_identity_verifiable
        ),
        "process_certified": process_certified,
    }


def _plan_ref_key(reference: Mapping[str, Any]) -> tuple[str, ...]:
    return source_ref_instance_key(reference)


def _plan_ref_identity(
    reference: Mapping[str, Any],
) -> tuple[str, ...]:
    return source_ref_identity(reference)


def _plan_ref_identity_matches(
    left: Mapping[str, Any],
    right: Mapping[str, Any],
) -> bool:
    left_identity = _plan_ref_identity(left)
    right_identity = _plan_ref_identity(right)
    return all(
        not left_value
        or not right_value
        or left_value == right_value
        for left_value, right_value in zip(
            left_identity,
            right_identity,
            strict=True,
        )
    )


def _plan_refs_equivalent(
    left: Mapping[str, Any],
    right: Mapping[str, Any],
) -> bool:
    """Return whether two plan references denote the same possible instance."""
    if _plan_ref_identity(left) != _plan_ref_identity(right):
        return False
    for keys in (
        ("source_id", "id"),
        ("producer_step",),
        ("source_path",),
        ("source_activity_id",),
        ("source_tool_call_id", "tool_call_id"),
    ):
        left_value = next(
            (
                str(left.get(key, "") or "")
                for key in keys
                if str(left.get(key, "") or "").strip()
            ),
            "",
        )
        right_value = next(
            (
                str(right.get(key, "") or "")
                for key in keys
                if str(right.get(key, "") or "").strip()
            ),
            "",
        )
        if "source_path" in keys:
            left_value = (
                normalize_source_path(left_value)
                if left_value
                else ""
            )
            right_value = (
                normalize_source_path(right_value)
                if right_value
                else ""
            )
        if left_value and right_value and left_value != right_value:
            return False
    return True


def _actual_edge_key(edge: Mapping[str, Any]) -> tuple[str, ...]:
    return (
        str(edge.get("plan_revision", "")),
        str(edge.get("target_step_id", "")),
        str(edge.get("target_action", "")),
        str(edge.get("target_parameter", "")),
        str(edge.get("source_app", "")).lower(),
        str(edge.get("source_entity", "")),
        tool_identity(
            str(edge.get("source_action", "") or ""),
            str(edge.get("source_app", "") or ""),
        ),
        normalize_source_path(str(edge.get("source_path", "") or "")),
        str(edge.get("source_activity_id", "")),
        str(edge.get("source_step_id", "")),
        str(edge.get("source_tool_call_id", "")),
        str(edge.get("influence_kind", "data")),
        ",".join(
            sorted(
                str(item)
                for item in edge.get("source_ids", [])
            )
        ),
    )


def _plan_ref_matches_actual(
    reference: Mapping[str, Any],
    actual: Mapping[str, Any],
) -> bool:
    ref_app = str(reference.get("app", "") or "").lower()
    if ref_app and ref_app != str(actual.get("source_app", "")).lower():
        return False
    ref_entity = canonical_entity_name(
        ref_app,
        str(reference.get("entity", "") or ""),
    )
    if ref_entity and ref_entity != actual.get("source_entity"):
        return False
    ref_action = tool_identity(
        str(
            reference.get("source_action")
            or reference.get("source_tool")
            or ""
        ),
        ref_app,
    )
    actual_app = str(actual.get("source_app", "") or "").lower()
    actual_action = tool_identity(
        str(actual.get("source_action", "") or ""),
        actual_app,
    )
    if (
        ref_action
        and ref_action != actual_action
    ):
        return False
    ref_source_id = str(
        reference.get("source_id")
        or reference.get("id")
        or ""
    )
    actual_source_ids = {
        str(item)
        for item in actual.get("source_ids", []) or []
        if str(item)
    }
    if (
        ref_source_id
        and actual_source_ids
        and ref_source_id not in actual_source_ids
    ):
        return False
    ref_instance_id = str(
        reference.get("source_activity_id", "") or ""
    )
    if (
        ref_instance_id
        and ref_instance_id
        != str(actual.get("source_activity_id", "") or "")
    ):
        return False
    ref_call_id = str(
        reference.get("source_tool_call_id")
        or reference.get("tool_call_id")
        or ""
    )
    if (
        ref_call_id
        and ref_call_id
        != str(actual.get("source_tool_call_id", "") or "")
    ):
        return False
    ref_producer_step = str(
        reference.get("producer_step", "") or ""
    )
    actual_source_step = str(
        actual.get("source_step_id", "") or ""
    )
    if (
        ref_producer_step
        and ref_producer_step != actual_source_step
    ):
        return False
    raw_ref_path = str(reference.get("source_path", "") or "")
    raw_actual_path = str(actual.get("source_path", "") or "")
    ref_path = (
        normalize_source_path(raw_ref_path) if raw_ref_path else ""
    )
    actual_path = (
        normalize_source_path(raw_actual_path)
        if raw_actual_path
        else ""
    )
    if ref_path:
        if not actual_path:
            return False
        canonical_ref_path = re.sub(
            r"\[\d+\]",
            "[*]",
            ref_path,
        )
        canonical_actual_path = re.sub(
            r"\[\d+\]",
            "[*]",
            actual_path,
        )
        if canonical_ref_path in {"$", "$[*]"}:
            return (
                canonical_actual_path in {"$", "$[*]"}
                or canonical_actual_path.startswith(
                    ("$.", "$[")
                )
            )
        return (
            canonical_actual_path == canonical_ref_path
            or canonical_actual_path.startswith(
                f"{canonical_ref_path}."
            )
            or canonical_actual_path.startswith(
                f"{canonical_ref_path}["
            )
        )
    return True


def _graph_endpoint_id(value: Any) -> str:
    if isinstance(value, Mapping):
        return str(value.get("id", "") or "")
    return str(value or "")


def _has_data_path(
    graph: Mapping[str, Any],
    source_id: str,
    target_id: str,
    *,
    max_depth: int = 8,
) -> bool:
    if not source_id or not target_id:
        return False
    nodes = {str(node.get("id", "")): node for node in graph.get("nodes", []) or [] if isinstance(node, Mapping)}
    data_flow_relations = {
        "produces",
        "informed",
        "wasDerivedFrom",
    }
    adjacency: dict[str, list[str]] = defaultdict(list)
    for edge in graph.get("links", []) or []:
        if not isinstance(edge, Mapping):
            continue
        if str(edge.get("relation", "")) not in data_flow_relations:
            continue
        if str(edge.get("influence", "")) == "control":
            continue
        source = _graph_endpoint_id(edge.get("source"))
        target = _graph_endpoint_id(edge.get("target"))
        if source and target:
            adjacency[source].append(target)

    queue: deque[tuple[str, int]] = deque([(source_id, 0)])
    visited = {source_id}
    allowed_intermediate = {
        "AgentTool",
        "DomainData",
        "AIModelInvocation",
        "TaskState",
    }
    while queue:
        current, depth = queue.popleft()
        if depth >= max_depth:
            continue
        for neighbor in adjacency.get(current, []):
            if neighbor == target_id:
                return True
            if neighbor in visited:
                continue
            node_type = str(nodes.get(neighbor, {}).get("type", ""))
            if node_type not in allowed_intermediate:
                continue
            visited.add(neighbor)
            queue.append((neighbor, depth + 1))
    return False


def evaluate_provenance_reconstruction(
    graph: Mapping[str, Any] | None,
    events: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Compare reconstructed graph edges with captured invocation facts.

    The captured invocation records define which source activity and output
    field actually influenced each target argument. The graph is the
    post-processing artifact being evaluated. This metric therefore measures
    capture-to-graph reconstruction fidelity, independently of whether the
    Agent followed a task plan or completed the task.
    """
    graph = graph if isinstance(graph, Mapping) else {}

    def edge_key(
        source: Mapping[str, Any],
        *,
        target_activity_id: str,
        target_action: str,
        target_app: str,
        target_parameter: str,
        forced_influence: str = "",
    ) -> tuple[str, ...] | None:
        source_kind = str(
            source.get("source_kind", "") or ""
        ).lower()
        source_app = str(
            source.get(
                "source_app",
                source.get("app", ""),
            )
            or ""
        ).lower()
        if source_kind in {
            "agent",
            "agent_literal",
            "user_prompt",
            "system_prompt",
        }:
            return None
        if source_app in {"", "agent", "system"}:
            return None
        source_activity_id = str(
            source.get("source_activity_id", "") or ""
        )
        if not source_activity_id or not target_activity_id:
            return None
        source_action = tool_identity(
            str(
                source.get("source_tool")
                or source.get("source_action")
                or source.get("tool")
                or ""
            ),
            source_app,
        )
        source_entity = canonical_entity_name(
            source_app,
            str(
                source.get("source_entity")
                or source.get("entity")
                or ""
            ),
        )
        source_path = normalize_source_path(
            str(source.get("source_path", "") or "$")
        )
        source_path = re.sub(
            r"\[\d+\]",
            "[*]",
            source_path,
        )
        provenance_role = str(
            source.get("provenance_role", "") or ""
        ).lower()
        influence = (
            forced_influence
            or (
                provenance_role
                if provenance_role in {"data", "control"}
                else ""
            )
            or (
                "control"
                if (
                    source_path == "$"
                    and bool(
                        source.get(
                            "control_influence",
                            False,
                        )
                    )
                    and not source.get("source_entity_id")
                )
                else "data"
            )
        )
        return (
            influence,
            source_app,
            source_entity,
            source_action,
            source_activity_id,
            source_path,
            str(target_app).lower(),
            tool_identity(target_action, target_app),
            target_activity_id,
            target_parameter,
        )

    def record_edges(
        record: Mapping[str, Any],
        *,
        target_activity_id: str,
        target_action: str,
        target_app: str,
    ) -> set[tuple[str, ...]]:
        result: set[tuple[str, ...]] = set()
        argument_sources = record.get("argument_sources")
        if (
            isinstance(argument_sources, Sequence)
            and not isinstance(argument_sources, str | bytes)
        ):
            for source in argument_sources:
                if not isinstance(source, Mapping):
                    continue
                parameter = str(
                    source.get("argument_root", "") or ""
                )
                if not parameter:
                    continue
                key = edge_key(
                    source,
                    target_activity_id=target_activity_id,
                    target_action=target_action,
                    target_app=target_app,
                    target_parameter=parameter,
                )
                if key:
                    result.add(key)
        resolutions = record.get("parameter_resolutions")
        if not isinstance(resolutions, Sequence) or isinstance(
            resolutions,
            str | bytes,
        ):
            resolutions = []
        for resolution in resolutions:
            if not isinstance(resolution, Mapping):
                continue
            parameter = str(
                resolution.get("parameter", "") or ""
            )
            if not parameter:
                continue
            control_sources = resolution.get("control_sources")
            if not isinstance(control_sources, Sequence) or isinstance(
                control_sources,
                str | bytes,
            ):
                continue
            for source in control_sources:
                if not isinstance(source, Mapping):
                    continue
                key = edge_key(
                    source,
                    target_activity_id=target_activity_id,
                    target_action=target_action,
                    target_app=target_app,
                    target_parameter=parameter,
                    forced_influence="control",
                )
                if key:
                    result.add(key)
        return result

    captured_edges: set[tuple[str, ...]] = set()
    for event in events:
        if not isinstance(event, Mapping):
            continue
        target_activity_id = str(
            event.get("activity_id", "") or ""
        )
        target_action = str(
            event.get("tool_intent")
            or event.get("tool_base_name")
            or event.get("label")
            or ""
        )
        target_app = str(
            event.get("app_domain")
            or event.get("target_app")
            or event.get("suite")
            or ""
        ).lower()
        if not target_activity_id or not target_action:
            continue
        captured_edges.update(
            record_edges(
                event,
                target_activity_id=target_activity_id,
                target_action=target_action,
                target_app=target_app,
            )
        )

    reconstructed_edges: set[tuple[str, ...]] = set()
    for node in graph.get("nodes", []) or []:
        if (
            not isinstance(node, Mapping)
            or str(node.get("type", "")) != "AgentTool"
        ):
            continue
        target_activity_id = str(node.get("id", "") or "")
        target_action = str(
            node.get("tool_alias")
            or node.get("tool_base_name")
            or node.get("label")
            or ""
        )
        target_app = str(
            node.get("app")
            or node.get("target_app")
            or node.get("app_domain")
            or node.get("suite")
            or ""
        ).lower()
        if not target_activity_id or not target_action:
            continue
        reconstructed_edges.update(
            record_edges(
                node,
                target_activity_id=target_activity_id,
                target_action=target_action,
                target_app=target_app,
            )
        )

    matched_edges = captured_edges & reconstructed_edges
    unmatched_captured = captured_edges - matched_edges
    unmatched_reconstructed = reconstructed_edges - matched_edges

    def data_edge_group(key: tuple[str, ...]) -> tuple[str, ...]:
        """Identify a data edge while allowing root-to-field matching."""
        return (key[0], *key[2:5], *key[6:])

    captured_groups: dict[
        tuple[str, ...],
        set[tuple[str, ...]],
    ] = defaultdict(set)
    reconstructed_groups: dict[
        tuple[str, ...],
        set[tuple[str, ...]],
    ] = defaultdict(set)
    for key in unmatched_captured:
        if key[0] == "data":
            captured_groups[data_edge_group(key)].add(key)
    for key in unmatched_reconstructed:
        if key[0] == "data":
            reconstructed_groups[data_edge_group(key)].add(key)

    generic_paths = {"$", "$[*]"}
    for group in captured_groups.keys() & reconstructed_groups.keys():
        captured_candidates = captured_groups[group]
        reconstructed_candidates = reconstructed_groups[group]
        captured_generic = {
            key
            for key in captured_candidates
            if key[5] in generic_paths
        }
        reconstructed_generic = {
            key
            for key in reconstructed_candidates
            if key[5] in generic_paths
        }
        captured_concrete = (
            captured_candidates - captured_generic
        )
        reconstructed_concrete = (
            reconstructed_candidates
            - reconstructed_generic
        )
        is_unambiguous_root_match = (
            len(captured_generic) == 1
            and len(reconstructed_concrete) == 1
            and not captured_concrete
            and not reconstructed_generic
        ) or (
            len(reconstructed_generic) == 1
            and len(captured_concrete) == 1
            and not reconstructed_concrete
            and not captured_generic
        )
        if not is_unambiguous_root_match:
            continue
        captured_key = next(iter(captured_candidates))
        reconstructed_key = next(
            iter(reconstructed_candidates)
        )
        matched_edges.add(captured_key)
        unmatched_captured.discard(captured_key)
        unmatched_reconstructed.discard(reconstructed_key)

    missing_edges = unmatched_captured
    unexpected_edges = unmatched_reconstructed
    available = bool(captured_edges or reconstructed_edges)
    denominator = (
        len(matched_edges)
        + len(missing_edges)
        + len(unexpected_edges)
    )

    def serialize(keys: set[tuple[str, ...]]) -> list[dict[str, Any]]:
        return [
            {
                "influence_kind": key[0],
                "source_app": key[1],
                "source_entity": key[2],
                "source_action": key[3],
                "source_activity_id": key[4],
                "source_path": key[5],
                "target_app": key[6],
                "target_action": key[7],
                "target_activity_id": key[8],
                "target_parameter": key[9],
            }
            for key in sorted(keys)
        ]

    return {
        "available": available,
        "captured_edges": len(captured_edges),
        "reconstructed_edges": len(reconstructed_edges),
        "matched_edges": len(matched_edges),
        "missing_edges": len(missing_edges),
        "unexpected_edges": len(unexpected_edges),
        "reconstruction_completeness": (
            len(matched_edges) / len(captured_edges)
            if captured_edges
            else 1.0
        ),
        "reconstruction_precision": (
            len(matched_edges) / len(reconstructed_edges)
            if reconstructed_edges
            else 1.0
        ),
        "reconstruction_accuracy": (
            len(matched_edges) / denominator
            if denominator
            else None
        ),
        "missing_edge_details": serialize(missing_edges),
        "unexpected_edge_details": serialize(unexpected_edges),
    }


def evaluate_cross_app_flow(
    task: Any,
    graph: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Match declared semantic dependencies to restored graph paths."""
    graph = graph if isinstance(graph, Mapping) else {}
    tool_nodes = [
        node
        for node in graph.get("nodes", []) or []
        if isinstance(node, Mapping) and str(node.get("type", "")) == "AgentTool"
    ]
    nodes_by_step: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    nodes_by_tool: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    nodes_by_semantic_output: dict[
        tuple[str, str],
        list[Mapping[str, Any]],
    ] = defaultdict(list)
    nodes_by_id: dict[str, Mapping[str, Any]] = {}
    for node in tool_nodes:
        node_id = str(node.get("id", ""))
        if node_id:
            nodes_by_id[node_id] = node
        step_id = str(node.get("plan_step_id") or node.get("subgoal_id") or "")
        if step_id:
            nodes_by_step[step_id].append(node)
        tool_name = base_tool_name(str(node.get("tool_base_name") or node.get("label") or ""))
        if tool_name:
            nodes_by_tool[tool_name].append(node)
        node_suite = str(node.get("target_app") or node.get("app_domain") or node.get("suite") or "").lower()
        output_entity = tool_output_entity(tool_name)
        if node_suite and output_entity:
            nodes_by_semantic_output[(node_suite, output_entity)].append(node)

    step_by_id = {str(step.step_id): step for step in getattr(task, "steps", ())}
    fallback_cursor: dict[str, int] = defaultdict(int)
    step_node_cache: dict[str, list[Mapping[str, Any]]] = {}

    def node_completed_successfully(
        node: Mapping[str, Any],
    ) -> bool:
        """Treat explicit failures as failures while accepting legacy nodes."""
        status = str(node.get("status", "") or "").strip().lower()
        if status:
            return status == "success"
        if bool(node.get("blocked", False)):
            return False
        return node.get("executed") is not False

    def node_matches_step(
        node: Mapping[str, Any],
        step: Any,
    ) -> bool:
        raw_name = str(
            node.get("tool_base_name")
            or node.get("tool_alias")
            or node.get("label")
            or ""
        )
        if not raw_name:
            return False
        qualified_suite, _ = split_qualified_tool_name(
            raw_name
        )
        node_suite = str(
            qualified_suite
            or node.get("suite")
            or node.get("target_app")
            or node.get("app_domain")
            or ""
        ).strip().lower()
        step_suite = str(
            getattr(step, "suite", "") or ""
        ).strip().lower()
        if node_suite in {"", "unknown", "unified"}:
            node_suite = step_suite
        return tool_identity(
            raw_name,
            node_suite,
        ) == tool_identity(
            str(getattr(step, "tool", "") or ""),
            step_suite,
        )

    def nodes_for_step(step_id: str) -> list[Mapping[str, Any]]:
        if step_id in step_node_cache:
            return step_node_cache[step_id]
        exact = nodes_by_step.get(step_id, [])
        if exact:
            step_node_cache[step_id] = exact
            return exact
        step = step_by_id.get(step_id)
        if step is None:
            step_node_cache[step_id] = []
            return []
        tool_name = base_tool_name(str(step.tool))
        candidates = nodes_by_tool.get(tool_name, [])
        semantic_fallback = False
        if not candidates:
            candidates = nodes_by_semantic_output.get(
                (
                    str(step.suite).lower(),
                    tool_output_entity(tool_name),
                ),
                [],
            )
            semantic_fallback = True
        if not candidates:
            step_node_cache[step_id] = []
            return []
        if not semantic_fallback and any(
            str(
                candidate.get("plan_step_id")
                or candidate.get("subgoal_id")
                or ""
            )
            for candidate in candidates
        ):
            step_node_cache[step_id] = []
            return []
        index = fallback_cursor[tool_name]
        fallback_cursor[tool_name] += 1
        matched = [candidates[min(index, len(candidates) - 1)]]
        step_node_cache[step_id] = matched
        return matched

    details = []
    obligations = [obligation for obligation in task.data_obligations() if obligation.required]
    for obligation in obligations:
        artifact = str(obligation.artifact)
        (
            artifact_scope_available,
            default_parameters,
        ) = resolve_artifact_target_parameters(artifact)
        target_nodes = [node for step_id in obligation.consumer_step_ids for node in nodes_for_step(step_id)]
        restored = False
        evidence = ""
        matched_alternative = None
        for alternative_index, alternative in enumerate(obligation.alternatives):
            target_scope_available = bool(
                alternative.allowed_parameters
                or artifact_scope_available
            )
            allowed_parameters = (
                set(alternative.allowed_parameters) if alternative.allowed_parameters else default_parameters
            )
            source_steps = [step_by_id[step_id] for step_id in alternative.source_step_ids if step_id in step_by_id]
            source_nodes = [node for step_id in alternative.source_step_ids for node in nodes_for_step(step_id)]
            source_ids = {str(node.get("id", "")) for node in source_nodes if node.get("id")}
            expected_suites = {str(step.suite).lower() for step in source_steps}
            expected_entities = set()
            for raw_entity in alternative.source_entities:
                text = str(raw_entity).strip()
                if not text:
                    continue
                if ":" in text:
                    app, entity = text.split(":", 1)
                    expected_entities.add(canonical_entity_name(app, entity))
                else:
                    expected_entities.add(text.lower())
            if not expected_entities:
                expected_entities = {tool_output_entity(str(step.tool)) for step in source_steps}
            for target in target_nodes:
                target_id = str(target.get("id", ""))
                target_step = step_by_id.get(
                    str(
                        target.get("plan_step_id")
                        or target.get("subgoal_id")
                        or ""
                    )
                )
                if target_step is None:
                    for consumer_step_id in (
                        obligation.consumer_step_ids
                    ):
                        candidate_step = step_by_id.get(
                            str(consumer_step_id)
                        )
                        if (
                            candidate_step is not None
                            and target in nodes_for_step(
                                str(consumer_step_id)
                            )
                        ):
                            target_step = candidate_step
                            break
                target_flow_contract = target.get(
                    "flow_contract"
                )
                control_source_ids = (
                    {
                        str(source_id)
                        for source_id in target_flow_contract.get(
                            "control_sources",
                            [],
                        )
                        if str(source_id).strip()
                    }
                    if isinstance(
                        target_flow_contract,
                        Mapping,
                    )
                    and isinstance(
                        target_flow_contract.get(
                            "control_sources",
                            [],
                        ),
                        list,
                    )
                    else set()
                )
                source_bindings = (
                    target_flow_contract.get(
                        "source_bindings",
                        {},
                    )
                    if isinstance(
                        target_flow_contract,
                        Mapping,
                    )
                    else {}
                )
                control_dependency = any(
                    isinstance(
                        source_bindings,
                        Mapping,
                    )
                    and isinstance(
                        source_bindings.get(source_id),
                        Mapping,
                    )
                    and str(
                        source_bindings[source_id].get(
                            "producer_step",
                            "",
                        )
                        or ""
                    )
                    in set(
                        str(step_id)
                        for step_id in (
                            alternative.source_step_ids
                        )
                    )
                    for source_id in control_source_ids
                )
                dependency_only = bool(
                    control_dependency
                    or (
                        target_step is not None
                        and tool_effect(
                            str(target_step.tool)
                        ).effect
                        == "read"
                        and not alternative.allowed_parameters
                    )
                )
                if dependency_only:
                    successful_sources = [
                        node
                        for node in source_nodes
                        if (
                            node_completed_successfully(node)
                            and any(
                                node_matches_step(node, source)
                                for source in source_steps
                            )
                        )
                    ]
                    if (
                        node_completed_successfully(target)
                        and node_matches_step(
                            target,
                            target_step,
                        )
                        and successful_sources
                    ):
                        restored = True
                        matched_alternative = alternative_index
                        evidence = (
                            "plan_dependency:"
                            f"{alternative.source_step_ids[0]}->"
                            f"{obligation.consumer_step_ids[0]}"
                        )
                        break
                    continue
                argument_sources = target.get("argument_sources")
                if isinstance(
                    argument_sources,
                    Sequence,
                ) and not isinstance(argument_sources, str | bytes):
                    for source in argument_sources:
                        if not isinstance(source, Mapping):
                            continue
                        source_activity = str(source.get("source_activity_id", "") or "")
                        argument_root = str(source.get("argument_root", "") or "")
                        parameter_matches = bool(
                            target_scope_available
                            and (
                                allowed_parameters is None
                                or argument_root in allowed_parameters
                            )
                        )
                        source_app = str(source.get("source_app", "")).lower()
                        observed_entity = canonical_entity_name(
                            source_app,
                            str(source.get("source_entity", "")),
                        )
                        semantic_match = bool(
                            source_activity in source_ids
                            or (
                                str(
                                    target.get("effect", "") or ""
                                )
                                in {"read", "egress"}
                                and (
                                    not expected_suites
                                    or source_app in expected_suites
                                )
                                and (
                                    not expected_entities
                                    or observed_entity
                                    in expected_entities
                                )
                            )
                        )
                        if (
                            semantic_match
                            and str(source.get("source_path", "") or "")
                            and parameter_matches
                        ):
                            restored = True
                            matched_alternative = alternative_index
                            evidence = f"argument_source:{source_activity}:{source.get('source_path')}"
                            break
                if restored:
                    break
                target_effect = str(target.get("effect", "") or "")
                if (
                    target_scope_available
                    and (
                        allowed_parameters is None
                        or target_effect == "read"
                    )
                    and any(
                    _has_data_path(graph, source_id, target_id) for source_id in source_ids
                    )
                ):
                    restored = True
                    matched_alternative = alternative_index
                    evidence = f"graph_path:{target_id}"
                    break
            if restored:
                break
        details.append(
            {
                "obligation_id": obligation.obligation_id,
                "artifact": artifact,
                "dependency_kind": obligation.dependency_kind,
                "required": obligation.required,
                "from": (
                    obligation.alternatives[0].source_step_ids[0]
                    if obligation.alternatives and obligation.alternatives[0].source_step_ids
                    else ""
                ),
                "to": (obligation.consumer_step_ids[0] if obligation.consumer_step_ids else ""),
                "matched": restored,
                "matched_alternative": matched_alternative,
                "evidence": evidence,
            }
        )

    correct = sum(bool(item["matched"]) for item in details)
    total = len(details)
    expected_task_flow_coverage = (
        correct / total if total else 1.0
    )
    return {
        "expected_flow_edges": total,
        "correct_flow_edges": correct,
        "missing_flow_edges": total - correct,
        "expected_task_flow_coverage": (
            expected_task_flow_coverage
        ),
        # Backward-compatible aliases for persisted trace consumers.
        "flow_link_completeness": (
            expected_task_flow_coverage
        ),
        "required_data_obligations": total,
        "satisfied_data_obligations": correct,
        "data_flow_accuracy": (
            expected_task_flow_coverage
        ),
        "edges": details,
    }


def evaluate_plan_path_compliance(
    plan: Mapping[str, Any] | None,
    events: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Measure trajectory adherence without conflating it with provenance."""
    if not isinstance(plan, Mapping):
        return {
            "steps_total": 0,
            "steps_completed": 0,
            "plan_path_compliance": 0.0,
            "steps": [],
        }
    successful_by_step: dict[str, set[str]] = defaultdict(set)
    fallback_events: dict[str, deque[int]] = defaultdict(deque)
    for event_index, event in enumerate(events):
        if not isinstance(event, Mapping):
            continue
        if str(event.get("status", "")).lower() != "success":
            continue
        step_id = str(event.get("plan_step_id", "") or "")
        action = _tool_identity(
            event.get("tool_intent", ""),
            event.get("tool_suite")
            or event.get("target_app")
            or event.get("app_domain")
            or "",
        )
        if step_id:
            successful_by_step[step_id].add(action)
        elif action:
            fallback_events[action].append(event_index)
    consumed_event_indices: set[int] = set()
    details = []
    for step in plan.get("steps", []):
        if not isinstance(step, Mapping):
            continue
        if step.get("optional") is True:
            continue
        step_id = str(step.get("id", "") or "")
        expected_actions = {
            plan_action_identity(step, action)
            for action in step.get("actions", [])
            if isinstance(action, Mapping)
            and action.get("name")
            and action.get("necessity") != "optional"
        }
        observed_actions = successful_by_step.get(step_id, set())
        normalized_observed_actions = {
            expected
            for expected in expected_actions
            for observed in observed_actions
            if (
                observed != expected
                and split_qualified_tool_name(observed)[0]
                is None
                and base_tool_name(observed)
                == base_tool_name(expected)
            )
        }
        observed_actions.update(normalized_observed_actions)
        matched_event_indices: list[int] = []
        missing_actions = expected_actions - observed_actions
        for action in sorted(missing_actions):
            queue = fallback_events.get(action)
            if (
                not queue
                and split_qualified_tool_name(action)[0]
                is not None
            ):
                queue = fallback_events.get(
                    base_tool_name(action)
                )
            while queue and queue[0] in consumed_event_indices:
                queue.popleft()
            if not queue:
                continue
            event_index = queue.popleft()
            consumed_event_indices.add(event_index)
            observed_actions.add(action)
            matched_event_indices.append(event_index)
        completed = bool(expected_actions) and expected_actions.issubset(observed_actions)
        details.append(
            {
                "step_id": step_id,
                "expected_actions": sorted(expected_actions),
                "observed_actions": sorted(observed_actions),
                "matched_event_indices": matched_event_indices,
                "completed": completed,
            }
        )
    total = len(details)
    completed = sum(bool(item["completed"]) for item in details)
    return {
        "steps_total": total,
        "steps_completed": completed,
        "plan_path_compliance": completed / total if total else 1.0,
        "steps": details,
    }
