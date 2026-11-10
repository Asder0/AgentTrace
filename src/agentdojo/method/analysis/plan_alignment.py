"""Align model-created plan step IDs with stable task contract IDs."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from typing import Any

from .plan_actions import plan_action_identity
from .plan_identity import finalize_plan


def align_plan_step_ids(
    plan: dict[str, Any],
    execution_contract: Mapping[str, Any] | None,
) -> list[str]:
    """Rename unambiguous plan steps to the IDs required by the contract."""

    if not isinstance(execution_contract, Mapping):
        return []
    raw_required_steps = execution_contract.get(
        "required_steps",
        [],
    )
    if not isinstance(raw_required_steps, Sequence) or isinstance(
        raw_required_steps,
        str | bytes,
    ):
        return ["execution_contract_required_steps_invalid"]
    required_steps = [
        dict(item)
        for item in raw_required_steps
        if isinstance(item, Mapping)
        and str(item.get("id", "")).strip()
    ]
    plan_steps = [
        step
        for step in plan.get("steps", []) or []
        if isinstance(step, dict)
        and str(step.get("id", "")).strip()
    ]
    if not required_steps:
        return []

    required_by_action: dict[str, list[dict[str, Any]]] = (
        defaultdict(list)
    )
    for required in required_steps:
        required_by_action[
            str(required.get("action", ""))
        ].append(required)
    plan_by_action: dict[str, list[dict[str, Any]]] = defaultdict(
        list
    )
    plan_step_identities: dict[str, set[str]] = {}
    for step in plan_steps:
        identities = {
            plan_action_identity(step, action)
            for action in step.get("actions", []) or []
            if isinstance(action, Mapping)
            and str(action.get("name", "")).strip()
        }
        step_id = str(step.get("id", ""))
        plan_step_identities[step_id] = identities
        for identity in identities:
            plan_by_action[identity].append(step)

    id_map: dict[str, str] = {}
    assigned_plan_ids: set[str] = set()
    grouped_required_ids: set[str] = set()
    required_side_effects = {
        str(item)
        for item in execution_contract.get(
            "required_side_effect_actions",
            [],
        )
        or []
        if str(item).strip()
    }
    required_groups: dict[
        tuple[str, tuple[str, ...]],
        list[dict[str, Any]],
    ] = defaultdict(list)
    for required in required_steps:
        action = str(required.get("action", ""))
        if action not in required_side_effects:
            continue
        dependencies = tuple(
            sorted(
                str(item)
                for item in required.get(
                    "depends_on",
                    [],
                )
                or []
                if str(item).strip()
            )
        )
        required_groups[(action, dependencies)].append(required)
    flow_edges_by_target: dict[
        str,
        list[Mapping[str, Any]],
    ] = defaultdict(list)
    for edge in execution_contract.get(
        "expected_flow_edges",
        [],
    ) or []:
        if not isinstance(edge, Mapping):
            continue
        target_step = str(
            edge.get("to")
            or edge.get("target_step")
            or ""
        )
        if target_step:
            flow_edges_by_target[target_step].append(edge)

    def group_flow_signature(
        step_id: str,
    ) -> tuple[tuple[Any, ...], ...]:
        return tuple(
            sorted(
                (
                    str(edge.get("artifact", "") or ""),
                    tuple(
                        sorted(
                            str(item)
                            for item in (
                                edge.get("source_actions", [])
                                or [
                                    edge.get(
                                        "source_action",
                                        "",
                                    )
                                ]
                            )
                            or []
                            if str(item).strip()
                        )
                    ),
                    tuple(
                        sorted(
                            str(item)
                            for item in edge.get(
                                "source_entities",
                                [],
                            )
                            or []
                            if str(item).strip()
                        )
                    ),
                    tuple(
                        sorted(
                            str(item)
                            for item in edge.get(
                                "allowed_parameters",
                                [],
                            )
                            or []
                            if str(item).strip()
                        )
                    ),
                    bool(
                        edge.get(
                            "allow_any_parameter",
                            False,
                        )
                    ),
                    bool(
                        edge.get(
                            "dependency_only",
                            False,
                        )
                    ),
                )
                for edge in flow_edges_by_target.get(
                    step_id,
                    [],
                )
            )
        )

    for action, required_group in required_by_action.items():
        candidates = plan_by_action.get(action, [])
        if (
            action
            and len(required_group) == 1
            and len(candidates) == 1
        ):
            required_id = str(required_group[0]["id"])
            plan_id = str(candidates[0].get("id", ""))
            if (
                plan_id
                and plan_id not in assigned_plan_ids
                and required_id not in {
                    str(step.get("id", ""))
                    for step in plan_steps
                    if str(step.get("id", "")) != plan_id
                }
            ):
                id_map[plan_id] = required_id
                assigned_plan_ids.add(plan_id)
                continue

    for (action, expected_dependencies), group in required_groups.items():
        if len(group) < 2:
            continue
        group_ids = [
            str(item.get("id", ""))
            for item in group
        ]
        signatures = {
            group_flow_signature(step_id)
            for step_id in group_ids
        }
        if (
            len(signatures) != 1
            or not next(iter(signatures), ())
        ):
            continue
        candidates = [
            candidate
            for candidate in plan_by_action.get(action, [])
            if {
                id_map.get(str(item), str(item))
                for item in candidate.get(
                    "depends_on",
                    [],
                )
                or []
            }
            == set(expected_dependencies)
        ]
        if len(candidates) != 1:
            continue
        plan_id = str(candidates[0].get("id", ""))
        required_id = str(group[0].get("id", ""))
        if (
            plan_id
            and required_id
            and plan_id not in assigned_plan_ids
        ):
            id_map[plan_id] = required_id
            assigned_plan_ids.add(plan_id)
            grouped_required_ids.update(
                str(item.get("id", ""))
                for item in group
            )

    for required in required_steps:
        required_id = str(required.get("id", ""))
        if required_id in id_map.values():
            continue
        action = str(required.get("action", ""))
        expected_dependencies = {
            id_map.get(str(item), str(item))
            for item in required.get("depends_on", []) or []
        }
        scored: list[tuple[int, dict[str, Any]]] = []
        for candidate in plan_by_action.get(action, []):
            plan_id = str(candidate.get("id", ""))
            if (
                not plan_id
                or plan_id in assigned_plan_ids
                or action
                not in plan_step_identities.get(
                    plan_id,
                    set(),
                )
            ):
                continue
            candidate_dependencies = {
                id_map.get(str(item), str(item))
                for item in candidate.get(
                    "depends_on",
                    [],
                )
                or []
            }
            score = len(
                expected_dependencies
                & candidate_dependencies
            )
            scored.append((score, candidate))
        if not scored:
            continue
        best_score = max(score for score, _candidate in scored)
        best_candidates = [
            candidate
            for score, candidate in scored
            if score == best_score
        ]
        if len(best_candidates) != 1:
            continue
        plan_id = str(best_candidates[0].get("id", ""))
        if (
            plan_id
            and plan_id not in assigned_plan_ids
        ):
            id_map[plan_id] = required_id
            assigned_plan_ids.add(plan_id)

    plan_ids = {
        str(step.get("id", "")) for step in plan_steps
    }
    matched_existing_required_ids = {
        required_id
        for required_id in {
            str(required.get("id", ""))
            for required in required_steps
            if str(required.get("id", "")).strip()
        }
        if required_id in plan_step_identities
        and any(
            str(required.get("action", ""))
            in plan_step_identities.get(required_id, set())
            for required in required_steps
            if str(required.get("id", "")) == required_id
        )
    }
    mapped_required_ids = (
        set(id_map.values())
        | matched_existing_required_ids
        | grouped_required_ids
    )
    failures = [
        (
            "unmapped_contract_step:"
            f"{required.get('id')}:{required.get('action')}"
        )
        for required in required_steps
        if str(required.get("id", ""))
        not in mapped_required_ids
    ]

    if not id_map:
        return failures

    def rewrite(value: Any, key: str = "") -> Any:
        if isinstance(value, Mapping):
            return {
                rewrite_key: rewrite(item, str(rewrite_key))
                for rewrite_key, item in value.items()
            }
        if isinstance(value, list | tuple):
            if key in {
                "depends_on",
                "required_source_steps",
                "step_ids",
            }:
                return [
                    id_map.get(str(item), str(item))
                    for item in value
                ]
            return [rewrite(item, key) for item in value]
        if key in {"producer_step", "step_id"}:
            return id_map.get(str(value), value)
        return value

    rewritten = rewrite(plan)
    for step in rewritten.get("steps", []) or []:
        if not isinstance(step, dict):
            continue
        step["id"] = id_map.get(
            str(step.get("id", "")),
            str(step.get("id", "")),
        )
    for step in rewritten.get("steps", []) or []:
        if not isinstance(step, dict):
            continue
        step["depends_on"] = [
            id_map.get(str(item), str(item))
            for item in step.get("depends_on", []) or []
        ]
    action_steps = rewritten.get("action_steps")
    if isinstance(action_steps, dict):
        rewritten["action_steps"] = {
            str(key): id_map.get(str(value), str(value))
            for key, value in action_steps.items()
        }
    plan.clear()
    plan.update(rewritten)
    finalize_plan(plan)
    return failures
