"""Immutable task contract shared by planning and runtime validation."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from ..modeling.data_sensitivity import (
    canonical_entity_name,
    parse_entity_source,
    tool_output_entity,
)
from ..modeling.policy import (
    base_tool_name,
    split_qualified_tool_name,
    tool_effect,
    tool_identity,
)
from .artifact_semantics import resolve_artifact_target_parameters
from .plan_identity import plan_hash_valid

_TARGET_PARAMETER_ALIASES: dict[
    str,
    frozenset[str],
] = {
    "body": frozenset({"body", "content"}),
    "content": frozenset({"body", "content"}),
    "recipient": frozenset({"recipient", "recipients"}),
    "recipients": frozenset({"recipient", "recipients"}),
}


def _scoped_target_parameters(
    parameters: Iterable[str],
    target_parameters: set[str],
) -> tuple[list[str], list[str]]:
    scoped: list[str] = []
    unsupported: list[str] = []
    for raw_parameter in parameters:
        parameter = str(raw_parameter).strip()
        if not parameter:
            continue
        if parameter in target_parameters:
            scoped.append(parameter)
            continue
        aliases = _TARGET_PARAMETER_ALIASES.get(
            parameter,
            frozenset({parameter}),
        )
        matches = sorted(
            aliases & target_parameters
        )
        if matches:
            scoped.extend(matches)
        else:
            unsupported.append(parameter)
    return (
        list(dict.fromkeys(scoped)),
        list(dict.fromkeys(unsupported)),
    )


def _freeze_contract_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {
                str(key): _freeze_contract_value(item)
                for key, item in value.items()
            }
        )
    if isinstance(value, list | tuple):
        return tuple(
            _freeze_contract_value(item) for item in value
        )
    if isinstance(value, set | frozenset):
        return tuple(
            sorted(_freeze_contract_value(item) for item in value)
        )
    return value


def _thaw_contract_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): _thaw_contract_value(item)
            for key, item in value.items()
        }
    if isinstance(value, tuple):
        return [_thaw_contract_value(item) for item in value]
    return value


def _literal_value_is_grounded(
    value: Any,
    prompt_text: str,
) -> bool:
    if isinstance(value, list | tuple):
        return bool(value) and all(
            _literal_value_is_grounded(item, prompt_text)
            for item in value
        )
    if isinstance(value, Mapping) or value in (None, ""):
        return False
    needle = " ".join(str(value).casefold().split())
    haystack = " ".join(str(prompt_text).casefold().split())
    return bool(needle) and needle in haystack


def execution_contract_digest(
    contract: Mapping[str, Any],
) -> str:
    """Hash the semantic contract while excluding its own digest."""

    material = {
        str(key): _thaw_contract_value(value)
        for key, value in contract.items()
        if str(key) != "contract_digest"
    }
    return hashlib.sha256(
        json.dumps(
            material,
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")
    ).hexdigest()


@dataclass(frozen=True)
class TaskExecutionContract:
    task_id: str
    prompt_digest: str
    contract_digest: str
    required_suites: tuple[str, ...]
    required_side_effect_actions: tuple[str, ...]
    required_effects: tuple[str, ...]
    required_steps: tuple[Mapping[str, Any], ...]
    expected_flow_edges: tuple[Mapping[str, Any], ...]
    contract_errors: tuple[str, ...]
    required_evaluation_kinds: tuple[str, ...]
    deferred_evaluation_kinds: tuple[str, ...]
    allowed_changes: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "prompt_digest": self.prompt_digest,
            "contract_digest": self.contract_digest,
            "required_suites": list(self.required_suites),
            "required_side_effect_actions": list(self.required_side_effect_actions),
            "required_effects": list(self.required_effects),
            "required_steps": [
                _thaw_contract_value(item)
                for item in self.required_steps
            ],
            "expected_flow_edges": [
                _thaw_contract_value(edge)
                for edge in self.expected_flow_edges
            ],
            "contract_errors": list(self.contract_errors),
            "required_evaluation_kinds": list(self.required_evaluation_kinds),
            "deferred_evaluation_kinds": list(
                self.deferred_evaluation_kinds
            ),
            "allowed_changes": list(self.allowed_changes),
        }


def build_task_execution_contract(task: Any) -> TaskExecutionContract:
    side_effects: list[str] = []
    required_effects: list[str] = []
    for step in task.steps:
        effect = tool_effect(step.tool).effect
        if effect != "read":
            side_effects.append(
                tool_identity(step.tool, step.suite)
            )
        if effect not in {"", "unknown"}:
            required_effects.append(effect)
    evaluation = task.evaluation if isinstance(task.evaluation, Mapping) else {}
    steps_by_id = {
        str(step.step_id): step for step in task.steps
    }
    all_obligations = list(task.data_obligations())
    contract_errors: list[str] = []
    if not str(task.task_id or "").strip():
        contract_errors.append("task_identity_unavailable")
    if not str(task.prompt or "").strip():
        contract_errors.append("task_prompt_empty")
    seen_obligation_ids: set[str] = set()
    for obligation in all_obligations:
        obligation_id = str(obligation.obligation_id or "")
        if not obligation_id:
            contract_errors.append(
                "data_obligation_without_id"
            )
        elif obligation_id in seen_obligation_ids:
            contract_errors.append(
                f"duplicate_data_obligation_id:{obligation_id}"
            )
        seen_obligation_ids.add(obligation_id)
        if not obligation.consumer_step_ids:
            contract_errors.append(
                f"data_obligation_without_consumer:{obligation_id}"
            )
        if not obligation.alternatives:
            contract_errors.append(
                f"data_obligation_without_alternatives:{obligation_id}"
            )
    obligations = [
        obligation
        for obligation in all_obligations
        if obligation.required
    ]
    expected_flow_edges: list[dict[str, Any]] = []
    covered_data_links: set[tuple[str, str, str]] = {
        (
            str(source_step_id),
            str(consumer_step_id),
            str(obligation.artifact),
        )
        for obligation in all_obligations
        for consumer_step_id in obligation.consumer_step_ids
        for alternative in obligation.alternatives
        for source_step_id in alternative.source_step_ids
    }
    for obligation in obligations:
        artifact = str(obligation.artifact or "")
        if not artifact:
            contract_errors.append(
                "data_obligation_without_artifact:"
                f"{obligation.obligation_id}"
            )
        for consumer_step_id in obligation.consumer_step_ids:
            consumer_step_id = str(consumer_step_id)
            target_step = steps_by_id.get(consumer_step_id)
            for alternative_index, alternative in enumerate(
                obligation.alternatives
            ):
                source_step_ids = (
                    tuple(alternative.source_step_ids)
                    or ("",)
                )
                declared_source_actions = [
                    str(item)
                    for item in alternative.source_actions
                    if str(item).strip()
                ]
                declared_source_entities = [
                    str(item)
                    for item in alternative.source_entities
                    if str(item).strip()
                ]
                alternative_source_steps = [
                    steps_by_id.get(str(step_id))
                    for step_id in source_step_ids
                ]

                def action_matches_step(
                    action_name: str,
                    source_step: Any,
                ) -> bool:
                    return bool(
                        source_step is not None
                        and tool_identity(
                            action_name,
                            source_step.suite,
                        )
                        == tool_identity(
                            source_step.tool,
                            source_step.suite,
                        )
                    )

                def entity_matches_step(
                    source_entity: str,
                    source_step: Any,
                ) -> bool:
                    if source_step is None:
                        return False
                    output_entity = tool_output_entity(
                        source_step.tool
                    )
                    if not output_entity:
                        return False
                    parsed = parse_entity_source(
                        source_entity
                    )
                    app = (
                        parsed[0]
                        if parsed is not None
                        else source_step.suite
                    )
                    entity = (
                        parsed[1]
                        if parsed is not None
                        else source_entity
                    )
                    return (
                        app == source_step.suite
                        and canonical_entity_name(app, entity)
                        == canonical_entity_name(
                            source_step.suite,
                            output_entity,
                        )
                    )

                for action_name in declared_source_actions:
                    if not any(
                        action_matches_step(
                            action_name,
                            source_step,
                        )
                        for source_step
                        in alternative_source_steps
                    ):
                        contract_errors.append(
                            "source_action_not_in_alternative:"
                            f"{obligation.obligation_id}:"
                            f"{action_name}"
                        )
                for source_entity in declared_source_entities:
                    if not any(
                        entity_matches_step(
                            source_entity,
                            source_step,
                        )
                        for source_step
                        in alternative_source_steps
                    ):
                        contract_errors.append(
                            "source_entity_not_in_alternative:"
                            f"{obligation.obligation_id}:"
                            f"{source_entity}"
                        )

                for source_step_id in source_step_ids:
                    source_step_id = str(source_step_id)
                    source_step = steps_by_id.get(
                        source_step_id
                    )
                    allowed_parameters = [
                        str(item)
                        for item in alternative.allowed_parameters
                        if str(item).strip()
                    ]
                    actual_source_action = (
                        tool_identity(
                            source_step.tool,
                            source_step.suite,
                        )
                        if source_step is not None
                        else ""
                    )
                    source_actions = [
                        tool_identity(
                            item,
                            (
                                source_step.suite
                                if source_step is not None
                                else ""
                            ),
                        )
                        for item in declared_source_actions
                        if action_matches_step(item, source_step)
                    ] if declared_source_actions else (
                        [actual_source_action]
                        if actual_source_action
                        else []
                    )
                    if (
                        declared_source_actions
                        and source_step is not None
                        and not source_actions
                    ):
                        contract_errors.append(
                            "source_step_without_declared_action:"
                            f"{obligation.obligation_id}:"
                            f"{source_step_id}:"
                            f"{actual_source_action}"
                        )
                    source_entities = [
                        item
                        for item in declared_source_entities
                        if entity_matches_step(
                            item,
                            source_step,
                        )
                    ]
                    if not source_entities and source_step is not None:
                        source_entity = tool_output_entity(
                            source_step.tool
                        )
                        if source_entity:
                            source_entities.append(
                                f"{source_step.suite}:"
                                f"{source_entity}"
                            )
                    if (
                        declared_source_entities
                        and source_step is not None
                        and not any(
                            entity_matches_step(
                                item,
                                source_step,
                            )
                            for item in declared_source_entities
                        )
                    ):
                        contract_errors.append(
                            "source_step_without_declared_entity:"
                            f"{obligation.obligation_id}:"
                            f"{source_step_id}"
                        )
                    if source_step is not None:
                        expected_source_entity = (
                            tool_output_entity(source_step.tool)
                        )
                        expected_source_entity = (
                            canonical_entity_name(
                                source_step.suite,
                                expected_source_entity,
                            )
                            if expected_source_entity
                            else ""
                        )
                        canonical_entities = {
                            (
                                source_step.suite,
                                canonical_entity_name(
                                    source_step.suite,
                                    item,
                                ),
                            )
                            for item in source_entities
                            if ":" not in item
                        }
                        for source_entity in source_entities:
                            parsed = parse_entity_source(
                                source_entity
                            )
                            if parsed is not None:
                                canonical_entities.add(
                                    (
                                        parsed[0],
                                        canonical_entity_name(
                                            parsed[0],
                                            parsed[1],
                                        ),
                                    )
                                )
                        if expected_source_entity and (
                            not canonical_entities
                            or canonical_entities
                            != {
                                (
                                    source_step.suite,
                                    expected_source_entity,
                                )
                            }
                        ):
                            contract_errors.append(
                                "source_entity_mismatch:"
                                f"{obligation.obligation_id}:"
                                f"{source_step_id}:"
                                f"{sorted(canonical_entities)}"
                            )
                        elif not expected_source_entity:
                            contract_errors.append(
                                "source_entity_semantics_unavailable:"
                                f"{obligation.obligation_id}:"
                                f"{source_step_id}"
                            )
                    allow_any_parameter = False
                    control_only_artifact = False
                    artifact_target_scope_unavailable = False
                    target_effect = "unknown"
                    target_parameters: set[str] = set()
                    if target_step is not None:
                        target_policy = tool_effect(
                            target_step.tool
                        )
                        target_effect = target_policy.effect
                        target_parameters = {
                            *target_policy.parameter_names,
                            *(
                                str(key)
                                for key in target_step.arguments
                            ),
                        }
                    explicit_target_parameters = bool(
                        allowed_parameters
                    )
                    dependency_only = bool(
                        target_effect == "read"
                        and not explicit_target_parameters
                    )
                    if explicit_target_parameters:
                        (
                            scoped_parameters,
                            unsupported_parameters,
                        ) = _scoped_target_parameters(
                            allowed_parameters,
                            target_parameters,
                        )
                        if (
                            unsupported_parameters
                            or not scoped_parameters
                        ):
                            artifact_target_scope_unavailable = True
                            contract_errors.append(
                                "unsupported_target_parameters:"
                                f"{obligation.obligation_id}:"
                                f"{consumer_step_id}:"
                                f"{allowed_parameters}:"
                                f"{sorted(target_parameters)}"
                            )
                        else:
                            allowed_parameters = (
                                scoped_parameters
                            )
                    elif not allowed_parameters:
                        (
                            target_scope_available,
                            artifact_parameters,
                        ) = resolve_artifact_target_parameters(
                            artifact
                        )
                        if target_scope_available:
                            if artifact_parameters is None:
                                allow_any_parameter = True
                            elif not artifact_parameters:
                                control_only_artifact = True
                            elif all(
                                parameter
                                in target_step.arguments
                                and _literal_value_is_grounded(
                                    target_step.arguments[
                                        parameter
                                    ],
                                    task.prompt,
                                )
                                for parameter in artifact_parameters
                            ):
                                control_only_artifact = True
                            else:
                                (
                                    scoped_parameters,
                                    _unsupported_parameters,
                                ) = _scoped_target_parameters(
                                    sorted(artifact_parameters),
                                    target_parameters,
                                )
                                if scoped_parameters:
                                    allowed_parameters.extend(
                                        scoped_parameters
                                    )
                                elif target_effect == "read":
                                    allow_any_parameter = True
                                else:
                                    artifact_target_scope_unavailable = (
                                        True
                                    )
                                    contract_errors.append(
                                        "unavailable_artifact_target_scope:"
                                        f"{source_step_id}->"
                                        f"{consumer_step_id}:"
                                        f"{artifact}"
                                    )
                        else:
                            artifact_target_scope_unavailable = True
                            contract_errors.append(
                                "unavailable_artifact_target_scope:"
                                f"{source_step_id}->"
                                f"{consumer_step_id}:{artifact}"
                            )
                    if source_step is None:
                        contract_errors.append(
                            "missing_data_source_step:"
                            f"{obligation.obligation_id}:"
                            f"{source_step_id}"
                        )
                    if target_step is None:
                        contract_errors.append(
                            "missing_data_consumer_step:"
                            f"{obligation.obligation_id}:"
                            f"{consumer_step_id}"
                        )
                    edge = {
                        "from": source_step_id,
                        "to": consumer_step_id,
                        "artifact": artifact,
                        "obligation_id": str(
                            obligation.obligation_id
                        ),
                        "alternative_group": (
                            f"{obligation.obligation_id}:"
                            f"{consumer_step_id}:{artifact}"
                        ),
                        "alternative_index": (
                            alternative_index
                        ),
                        "dependency_only": (
                            dependency_only
                            or control_only_artifact
                        ),
                    }
                    if source_step is not None:
                        edge["source_action"] = (
                            actual_source_action
                        )
                    if target_step is not None:
                        edge["target_action"] = (
                            tool_identity(
                                target_step.tool,
                                target_step.suite,
                            )
                        )
                    edge["allowed_parameters"] = list(
                        dict.fromkeys(allowed_parameters)
                    )
                    edge["allow_any_parameter"] = (
                        allow_any_parameter
                    )
                    edge[
                        "artifact_target_scope_unavailable"
                    ] = artifact_target_scope_unavailable
                    edge["source_entities"] = list(
                        dict.fromkeys(source_entities)
                    )
                    edge["source_actions"] = list(
                        dict.fromkeys(source_actions)
                    )
                    edge["dependency_kinds"] = (
                        [str(obligation.dependency_kind)]
                        if obligation.dependency_kind
                        else []
                    )
                    expected_flow_edges.append(
                        _freeze_contract_value(edge)
                    )
    contract_errors.extend(
        (
            "uncovered_data_link:"
            f"{link.get('from')}->{link.get('to')}:"
            f"{link.get('artifact')}"
        )
        for link in task.data_links()
        if (
            str(link.get("from", "")),
            str(link.get("to", "")),
            str(link.get("artifact", "")),
        )
        not in covered_data_links
    )
    all_evaluation_kinds = tuple(
        dict.fromkeys(
            str(requirement.get("kind", ""))
            for requirement in evaluation.get("requirements", [])
            if requirement.get("kind")
        )
    )
    standardized_evaluation_kinds = {
        "data",
        "action",
        "constraint",
        "semantic",
    }
    contract_values = {
        "task_id": str(task.task_id),
        "prompt_digest": hashlib.sha256(
            str(task.prompt).encode("utf-8")
        ).hexdigest(),
        "required_suites": tuple(task.required_suites),
        "required_side_effect_actions": tuple(
            dict.fromkeys(side_effects)
        ),
        "required_effects": tuple(
            dict.fromkeys(required_effects)
        ),
        "required_steps": tuple(
            {
                "id": str(step.step_id),
                "action": tool_identity(
                    step.tool,
                    step.suite,
                ),
                "depends_on": tuple(
                    str(item)
                    for item in step.depends_on
                ),
            }
            for step in task.steps
        ),
        "expected_flow_edges": tuple(
            expected_flow_edges
        ),
        "contract_errors": tuple(contract_errors),
        "required_evaluation_kinds": tuple(
            kind
            for kind in all_evaluation_kinds
            if kind in standardized_evaluation_kinds
        ),
        "deferred_evaluation_kinds": tuple(
            kind
            for kind in all_evaluation_kinds
            if kind not in standardized_evaluation_kinds
        ),
        "allowed_changes": tuple(
            str(path)
            for path in evaluation.get(
                "allowed_changes",
                [],
            )
        ),
    }
    contract_digest = execution_contract_digest(
        contract_values
    )
    return TaskExecutionContract(
        task_id=str(contract_values["task_id"]),
        prompt_digest=str(
            contract_values["prompt_digest"]
        ),
        contract_digest=contract_digest,
        required_suites=tuple(
            contract_values["required_suites"]
        ),
        required_side_effect_actions=tuple(
            contract_values[
                "required_side_effect_actions"
            ]
        ),
        required_effects=tuple(
            contract_values["required_effects"]
        ),
        required_steps=tuple(
            _freeze_contract_value(item)
            for item in contract_values["required_steps"]
        ),
        expected_flow_edges=tuple(
            contract_values["expected_flow_edges"]
        ),
        contract_errors=tuple(
            contract_values["contract_errors"]
        ),
        required_evaluation_kinds=tuple(
            contract_values[
                "required_evaluation_kinds"
            ]
        ),
        deferred_evaluation_kinds=tuple(
            contract_values[
                "deferred_evaluation_kinds"
            ]
        ),
        allowed_changes=tuple(
            contract_values["allowed_changes"]
        ),
    )


def validate_plan_against_contract(
    plan: Mapping[str, Any] | None,
    contract: Mapping[str, Any] | TaskExecutionContract | None,
) -> list[str]:
    if contract is None:
        return []
    if isinstance(contract, TaskExecutionContract):
        contract_data = contract.to_dict()
    elif isinstance(contract, Mapping):
        contract_data = dict(contract)
    else:
        return ["execution_contract_invalid"]
    if not isinstance(plan, Mapping) or not plan.get("valid", False):
        return ["plan_invalid"]

    failures: list[str] = []
    plan_hash = str(plan.get("plan_hash", "") or "")
    contract_task_identity = bool(
        contract_data.get("task_id")
    )
    if plan_hash or contract_task_identity:
        if not plan_hash_valid(plan):
            failures.append("plan_hash_invalid")
    for invalid in plan.get("invalid_actions", []) or []:
        if not isinstance(invalid, Mapping):
            failures.append("invalid_action_present")
            continue
        failures.append(
            f"invalid_action:{base_tool_name(str(invalid.get('action', 'unknown')))}:{invalid.get('reason', 'unknown')}"
        )
    plan_suites = {str(item) for item in plan.get("allowed_suites", []) if str(item).strip()}
    required_suites = {str(item) for item in contract_data.get("required_suites", []) if str(item).strip()}
    for suite in sorted(required_suites - plan_suites):
        failures.append(f"missing_required_suite:{suite}")
    for suite in sorted(plan_suites - required_suites):
        failures.append(f"unexpected_suite:{suite}")

    action_records: list[tuple[Mapping[str, Any], Mapping[str, Any]]] = [
        (step, action)
        for step in plan.get("steps", [])
        if isinstance(step, Mapping)
        for action in step.get("actions", [])
        if isinstance(action, Mapping)
    ]
    def action_identity(
        step: Mapping[str, Any],
        action: Mapping[str, Any],
    ) -> str:
        raw_name = str(action.get("name", ""))
        qualified_suite, base_name = split_qualified_tool_name(raw_name)
        if qualified_suite:
            return f"{qualified_suite}__{base_name}"
        data_access = action.get("data_access")
        access_suite = (
            str(data_access.get("app", "") or "")
            if isinstance(data_access, Mapping)
            else ""
        )
        suite = str(
            action.get("suite")
            or step.get("suite")
            or access_suite
            or ""
        ).strip()
        if not suite and len(plan_suites) == 1:
            suite = next(iter(plan_suites))
        return tool_identity(raw_name, suite)

    action_names = {
        action_identity(step, action)
        for step, action in action_records
        if action.get("name")
    }
    action_records_by_step: dict[
        str,
        list[Mapping[str, Any]],
    ] = defaultdict(list)
    action_names_by_step: dict[str, set[str]] = defaultdict(set)
    step_records_by_id: dict[str, Mapping[str, Any]] = {}
    dependencies_by_step: dict[str, set[str]] = {}
    for step in plan.get("steps", []) or []:
        if not isinstance(step, Mapping):
            continue
        step_id = str(step.get("id", "") or "")
        if step_id:
            step_records_by_id[step_id] = step
    for step, action in action_records:
        step_id = str(step.get("id", "") or "")
        if not step_id:
            continue
        action_records_by_step[step_id].append(action)
        action_names_by_step[step_id].add(
            action_identity(step, action)
        )
    for step in plan.get("steps", []) or []:
        if not isinstance(step, Mapping):
            continue
        step_id = str(step.get("id", "") or "")
        if step_id:
            dependencies_by_step[step_id] = {
                str(item)
                for item in step.get("depends_on", []) or []
                if str(item).strip()
            }

    def dependency_closure(step_id: str) -> set[str]:
        result: set[str] = set()
        queue = list(dependencies_by_step.get(step_id, set()))
        while queue:
            dependency = queue.pop(0)
            if dependency in result:
                continue
            result.add(dependency)
            queue.extend(
                dependencies_by_step.get(dependency, set())
            )
        return result

    required_steps = [
        dict(item)
        for item in contract_data.get("required_steps", []) or []
        if isinstance(item, Mapping)
    ]
    required_side_effects = {
        str(item)
        for item in contract_data.get(
            "required_side_effect_actions",
            [],
        )
        or []
        if str(item).strip()
    }
    if (
        required_side_effects
        and not any(
            str(required.get("action", ""))
            in required_side_effects
            for required in required_steps
        )
    ):
        failures.append(
            "required_side_effect_steps_unavailable"
        )
    required_groups: dict[
        tuple[str, tuple[str, ...]],
        list[dict[str, Any]],
    ] = defaultdict(list)
    for required in required_steps:
        action = str(required.get("action", "") or "")
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
    grouped_step_aliases: dict[str, str] = {}
    grouped_required_ids: set[str] = set()
    flow_edges_by_target: dict[
        str,
        list[Mapping[str, Any]],
    ] = defaultdict(list)
    for expected_edge in contract_data.get(
        "expected_flow_edges",
        [],
    ) or []:
        if not isinstance(expected_edge, Mapping):
            continue
        target_step = str(
            expected_edge.get("to")
            or expected_edge.get("target_step")
            or ""
        )
        if target_step:
            flow_edges_by_target[target_step].append(
                expected_edge
            )

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

    for (action, expected_dependencies), group in (
        required_groups.items()
    ):
        if len(group) < 2:
            continue
        group_ids = [
            str(required.get("id", "") or "")
            for required in group
            if str(required.get("id", "") or "")
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
        exact_ids = [
            step_id
            for step_id in group_ids
            if action
            in action_names_by_step.get(step_id, set())
        ]
        if len(exact_ids) == len(group_ids):
            continue
        candidates = [
            step_id
            for step_id in step_records_by_id
            if action in action_names_by_step.get(
                step_id,
                set(),
            )
            and set(expected_dependencies).issubset(
                dependency_closure(step_id)
            )
        ]
        if len(candidates) != 1:
            failures.append(
                "missing_required_step_group:"
                f"{action}:{group_ids}"
            )
            continue
        representative = candidates[0]
        grant = next(
            (
                item
                for item in plan.get("l2_grants", [])
                or []
                if isinstance(item, Mapping)
                and tool_identity(
                    str(item.get("action", "")),
                    "",
                )
                == tool_identity(action, "")
                and representative
                in {
                    str(step_id)
                    for step_id in item.get(
                        "step_ids",
                        [],
                    )
                    or []
                }
            ),
            None,
        )
        if isinstance(grant, Mapping):
            try:
                max_calls = int(
                    grant.get("max_calls", 1) or 1
                )
            except (TypeError, ValueError):
                max_calls = 1
            max_calls_mode = str(
                grant.get("max_calls_mode", "fixed")
                or "fixed"
            ).lower()
        else:
            representative_action = next(
                (
                    candidate_action
                    for candidate_action in action_records_by_step.get(
                        representative,
                        [],
                    )
                    if action_identity(
                        step_records_by_id[representative],
                        candidate_action,
                    )
                    == action
                ),
                None,
            )
            try:
                max_calls = int(
                    (representative_action or {}).get(
                        "max_calls",
                        1,
                    )
                    or 1
                )
            except (TypeError, ValueError):
                max_calls = 1
            max_calls_spec = (
                (representative_action or {}).get(
                    "max_calls_spec"
                )
            )
            max_calls_mode = str(
                max_calls_spec.get("mode", "fixed")
                if isinstance(max_calls_spec, Mapping)
                else "fixed"
            ).lower()
        if (
            max_calls_mode != "derived_cardinality"
            and max_calls < len(group_ids)
        ):
            failures.append(
                "insufficient_required_step_cardinality:"
                f"{action}:{max_calls}:{len(group_ids)}"
            )
            continue
        for required_step_id in group_ids:
            grouped_step_aliases[
                required_step_id
            ] = representative
        grouped_required_ids.update(group_ids)

    required_step_ids: set[str] = set()
    for required in required_steps:
        required_step_id = str(
            required.get("id", "") or ""
        ).strip()
        required_action = str(
            required.get("action", "") or ""
        ).strip()
        if not required_step_id or not required_action:
            failures.append("invalid_required_step")
            continue
        if required_step_id in required_step_ids:
            failures.append(
                f"duplicate_required_step:{required_step_id}"
            )
            continue
        required_step_ids.add(required_step_id)
        if required_step_id in grouped_required_ids:
            continue
        if required_step_id not in step_records_by_id:
            failures.append(
                f"missing_required_step:{required_step_id}:"
                f"{required_action}"
            )
            continue
        if bool(
            step_records_by_id[required_step_id].get(
                "optional",
                False,
            )
        ):
            failures.append(
                f"required_step_marked_optional:"
                f"{required_step_id}:{required_action}"
            )
        if required_action not in action_names_by_step.get(
            required_step_id,
            set(),
        ):
            failures.append(
                f"required_step_action_mismatch:"
                f"{required_step_id}:{required_action}"
            )
        ancestors = dependency_closure(required_step_id)
        for dependency in required.get("depends_on", []) or []:
            dependency = str(dependency)
            if dependency and dependency not in ancestors:
                failures.append(
                    f"missing_required_step_dependency:"
                    f"{required_step_id}:{dependency}"
                )

    if required_steps:
        required_side_effect_steps = {
            required_step_id
            for required in required_steps
            if str(required.get("action", ""))
            in required_side_effects
            for required_step_id in [
                str(required.get("id", "") or "")
            ]
            if required_step_id
        }
        required_side_effect_steps.update(
            grouped_step_aliases.values()
        )
        for step, action in action_records:
            action_name = action_identity(step, action)
            action_effect = str(
                action.get("effect")
                or tool_effect(
                    str(action.get("name", ""))
                ).effect
            )
            if action_effect in {"", "unknown", "read"}:
                continue
            step_id = str(step.get("id", "") or "")
            if action_name not in required_side_effects:
                failures.append(
                    f"unexpected_side_effect_action:"
                    f"{step_id}:{action_name}"
                )
            elif step_id not in required_side_effect_steps:
                failures.append(
                    f"unexpected_side_effect_step:"
                    f"{step_id}:{action_name}"
                )

        required_call_counts: dict[str, int] = defaultdict(int)
        for required in required_steps:
            action_name = str(
                required.get("action", "") or ""
            )
            if action_name in required_side_effects:
                required_call_counts[action_name] += 1

        authorized_call_counts: dict[str, int] = defaultdict(int)
        derived_call_actions: set[str] = set()
        grant_actions: set[str] = set()
        for grant in plan.get("l2_grants", []) or []:
            if not isinstance(grant, Mapping):
                continue
            action_name = tool_identity(
                str(grant.get("action", "") or ""),
                "",
            )
            if not action_name:
                continue
            grant_actions.add(action_name)
            if str(
                grant.get("max_calls_mode", "fixed")
                or "fixed"
            ).lower() == "derived_cardinality":
                derived_call_actions.add(action_name)
                continue
            try:
                authorized_call_counts[action_name] += max(
                    1,
                    int(grant.get("max_calls", 1) or 1),
                )
            except (TypeError, ValueError):
                authorized_call_counts[action_name] += 1
        for step_record, action in action_records:
            action_name = action_identity(
                step_record,
                action,
            )
            if action_name in grant_actions:
                continue
            action_effect = str(
                action.get("effect")
                or tool_effect(
                    str(action.get("name", ""))
                ).effect
            )
            if action_effect in {"", "unknown", "read"}:
                continue
            try:
                authorized_call_counts[action_name] += max(
                    1,
                    int(action.get("max_calls", 1) or 1),
                )
            except (TypeError, ValueError):
                authorized_call_counts[action_name] += 1
        for action_name, required_count in (
            required_call_counts.items()
        ):
            if action_name in derived_call_actions:
                continue
            planned_count = authorized_call_counts.get(
                action_name,
                0,
            )
            if planned_count != required_count:
                failures.append(
                    "side_effect_call_capacity_mismatch:"
                    f"{action_name}:{planned_count}:"
                    f"{required_count}"
                )

    def contract_source_bindings(
        action: Mapping[str, Any],
    ) -> list[tuple[str, Mapping[str, Any]]]:
        """Return only references that are required by this action.

        A flow-contract edge represents a real data dependency. Merely listing
        a source in the allowed scope is insufficient evidence that the
        parameter actually consumes it.
        """
        result: list[tuple[str, Mapping[str, Any]]] = []
        for contract_name in (
            "flow_contract",
            "data_flow_bindings",
            "data_access",
            "resource_access",
        ):
            contract = action.get(contract_name)
            if not isinstance(contract, Mapping):
                continue
            source_bindings = contract.get("source_bindings")
            source_bindings = (
                source_bindings
                if isinstance(source_bindings, Mapping)
                else {}
            )
            if contract_name == "flow_contract":
                result.extend(
                    ("*", source_ref)
                    for source_ref in contract.get(
                        "required_source_refs",
                        [],
                    )
                    or []
                    if isinstance(source_ref, Mapping)
                )
                for source_id in contract.get(
                    "control_sources",
                    [],
                ) or []:
                    source_ref = source_bindings.get(
                        str(source_id)
                    )
                    if isinstance(source_ref, Mapping):
                        result.append(
                            (
                                "__action_control__",
                                source_ref,
                            )
                        )
            parameter_contracts = [
                contract.get("parameter_bindings", {}),
                contract.get("resource_parameters", {}),
            ]
            for parameter_contract in parameter_contracts:
                if not isinstance(parameter_contract, Mapping):
                    continue
                for parameter, binding in parameter_contract.items():
                    if not isinstance(binding, Mapping):
                        continue
                    if str(binding.get("mode", "")).lower() == "copy":
                        source_id = str(
                            binding.get("source_id", "") or ""
                        )
                        source_ref = source_bindings.get(source_id)
                        binding_action = str(
                            binding.get("source_action")
                            or binding.get("source_tool")
                            or ""
                        )
                        if isinstance(source_ref, Mapping):
                            source_action = str(
                                source_ref.get("source_action")
                                or source_ref.get("source_tool")
                                or ""
                            )
                            if (
                                source_action
                                and binding_action
                                and tool_identity(
                                    binding_action,
                                    str(
                                        binding.get("app", "")
                                        or source_ref.get("app", "")
                                    ),
                                )
                                != tool_identity(
                                    source_action,
                                    str(source_ref.get("app", "")),
                                )
                            ):
                                source_ref = None
                        if isinstance(source_ref, Mapping):
                            result.append(
                                (
                                    str(parameter),
                                    {
                                        **dict(source_ref),
                                        **(
                                            {
                                                "source_action": (
                                                    binding_action
                                                )
                                            }
                                            if binding_action
                                            else {}
                                        ),
                                        **(
                                            {
                                                "source_path": str(
                                                    binding.get(
                                                        "source_path"
                                                    )
                                                )
                                            }
                                            if str(
                                                binding.get(
                                                    "source_path",
                                                    "",
                                                )
                                                or ""
                                            ).strip()
                                            else {}
                                        ),
                                    },
                                )
                            )
                    for source_ref in binding.get(
                        "required_source_refs",
                        [],
                    ) or []:
                        if isinstance(source_ref, Mapping):
                            result.append(
                                (str(parameter), source_ref)
                            )
                    for source_id in binding.get(
                        "required_sources",
                        [],
                    ) or []:
                        source_ref = source_bindings.get(
                            str(source_id)
                        )
                        if isinstance(source_ref, Mapping):
                            result.append(
                                (str(parameter), source_ref)
                            )
                    for group in binding.get(
                        "required_source_groups",
                        [],
                    ) or []:
                        if not isinstance(group, Mapping):
                            continue
                        for raw_source in group.get(
                            "source_refs",
                            group.get(
                                "sources",
                                group.get("source_ids", []),
                            ),
                        ) or []:
                            if isinstance(raw_source, Mapping):
                                source_ref = raw_source
                            else:
                                source_ref = source_bindings.get(
                                    str(raw_source)
                                )
                            if isinstance(source_ref, Mapping):
                                result.append(
                                    (
                                        str(parameter),
                                        source_ref,
                                    )
                                )
        return result

    for contract_error in contract_data.get(
        "contract_errors",
        [],
    ) or []:
        failures.append(str(contract_error))

    flow_groups: dict[str, dict[str, Any]] = {}
    for edge_index, expected_edge in enumerate(
        contract_data.get(
            "expected_flow_edges",
            [],
        )
        or []
    ):
        if not isinstance(expected_edge, Mapping):
            failures.append("invalid_expected_flow_edge")
            continue
        alternative_group = str(
            expected_edge.get("alternative_group", "") or ""
        )
        source_step = str(
            expected_edge.get("from")
            or expected_edge.get("source_step")
            or ""
        )
        target_step = str(
            expected_edge.get("to")
            or expected_edge.get("target_step")
            or ""
        )
        effective_source_step = grouped_step_aliases.get(
            source_step,
            source_step,
        )
        effective_target_step = grouped_step_aliases.get(
            target_step,
            target_step,
        )
        artifact = str(expected_edge.get("artifact", "") or "")
        edge_label = f"{source_step}->{target_step}:{artifact}"
        group_key = (
            alternative_group
            or f"edge:{edge_index}:{edge_label}"
        )
        group = flow_groups.setdefault(
            group_key,
            {
                "alternative_group": alternative_group,
                "edge_label": edge_label,
                "failures": [],
                "matched": False,
            },
        )

        def fail_edge(failure: str) -> None:
            group["failures"].append(failure)

        if (
            not source_step
            or not target_step
            or effective_source_step
            not in action_records_by_step
            or effective_target_step
            not in action_records_by_step
        ):
            fail_edge(
                f"missing_expected_flow_step:{edge_label}"
            )
            continue
        if effective_source_step not in dependency_closure(
            effective_target_step
        ):
            fail_edge(
                f"missing_expected_flow_dependency:{edge_label}"
            )
            continue
        if expected_edge.get("dependency_only", False):
            group["matched"] = True
            continue
        target_source_bindings = [
            (parameter, source_ref)
            for step_record, action in action_records
            if str(step_record.get("id", "") or "")
            == effective_target_step
            if not expected_edge.get("target_action")
            or action_identity(step_record, action)
            == str(expected_edge.get("target_action"))
            for parameter, source_ref in contract_source_bindings(action)
        ]
        source_actions = action_names_by_step.get(
            effective_source_step,
            set(),
        )
        source_step_record = step_records_by_id.get(
            effective_source_step,
            {},
        )
        source_step_suite = str(
            source_step_record.get("suite", "") or ""
        )
        declared_source_actions = (
            expected_edge.get("source_actions", []) or []
        )
        if not isinstance(
            declared_source_actions,
            str | bytes | list | tuple,
        ):
            declared_source_actions = []
        if not declared_source_actions:
            declared_source_actions = [
                expected_edge.get("source_action", "")
            ]
        explicit_source_actions = {
            tool_identity(
                str(item),
                source_step_suite,
            )
            for item in declared_source_actions
            if str(item).strip()
        }

        def canonical_source_entity(value: str) -> str:
            parsed = parse_entity_source(value)
            if parsed is None:
                return value.strip().lower()
            app, entity = parsed
            return (
                f"{app}:{canonical_entity_name(app, entity)}"
            )

        expected_source_entities = {
            canonical_source_entity(str(item))
            for item in expected_edge.get("source_entities", []) or []
            if str(item).strip()
        }
        allowed_parameters = {
            str(item).strip()
            for item in expected_edge.get(
                "allowed_parameters",
                [],
            ) or []
            if str(item).strip()
        }
        if expected_edge.get(
            "artifact_target_scope_unavailable",
            False,
        ):
            fail_edge(
                f"unavailable_artifact_target_scope:{edge_label}"
            )
            continue
        allow_any_parameter = bool(
            expected_edge.get("allow_any_parameter", False)
        )
        if (
            not allowed_parameters
            and not allow_any_parameter
            and not expected_edge.get(
                "artifact_target_scope_unavailable",
                False,
            )
        ):
            (
                target_scope_available,
                mapped_parameters,
            ) = resolve_artifact_target_parameters(artifact)
            if not target_scope_available:
                fail_edge(
                    f"unavailable_artifact_target_scope:{edge_label}"
                )
                continue
            if mapped_parameters is None:
                allow_any_parameter = True
            else:
                allowed_parameters = set(mapped_parameters)

        def binding_matches(
            parameter: str,
            source_ref: Mapping[str, Any],
        ) -> bool:
            if (
                allowed_parameters
                and not allow_any_parameter
                and parameter not in allowed_parameters
            ):
                return False
            ref_action = tool_identity(
                str(
                    source_ref.get("source_action")
                    or source_ref.get("source_tool")
                    or ""
                ),
                str(source_ref.get("app", "") or ""),
            )
            action_matches = (
                ref_action in explicit_source_actions
                if explicit_source_actions
                else ref_action in source_actions
            )
            if not action_matches:
                return False
            ref_entity = canonical_source_entity(
                f"{source_ref.get('app', '')!s}:"
                f"{source_ref.get('entity', '')!s}"
            )
            if (
                expected_source_entities
                and ref_entity not in expected_source_entities
            ):
                return False
            producer_step = str(
                source_ref.get("producer_step", "") or ""
            )
            return (
                not producer_step
                or producer_step == effective_source_step
            )

        if not any(
            binding_matches(parameter, source_ref)
            for parameter, source_ref
            in target_source_bindings
        ):
            fail_edge(
                f"missing_expected_flow_binding:{edge_label}"
            )
            continue
        group["matched"] = True

    for group in flow_groups.values():
        if group["matched"]:
            continue
        if group["alternative_group"]:
            failures.append(
                "missing_expected_flow_alternative:"
                f"{group['alternative_group']}"
            )
        elif group["failures"]:
            failures.append(str(group["failures"][0]))

    standardized_outcome_kinds = {
        "data",
        "action",
        "constraint",
        "semantic",
    }
    plan_outcome_kinds = {
        str(outcome.get("kind", "")).lower()
        for outcome in plan.get("required_outcomes", []) or []
        if isinstance(outcome, Mapping)
    }
    for kind in contract_data.get(
        "required_evaluation_kinds",
        [],
    ) or []:
        normalized_kind = str(kind).lower()
        if (
            normalized_kind in standardized_outcome_kinds
            and normalized_kind not in plan_outcome_kinds
        ):
            failures.append(
                f"missing_required_evaluation_kind:{normalized_kind}"
            )

    contract_digest = str(
        contract_data.get("contract_digest", "") or ""
    )
    if contract_digest:
        computed_digest = execution_contract_digest(
            contract_data
        )
        if computed_digest != contract_digest:
            failures.append(
                "execution_contract_digest_mismatch"
            )
    elif contract_data.get("task_id"):
        failures.append("contract_digest_unavailable")

    contract_task_id = str(contract_data.get("task_id", "") or "")
    plan_task_id = str(plan.get("task_id", "") or "")
    if contract_task_id:
        if not plan_task_id:
            failures.append("contract_task_identity_unavailable")
        elif contract_task_id != plan_task_id:
            failures.append(
                "contract_task_identity_mismatch:"
                f"{contract_task_id}:{plan_task_id}"
            )
    contract_prompt_digest = str(
        contract_data.get("prompt_digest", "") or ""
    )
    plan_prompt_digest = str(
        plan.get("prompt_digest", "") or ""
    )
    if contract_prompt_digest:
        if not plan_prompt_digest:
            failures.append("contract_prompt_digest_unavailable")
        elif contract_prompt_digest != plan_prompt_digest:
            failures.append("contract_prompt_digest_mismatch")
    plan_contract_digest = str(
        plan.get("contract_digest", "") or ""
    )
    if contract_digest:
        if not plan_contract_digest:
            failures.append(
                "plan_contract_digest_unavailable"
            )
        elif plan_contract_digest != contract_digest:
            failures.append(
                "contract_plan_digest_mismatch"
            )
    for action_name in contract_data.get(
        "required_side_effect_actions",
        [],
    ):
        required_name = str(action_name)
        required_suite, required_base = split_qualified_tool_name(
            required_name
        )
        expected_identity = (
            f"{required_suite}__{required_base}"
            if required_suite
            else required_base
        )
        if expected_identity not in action_names:
            failures.append(
                f"missing_required_action:{expected_identity}"
            )

    declared_effects = {str(item) for item in plan.get("allowed_effects", []) if str(item).strip()}
    for effect in contract_data.get("required_effects", []):
        if str(effect) not in declared_effects:
            failures.append(f"missing_required_effect:{effect}")
    for step, action in action_records:
        action_effect = str(action.get("effect") or tool_effect(str(action.get("name", ""))).effect)
        if action_effect and action_effect not in {"", "unknown"} and action_effect not in declared_effects:
            failures.append(
                "action_effect_not_declared:"
                f"{action_identity(step, action)}:{action_effect}"
            )
    return list(dict.fromkeys(failures))
