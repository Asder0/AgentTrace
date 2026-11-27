"""Deterministic resource and field exposure policy for Ring 2."""

from __future__ import annotations

import copy
import re
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import replace
from datetime import date, datetime
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from ..modeling.data_sensitivity import (
    ValueOrigin,
    canonical_entity_name,
    combined_field_policy,
    field_policy,
    field_sensitivity_catalog,
    normalize_data_path,
    origins_for_value,
    policy_allows_span_detection,
)
from ..modeling.labels import (
    CONFIDENTIALITY_LEVELS,
    minimum_level_for_categories,
)
from ..modeling.policy import tool_identity
from ..modeling.sensitive_ner import (
    elevate_policy_for_content,
    ensure_sensitivity_detector_ready,
)
from .access_plan import project_with_plan, schema_paths
from .source_refs import canonicalize_schema_path
from .plan_actions import find_plan_action

SENSITIVE_REFERENCE_PREFIX = "[[SENSITIVE_REF:"
SENSITIVE_REFERENCE_PATTERN = re.compile(r"\[\[SENSITIVE_REF:.+?\]\]")
_STRUCTURED_SCALAR_PATTERNS = (
    re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+"),
    re.compile(r"(?:https?://|www\.)\S+", re.IGNORECASE),
    re.compile(
        r"\d{4}-\d{2}-\d{2}"
        r"(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?"
        r"(?:Z|[+-]\d{2}:?\d{2})?)?"
    ),
    re.compile(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{12}"
    ),
    re.compile(r"[+-]?\d+(?:[.,]\d+)?"),
)
SEARCH_SELECTOR_PARAMETERS = frozenset(
    {
        "query",
        "search",
        "search_query",
        "keyword",
        "keywords",
    }
)


def _is_structured_scalar(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    text = value.strip()
    return bool(
        text
        and any(
            pattern.fullmatch(text)
            for pattern in _STRUCTURED_SCALAR_PATTERNS
        )
    )


def canonicalize_resource_value(
    value: Any,
    semantic_type: str = "",
) -> str:
    """Canonicalize a resource selector only within its declared type."""
    semantic = str(semantic_type or "").strip().lower()
    text = unicodedata.normalize("NFKC", str(value)).strip()
    if semantic in {"slack_channel", "channel"}:
        return text.lstrip("#").strip().casefold()
    if semantic in {"slack_user", "user"}:
        return text.casefold()
    if semantic == "email":
        return text.casefold()
    if semantic == "url":
        parts = urlsplit(text)
        if parts.scheme and parts.netloc:
            return urlunsplit(
                (
                    parts.scheme.lower(),
                    parts.netloc.lower(),
                    parts.path,
                    parts.query,
                    "",
                )
            )
    return text


def resource_values_equal(
    left: Any,
    right: Any,
    semantic_type: str = "",
) -> bool:
    """Compare resource values with only their declared equivalence rules."""
    return canonicalize_resource_value(
        left,
        semantic_type,
    ) == canonicalize_resource_value(
        right,
        semantic_type,
    )


def tool_resource_value(
    value: Any,
    semantic_type: str = "",
) -> Any:
    """Convert a validated selector to its tool-native representation."""
    semantic = str(semantic_type or "").strip().lower()
    if isinstance(value, list | tuple):
        return [tool_resource_value(item, semantic_type) for item in value]
    if not isinstance(value, str):
        return value
    text = unicodedata.normalize("NFKC", value).strip()
    if semantic in {"slack_channel", "channel"}:
        return text.lstrip("#").strip().casefold()
    if semantic == "email":
        return text.casefold()
    return value


def normalize_resource_source_path(path: Any) -> str:
    """Normalize an output-source path without discarding array roots."""
    raw = str(path or "$").strip()
    if not raw:
        return "$"
    indexed_root = bool(re.match(r"^\$\[", raw))
    normalized = normalize_data_path(raw)
    if indexed_root and normalized == "$":
        return "$[*]"
    if indexed_root and normalized.startswith("$."):
        return f"$[*]{normalized[1:]}"
    return normalized


def _resource_path_matches(path: str, pattern: str) -> bool:
    normalized_path = normalize_resource_source_path(path)
    normalized_pattern = normalize_resource_source_path(pattern)
    if normalized_pattern == "$":
        return normalized_path == "$" or normalized_path.startswith(("$.", "$["))
    return (
        normalized_path == normalized_pattern
        or normalized_path.startswith(f"{normalized_pattern}.")
        or normalized_path.startswith(f"{normalized_pattern}[")
    )


def _mapping_paths(
    value: Any,
    output_schema: Mapping[str, Any] | None = None,
) -> list[str]:
    if not isinstance(value, list):
        return []
    result: list[str] = []
    for item in value:
        raw = item.get("path", "") if isinstance(item, Mapping) else item
        path = normalize_data_path(
            canonicalize_schema_path(raw, output_schema)
        )
        if path:
            result.append(path)
    return list(dict.fromkeys(result))


def _schema_projection(
    visible_fields: list[str],
    output_schema: Mapping[str, Any],
    allowed_output_fields: list[str] | tuple[str, ...] | set[str] = (),
) -> list[str]:
    known = {normalize_data_path(path): path for path in schema_paths(output_schema)}
    fallback_paths = {normalize_data_path(path): normalize_data_path(path) for path in allowed_output_fields}
    projected: list[str] = []
    for path in visible_fields:
        normalized = normalize_data_path(path)
        concrete = known.get(normalized) or fallback_paths.get(normalized)
        if concrete is None and any(
            normalized.startswith(f"{allowed}.") or normalized.startswith(f"{allowed}[")
            for allowed in fallback_paths
            if allowed not in {"$", "$[*]"}
        ):
            concrete = normalized
        if concrete == normalized and output_schema.get("type") == "array" and normalized.startswith("$."):
            concrete = f"$[*]{normalized[1:]}"
        if concrete:
            projected.append(concrete)
    return list(dict.fromkeys(projected))


def _compile_resource_parameters(
    raw_resources: Any,
    *,
    action_name: str,
    resource_semantic_types: Mapping[str, str] | None = None,
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    resource_parameters: dict[str, dict[str, Any]] = {}
    warnings: list[str] = []
    if not isinstance(raw_resources, Mapping):
        return resource_parameters, warnings
    for parameter, raw_rule in raw_resources.items():
        name = str(parameter).strip()
        if not name or not isinstance(raw_rule, Mapping):
            warnings.append(f"invalid_resource_parameter:{action_name}:{parameter}")
            continue
        mode = str(raw_rule.get("mode", "literal")).lower()
        if mode not in {"literal", "derived"}:
            warnings.append(f"invalid_resource_mode:{action_name}:{name}:{mode}")
            continue
        allowed_values = [item for item in raw_rule.get("allowed_values", []) if item not in (None, "")]
        semantic_type = (
            str((resource_semantic_types or {}).get(name) or raw_rule.get("semantic_type") or "identifier")
            .strip()
            .lower()
        )
        allowed_refs = []
        for item in raw_rule.get("allowed_source_refs", []):
            if not isinstance(item, Mapping):
                continue
            source_path = str(item.get("source_path", "")).strip()
            if not item.get("source_action") or not source_path:
                warnings.append(f"derived_resource_source_ref_incomplete:{action_name}:{name}")
                continue
            allowed_refs.append(
                {
                    "app": str(item.get("app", "")).strip().lower(),
                    "entity": canonical_entity_name(
                        str(item.get("app", "")).strip().lower(),
                        str(item.get("entity", "")).strip().lower(),
                    ),
                    "source_action": str(item.get("source_action", "")).strip(),
                    "source_path": normalize_resource_source_path(source_path),
                }
            )
        required_sources = [str(item) for item in raw_rule.get("required_sources", []) if str(item).strip()]
        required_source_groups: list[dict[str, Any]] = []
        raw_groups = raw_rule.get("required_source_groups", [])
        raw_groups = raw_groups if isinstance(raw_groups, list) else []
        for group_index, raw_group in enumerate(raw_groups):
            if not isinstance(raw_group, Mapping):
                warnings.append(
                    "invalid_required_source_group:"
                    f"{action_name}:{name}:{group_index}"
                )
                continue
            mode = str(raw_group.get("mode", "all")).lower()
            if mode not in {"any", "all"}:
                warnings.append(
                    "invalid_required_source_group_mode:"
                    f"{action_name}:{name}:{group_index}:{mode}"
                )
                continue
            raw_group_sources = raw_group.get(
                "sources",
                raw_group.get(
                    "source_ids",
                    raw_group.get("source_refs", []),
                ),
            )
            if not isinstance(raw_group_sources, list):
                raw_group_sources = []
            group_source_ids: list[str] = []
            group_source_refs: list[dict[str, Any]] = []
            for raw_group_source in raw_group_sources:
                if isinstance(raw_group_source, Mapping):
                    group_ref = {
                        **dict(raw_group_source),
                        "app": str(
                            raw_group_source.get("app", "")
                        ).lower(),
                        "entity": canonical_entity_name(
                            str(raw_group_source.get("app", "")),
                            str(raw_group_source.get("entity", "")),
                        ),
                        "source_action": tool_identity(
                            str(
                                raw_group_source.get(
                                    "source_action",
                                    "",
                                )
                            ),
                            str(
                                raw_group_source.get(
                                    "app",
                                    "",
                                )
                            ),
                        ),
                    }
                    source_id = str(
                        raw_group_source.get("source_id")
                        or raw_group_source.get("id")
                        or ""
                    )
                else:
                    source_id = str(raw_group_source).strip()
                    group_ref = {"source_id": source_id}
                if not source_id:
                    warnings.append(
                        "required_source_group_source_without_id:"
                        f"{action_name}:{name}:{group_index}"
                    )
                    continue
                group_source_ids.append(source_id)
                group_source_refs.append(group_ref)
            if not group_source_ids:
                warnings.append(
                    "required_source_group_without_sources:"
                    f"{action_name}:{name}:{group_index}"
                )
                continue
            required_source_groups.append(
                {
                    "id": str(
                        raw_group.get("id")
                        or f"group_{group_index}"
                    ),
                    "mode": mode,
                    "sources": list(dict.fromkeys(group_source_ids)),
                    "source_ids": list(dict.fromkeys(group_source_ids)),
                    "source_refs": group_source_refs,
                }
            )
        if mode == "literal" and not allowed_values:
            warnings.append(f"literal_resource_without_values:{action_name}:{name}")
            continue
        if mode == "derived" and not allowed_refs:
            warnings.append(f"derived_resource_without_sources:{action_name}:{name}")
            continue
        if (
            mode == "derived"
            and not required_sources
            and not required_source_groups
        ):
            warnings.append(f"derived_resource_without_required_sources:{action_name}:{name}")
            continue
        resource_parameters[name] = {
            "mode": mode,
            "semantic_type": semantic_type,
            "explanation": str(
                raw_rule.get(
                    "explanation",
                    raw_rule.get("reason", ""),
                )
                or ""
            ).strip(),
            "allowed_values": copy.deepcopy(allowed_values),
            "allowed_canonical_values": list(
                dict.fromkeys(
                    canonicalize_resource_value(
                        item,
                        semantic_type,
                    )
                    for item in allowed_values
                )
            ),
            "allowed_source_refs": allowed_refs,
            "required_sources": required_sources,
            "required_source_groups": required_source_groups,
        }
    return resource_parameters, warnings


def compile_data_access(
    raw: Any,
    *,
    action_name: str,
    output_schema: Mapping[str, Any] | None,
    transport_required_fields: list[str] | tuple[str, ...] | set[str] = (),
    resource_fields: list[str] | tuple[str, ...] | set[str] = (),
    input_fields: list[str] | tuple[str, ...] | set[str] = (),
    allowed_output_fields: list[str] | tuple[str, ...] | set[str] = (),
    output_field_levels: Mapping[str, str] | None = None,
    allow_empty_visible: bool = False,
    app: str = "",
    entity: str = "",
    dynamic_entity_map: bool = False,
    content_detection: bool = True,
    allow_exposure_downgrade: bool = False,
    resource_semantic_types: Mapping[str, str] | None = None,
) -> tuple[dict[str, Any] | None, list[str]]:
    """Validate a planner-declared resource and output-field exposure grant."""
    warnings: list[str] = []
    if not isinstance(raw, Mapping):
        return None, [f"missing_data_access:{action_name}"]

    visible = _mapping_paths(
        raw.get("visible_fields", []),
        output_schema,
    )
    hidden = _mapping_paths(
        raw.get("hidden_fields", []),
        output_schema,
    )
    opaque = _mapping_paths(
        raw.get("opaque_fields", []),
        output_schema,
    )
    analysis = _mapping_paths(
        raw.get("analysis_fields", []),
        output_schema,
    )
    known_paths = {normalize_data_path(path) for path in schema_paths(output_schema or {})}
    known_paths.update(normalize_data_path(path) for path in allowed_output_fields)

    def known_path(path: str) -> bool:
        return path in known_paths or any(
            known not in {"$", "$[*]"} and (path.startswith(f"{known}.") or path.startswith(f"{known}["))
            for known in known_paths
        )

    invalid_paths: list[str] = []
    for label, paths in (
        ("visible", visible),
        ("hidden", hidden),
        ("opaque", opaque),
        ("analysis", analysis),
    ):
        invalid = [path for path in paths if known_paths and not known_path(path)]
        if invalid:
            warnings.append(f"invalid_{label}_fields:{action_name}:{invalid}")
            invalid_paths.extend(invalid)
    visible = [path for path in visible if path not in invalid_paths]
    hidden = [path for path in hidden if path not in invalid_paths]
    opaque = [path for path in opaque if path not in invalid_paths]
    analysis = [path for path in analysis if path not in invalid_paths]

    transport_paths = {
        normalize_data_path(path)
        for path in transport_required_fields
        if str(path).strip()
    }

    def field_is_transported(path: str) -> bool:
        normalized = normalize_data_path(path)
        return any(
            candidate == normalized
            or candidate.startswith(f"{normalized}.")
            or candidate.startswith(f"{normalized}[")
            for candidate in transport_paths
        )

    resolved_visible_hidden = (
        sorted(set(visible) & set(hidden))
        if not allow_empty_visible
        else []
    )
    if resolved_visible_hidden:
        hidden = [
            path
            for path in hidden
            if path not in resolved_visible_hidden
        ]
        warnings.append(
            "resolved_visible_hidden_exposure_overlap:"
            f"{action_name}:visible:{resolved_visible_hidden}"
        )
    visible_mode_conflicts = sorted(
        (set(visible) & set(opaque))
        | (set(visible) & set(hidden))
    )
    hidden_opaque_conflicts = sorted(
        set(hidden) & set(opaque)
    )
    if hidden_opaque_conflicts:
        keep_opaque = [
            path
            for path in hidden_opaque_conflicts
            if (
                not allow_empty_visible
                or field_is_transported(path)
            )
        ]
        keep_hidden = [
            path
            for path in hidden_opaque_conflicts
            if path not in keep_opaque
        ]
        if keep_opaque:
            hidden = [
                path
                for path in hidden
                if path not in keep_opaque
            ]
            warnings.append(
                "resolved_hidden_opaque_exposure_overlap:"
                f"{action_name}:opaque:{keep_opaque}"
            )
        if keep_hidden:
            opaque = [
                path
                for path in opaque
                if path not in keep_hidden
            ]
            warnings.append(
                "resolved_hidden_opaque_exposure_overlap:"
                f"{action_name}:hidden:{keep_hidden}"
            )
    mode_conflicts = visible_mode_conflicts
    if mode_conflicts:
        warnings.append(
            "conflicting_field_exposure_modes:"
            f"{action_name}:{mode_conflicts}"
        )
    normalized_visible = {
        normalize_data_path(path) for path in visible
    }
    analysis_not_visible = sorted(
        {
            path
            for path in analysis
            if not any(
                (
                    normalize_data_path(path)
                    == normalize_data_path(visible_path)
                    or normalize_data_path(path).startswith(
                        f"{normalize_data_path(visible_path)}."
                    )
                    or normalize_data_path(path).startswith(
                        f"{normalize_data_path(visible_path)}["
                    )
                )
                for visible_path in visible
            )
        }
        - normalized_visible
    )
    if analysis_not_visible:
        warnings.append(
            "analysis_fields_not_visible:"
            f"{action_name}:{analysis_not_visible}"
        )

    resource_parameters, resource_warnings = _compile_resource_parameters(
        raw.get("resource_parameters", {}),
        action_name=action_name,
        resource_semantic_types=resource_semantic_types,
    )
    warnings.extend(resource_warnings)
    known_inputs = {str(item).strip() for item in input_fields if str(item).strip()}
    unknown_resources = sorted(set(resource_parameters) - known_inputs) if known_inputs else []
    if resource_parameters and not known_inputs:
        schema_warning = f"input_schema_unavailable_for_resource_parameters:{action_name}"
        warnings.append(schema_warning)
        resource_warnings.append(schema_warning)
    if known_inputs and unknown_resources:
        warnings.append(f"resource_parameter_not_in_schema:{action_name}:{unknown_resources}")

    valid = (
        (bool(visible) or bool(opaque) or allow_empty_visible)
        and not invalid_paths
        and not mode_conflicts
        and not analysis_not_visible
        and not unknown_resources
        and not resource_warnings
    )
    missing_resource_fields = sorted(
        {str(item) for item in resource_fields if str(item).strip() and str(item) not in resource_parameters}
    )
    if missing_resource_fields:
        warnings.append(f"missing_resource_access:{action_name}:{missing_resource_fields}")
        valid = False
    if not visible and not opaque and not allow_empty_visible:
        warnings.append(f"data_access_without_visible_fields:{action_name}")
    max_exposure_level = str(raw.get("max_exposure_level", "internal")).lower()
    planned_max_exposure_level = max_exposure_level
    if max_exposure_level not in CONFIDENTIALITY_LEVELS:
        warnings.append(f"invalid_max_exposure_level:{action_name}:{max_exposure_level}")
        max_exposure_level = "internal"
        valid = False
    resolved_field_levels = dict(output_field_levels or {})
    if not resolved_field_levels and app and entity:
        resolved_field_levels = {
            path: str(policy.get("level", "secret"))
            for path, policy in (
                field_sensitivity_catalog().get(str(app).lower(), {}).get(str(entity).lower(), {})
            ).items()
        }
    configured_levels = {normalize_data_path(path): str(level).lower() for path, level in resolved_field_levels.items()}

    def configured_level(path: str) -> str | None:
        matches = [
            (known, level)
            for known, level in configured_levels.items()
            if path == known or path.startswith(f"{known}.") or path.startswith(f"{known}[")
        ]
        return max(matches, key=lambda item: len(item[0]))[1] if matches else None

    if (
        "$" in visible
        and isinstance(output_schema, Mapping)
        and output_schema.get("type") == "object"
        and output_schema.get("dynamic") is True
        and allowed_output_fields
    ):
        maximum_rank = CONFIDENTIALITY_LEVELS.get(
            max_exposure_level,
            0,
        )
        expanded_visible = sorted(
            {
                path
                for path in (
                    normalize_data_path(item)
                    for item in allowed_output_fields
                )
                if path
                and path not in {"$", "$[*]"}
                and CONFIDENTIALITY_LEVELS.get(
                    configured_level(path) or max_exposure_level,
                    3,
                )
                <= maximum_rank
            }
        )
        if expanded_visible:
            visible = [
                path
                for path in visible
                if path != "$"
            ]
            visible = list(
                dict.fromkeys(
                    [*visible, *expanded_visible]
                )
            )
            warnings.append(
                "dynamic_root_visible_fields_expanded:"
                f"{action_name}:{expanded_visible}"
            )

    broad_field_level = max(
        (CONFIDENTIALITY_LEVELS.get(level, 3) for level in configured_levels.values()),
        default=CONFIDENTIALITY_LEVELS.get(max_exposure_level, 0),
    )
    exceeding_fields = []
    for path in visible:
        path_level = configured_level(path)
        configured_rank = (
            broad_field_level
            if path == "$" and path_level is None
            else CONFIDENTIALITY_LEVELS.get(
                path_level or max_exposure_level,
                3,
            )
        )
        if configured_rank > CONFIDENTIALITY_LEVELS.get(
            max_exposure_level,
            0,
        ):
            exceeding_fields.append(path)
    if exceeding_fields:
        required_exposure_level = max(
            (
                CONFIDENTIALITY_LEVELS.get(
                    configured_level(path)
                    or (
                        "secret"
                        if path == "$"
                        else max_exposure_level
                    ),
                    3,
                )
                for path in exceeding_fields
            ),
            default=CONFIDENTIALITY_LEVELS.get(
                max_exposure_level,
                0,
            ),
        )
        max_exposure_level = next(
            (
                level
                for level, rank in CONFIDENTIALITY_LEVELS.items()
                if rank == required_exposure_level
            ),
            "secret",
        )
        warnings.append(
            "exposure_limit_auto_raised_for_task_plan:"
            f"{action_name}:{planned_max_exposure_level}"
            f"->{max_exposure_level}:{exceeding_fields}"
        )

    requested_visible_fields = list(visible)
    protected_visible_fields: list[str] = []
    for path in visible:
        path_level = configured_level(path)
        if path == "$" and path_level is None:
            path_rank = broad_field_level
        else:
            path_rank = CONFIDENTIALITY_LEVELS.get(
                path_level or "internal",
                3,
            )
        if path_rank > CONFIDENTIALITY_LEVELS["internal"]:
            protected_visible_fields.append(path)
    if visible and CONFIDENTIALITY_LEVELS.get(max_exposure_level, 0) > CONFIDENTIALITY_LEVELS["internal"]:
        protected_visible_fields.extend(visible)
    protected_visible_fields = list(dict.fromkeys(protected_visible_fields))
    dynamic_mapping_policy_paths: list[str] = []
    if (
        dynamic_entity_map
        and output_schema is not None
        and output_schema.get("type") == "object"
        and output_schema.get("dynamic") is True
    ):
        dynamic_mapping_policy_paths = list(requested_visible_fields)
        if visible:
            visible = ["$"]
    exposure_modes = {
        "inspect": list(visible),
        "analysis": list(analysis),
        "transport": list(opaque),
        "hidden": list(hidden),
    }
    return {
        "valid": valid,
        "source_action": action_name,
        "app": str(app),
        "entity": str(entity),
        "resource_parameters": resource_parameters,
        "visible_fields": visible,
        "requested_visible_fields": requested_visible_fields,
        "analysis_fields": analysis,
        "opaque_fields": opaque,
        "hidden_fields": hidden,
        "dynamic_entity_map": bool(dynamic_mapping_policy_paths),
        "dynamic_mapping_policy_paths": (dynamic_mapping_policy_paths),
        "content_detection": bool(content_detection),
        "max_exposure_level": max_exposure_level,
        "planned_max_exposure_level": planned_max_exposure_level,
        "exposure_limit_auto_raised": bool(exceeding_fields),
        "exposure_modes": exposure_modes,
        "protected_visible_fields": protected_visible_fields,
        "requires_exposure_authorization": bool(protected_visible_fields),
        "root_is_array": output_schema is not None and output_schema.get("type") == "array",
        "schema_paths": list(
            dict.fromkeys(
                [
                    *schema_paths(output_schema or {}),
                    *[
                        (
                            f"$[*]{normalize_data_path(path)[1:]}"
                            if output_schema is not None
                            and output_schema.get("type") == "array"
                            and normalize_data_path(path).startswith("$.")
                            else normalize_data_path(path)
                        )
                        for path in allowed_output_fields
                    ],
                ]
            )
        ),
        "projection": {
            "decision": "PROJECT",
            "visible_fields": _schema_projection(
                visible,
                output_schema or {},
                allowed_output_fields,
            ),
            "hidden_fields": _schema_projection(
                hidden,
                output_schema or {},
                allowed_output_fields,
            ),
            "opaque_fields": _schema_projection(
                opaque,
                output_schema or {},
                allowed_output_fields,
            ),
        },
    }, warnings


def compile_resource_access(
    raw: Any,
    *,
    action_name: str,
    resource_fields: list[str] | tuple[str, ...] | set[str] = (),
    input_fields: list[str] | tuple[str, ...] | set[str] = (),
    resource_semantic_types: Mapping[str, str] | None = None,
) -> tuple[dict[str, Any] | None, list[str]]:
    """Compile the resource scope for a non-read action."""
    warnings: list[str] = []
    if not isinstance(raw, Mapping):
        return None, [f"missing_resource_access:{action_name}"]
    resource_parameters, resource_warnings = _compile_resource_parameters(
        raw.get("resource_parameters", {}),
        action_name=action_name,
        resource_semantic_types=resource_semantic_types,
    )
    warnings.extend(resource_warnings)
    required = {str(item).strip() for item in resource_fields if str(item).strip()}
    known_inputs = {str(item).strip() for item in input_fields if str(item).strip()}
    unknown_resources = sorted(set(resource_parameters) - known_inputs) if known_inputs else []
    if resource_parameters and not known_inputs:
        schema_warning = f"input_schema_unavailable_for_resource_parameters:{action_name}"
        warnings.append(schema_warning)
        resource_warnings.append(schema_warning)
    if known_inputs and unknown_resources:
        warnings.append(f"resource_parameter_not_in_schema:{action_name}:{unknown_resources}")
    missing = sorted(required - set(resource_parameters))
    if missing:
        warnings.append(f"missing_resource_access:{action_name}:{missing}")
    valid = bool(resource_parameters) and not missing and not unknown_resources and not resource_warnings
    return {
        "valid": valid,
        "source_action": action_name,
        "resource_parameters": resource_parameters,
    }, warnings


def action_data_access(
    plan: Mapping[str, Any] | None,
    tool_name: str,
    step_id: str = "",
) -> dict[str, Any] | None:
    action = find_plan_action(
        plan,
        tool_name,
        step_id=step_id,
    )
    value = action.get("data_access") if action else None
    if isinstance(value, Mapping):
        return copy.deepcopy(dict(value))
    return None


def action_resource_access(
    plan: Mapping[str, Any] | None,
    tool_name: str,
    step_id: str = "",
) -> dict[str, Any] | None:
    """Resolve the resource-only contract for a write, privilege or egress action."""
    action = find_plan_action(
        plan,
        tool_name,
        step_id=step_id,
    )
    value = action.get("resource_access") if action else None
    if isinstance(value, Mapping):
        return copy.deepcopy(dict(value))
    return None


def _flatten_scalars(value: Any) -> list[Any]:
    if isinstance(value, list | tuple | set):
        return [child for item in value for child in _flatten_scalars(item)]
    if isinstance(value, Mapping):
        return [child for item in value.values() for child in _flatten_scalars(item)]
    return [] if value in (None, "") else [value]


def value_occurs_in_origin(
    value: Any,
    origin: ValueOrigin,
    semantic_type: str,
) -> bool:
    """Recognize an exact scalar extracted from an authorized text field."""
    if not isinstance(value, str) or not isinstance(origin.value, str):
        return False
    if str(semantic_type).lower() in {"date", "datetime"}:
        return _temporal_value_occurs_in_origin(
            value,
            origin.value,
        )
    needle = " ".join(unicodedata.normalize("NFKC", value).casefold().split())
    if len(needle) < 2:
        return False
    haystack = " ".join(
        unicodedata.normalize(
            "NFKC",
            origin.value,
        )
        .casefold()
        .split()
    )
    if not haystack:
        return False
    if semantic_type in {"email", "slack_user", "user", "url"}:
        return needle == haystack
    return bool(
        re.search(
            rf"(?<![\w]){re.escape(needle)}(?![\w])",
            haystack,
        )
    )


def composed_value_supports_origin(
    value: Any,
    origin: ValueOrigin,
) -> bool:
    """Recognize a generated value that preserves distinctive source tokens."""
    if not isinstance(value, str) or not isinstance(origin.value, str):
        return False
    generated = unicodedata.normalize("NFKC", value)
    source = unicodedata.normalize("NFKC", origin.value)
    if not generated.strip() or not source.strip():
        return False
    generated_folded = generated.casefold()
    source_folded = source.casefold()
    if (
        len(source_folded) >= 2
        and source_folded in generated_folded
    ):
        return True

    strong_token_pattern = re.compile(
        r"(?<![\w])(?:"
        r"[A-Za-z]{1,6}\d{2,}[A-Za-z0-9-]*"
        r"|\d{2,}[A-Za-z]{1,6}[A-Za-z0-9-]*"
        r"|(?:19|20)\d{2}-\d{1,2}-\d{1,2}"
        r"|(?:19|20)\d{2}[-/]\d{1,2}[-/]\d{1,2}"
        r"|[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}"
        r"|https?://\S+"
        r")(?![\w])",
        flags=re.IGNORECASE,
    )
    source_tokens = {
        token.casefold()
        for token in strong_token_pattern.findall(source)
    }
    if not source_tokens:
        return False
    generated_tokens = {
        token.casefold()
        for token in strong_token_pattern.findall(generated)
    }
    return bool(source_tokens & generated_tokens)


def value_occurs_in_trusted_text(
    value: Any,
    text: str,
    semantic_type: str = "",
) -> bool:
    """Return whether a selector value is explicitly grounded in trusted text."""
    if value in (None, "") or not str(text).strip():
        return False
    normalized_value = unicodedata.normalize(
        "NFKC",
        str(value),
    ).strip()
    normalized_semantic = str(semantic_type).strip().lower()
    if normalized_semantic == "email" and not re.fullmatch(
        r"[^@\s]+@[^@\s]+\.[^@\s]+",
        normalized_value,
    ):
        return False
    if normalized_semantic == "iban" and not re.fullmatch(
        r"[A-Za-z]{2}\d{2}[A-Za-z0-9]{10,30}",
        normalized_value,
    ):
        return False
    if (
        normalized_semantic in {"slack_user", "user"}
        and (
            "@" in normalized_value
            or re.fullmatch(
                r"[A-Za-z]{2}\d{2}[A-Za-z0-9]{10,30}",
                normalized_value,
            )
        )
    ):
        return False
    if normalized_semantic in {"date", "datetime"}:
        return _temporal_value_occurs_in_origin(
            str(value),
            str(text),
        )
    needle = " ".join(
        unicodedata.normalize("NFKC", str(value))
        .casefold()
        .split()
    )
    if len(needle) < 2:
        return False
    haystack = " ".join(
        unicodedata.normalize("NFKC", str(text))
        .casefold()
        .split()
    )
    return bool(
        re.search(
            rf"(?<![\w]){re.escape(needle)}(?![\w])",
            haystack,
        )
    )


def _clock_occurrences(
    text: str,
) -> list[tuple[int, int, int]]:
    """Extract clock values and source offsets from natural-language text."""
    result: list[tuple[int, int, int]] = []
    source = unicodedata.normalize("NFKC", text)
    for match in re.finditer(
        r"\b(noon|midnight)\b",
        source,
        flags=re.IGNORECASE,
    ):
        result.append(
            (
                match.start(),
                match.end(),
                12 * 60
                if match.group(1).lower() == "noon"
                else 0,
            )
        )
    for match in re.finditer(
        r"(?<![\w])(\d{1,2})(?::(\d{2}))?"
        r"\s*(AM|PM)(?![\w])",
        source,
        flags=re.IGNORECASE,
    ):
        hour = int(match.group(1)) % 12
        minute = int(match.group(2) or 0)
        if match.group(3).upper() == "PM":
            hour += 12
        result.append(
            (
                match.start(),
                match.end(),
                hour * 60 + minute,
            )
        )
    for match in re.finditer(
        r"(?<![\w])([01]?\d|2[0-3]):([0-5]\d)(?![\w])",
        source,
    ):
        hour = int(match.group(1))
        minute = int(match.group(2))
        result.append(
            (
                match.start(),
                match.end(),
                hour * 60 + minute,
            )
        )
    return result


def _temporal_value_occurs_in_origin(
    value: str,
    origin_text: str,
) -> bool:
    """Match an ISO temporal value against natural-language source text."""
    raw_value = str(value).strip()
    try:
        target = datetime.fromisoformat(
            raw_value.replace("Z", "+00:00")
        )
    except ValueError:
        try:
            target = datetime.combine(
                date.fromisoformat(raw_value[:10]),
                datetime.min.time(),
            )
        except ValueError:
            return False
    source = unicodedata.normalize("NFKC", origin_text)
    years = {
        int(match)
        for match in re.findall(r"\b(?:19|20)\d{2}\b", source)
    }
    if years and target.year not in years:
        return False
    matched_dates: set[date] = set()
    matched_date_windows: dict[
        date,
        list[tuple[int, int]],
    ] = {}

    def remember_date(
        matched_date: date,
        start: int,
        end: int,
    ) -> None:
        matched_dates.add(matched_date)
        matched_date_windows.setdefault(
            matched_date,
            [],
        ).append((start, end))

    for match in re.finditer(
        r"\b(?:19|20)\d{2}-\d{1,2}-\d{1,2}\b",
        source,
    ):
        try:
            parsed = date.fromisoformat(match.group(0))
        except ValueError:
            continue
        remember_date(
            parsed,
            match.start(),
            match.end(),
        )
    month_numbers = {
        "jan": 1,
        "feb": 2,
        "mar": 3,
        "apr": 4,
        "may": 5,
        "jun": 6,
        "jul": 7,
        "aug": 8,
        "sep": 9,
        "oct": 10,
        "nov": 11,
        "dec": 12,
    }
    for match in re.finditer(
        r"\b("
        r"Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|"
        r"May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|"
        r"Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?"
        r")\.?\s+(\d{1,2})(?:st|nd|rd|th)?\b",
        source,
        flags=re.IGNORECASE,
    ):
        month = month_numbers[
            match.group(1)[:3].casefold()
        ]
        day = int(match.group(2))
        if month and 1 <= day <= 31:
            try:
                parsed = date(
                    target.year,
                    month,
                    day,
                )
                remember_date(
                    parsed,
                    match.start(),
                    match.end(),
                )
            except ValueError:
                pass
    for match in re.finditer(
        r"\b("
        r"Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|"
        r"May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|"
        r"Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?"
        r")\.?\s+(\d{1,2})(?:st|nd|rd|th)?"
        r"(?:\s*,?\s*(?:19|20)\d{2})?"
        r"\s*(?:to|through|until|and|-|–)\s*"
        r"(?:(Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|"
        r"May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|"
        r"Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?"
        r")\s+)?"
        r"(\d{1,2})(?:st|nd|rd|th)?"
        r"(?:\s*,?\s*((?:19|20)\d{2}))?",
        source,
        flags=re.IGNORECASE,
    ):
        start_month = month_numbers[
            match.group(1)[:3].casefold()
        ]
        end_month = (
            month_numbers[match.group(3)[:3].casefold()]
            if match.group(3)
            else start_month
        )
        year = (
            int(match.group(5))
            if match.group(5)
            else target.year
        )
        try:
            range_start = date(
                year,
                start_month,
                int(match.group(2)),
            )
            range_end = date(
                year,
                end_month,
                int(match.group(4)),
            )
        except ValueError:
            continue
        if range_end < range_start:
            continue
        for range_date in (
            range_start,
            range_end,
        ):
            remember_date(
                range_date,
                match.start(),
                match.end(),
            )

    if target.date() not in matched_dates:
        return False
    value_has_time = bool(
        re.search(
            r"[T ]\d{2}:\d{2}",
            raw_value,
        )
    )
    if not value_has_time:
        return True
    target_minutes = target.hour * 60 + target.minute
    clock_occurrences = _clock_occurrences(source)
    source_minutes = {
        minutes
        for _start, _end, minutes in clock_occurrences
    }
    if target_minutes == 0:
        # A date-only source grounds midnight for a date-only operation.
        # Once the source states a clock time, midnight must match exactly.
        return not source_minutes or 0 in source_minutes
    if target_minutes not in source_minutes:
        return False
    if len(matched_dates) == 1:
        return True
    target_windows = matched_date_windows.get(
        target.date(),
        [],
    )
    all_date_windows = [
        window
        for windows in matched_date_windows.values()
        for window in windows
    ]

    def window_distance(
        clock_start: int,
        clock_end: int,
        date_start: int,
        date_end: int,
    ) -> int:
        if clock_start >= date_start and clock_end <= date_end:
            return 0
        if clock_end < date_start:
            return date_start - clock_end
        return clock_start - date_end

    for clock_start, clock_end, clock_minutes in clock_occurrences:
        if clock_minutes != target_minutes:
            continue
        target_distance = min(
            (
                window_distance(
                    clock_start,
                    clock_end,
                    date_start,
                    date_end,
                )
                for date_start, date_end in target_windows
            ),
            default=len(source) + 1,
        )
        nearest_distance = min(
            (
                window_distance(
                    clock_start,
                    clock_end,
                    date_start,
                    date_end,
                )
                for date_start, date_end in all_date_windows
            ),
            default=len(source) + 1,
        )
        if target_distance <= nearest_distance:
            return True
    return False


def resolve_resource_parameter_resolutions(
    plan: Mapping[str, Any] | None,
    tool_name: str,
    step_id: str,
    inputs: Mapping[str, Any],
    value_index: Mapping[str, list[ValueOrigin]],
    events: Sequence[Mapping[str, Any]] = (),
) -> list[dict[str, Any]]:
    """Resolve derived resource selectors from controller-tracked value origins."""
    contract = action_data_access(plan, tool_name, step_id)
    resource_contract = action_resource_access(
        plan,
        tool_name,
        step_id,
    )
    if resource_contract is not None and (contract is None or not contract.get("resource_parameters")):
        contract = resource_contract
    if not isinstance(contract, Mapping):
        return []
    resource_parameters = contract.get("resource_parameters", {})
    if not isinstance(resource_parameters, Mapping):
        return []
    source_registry = plan.get("source_refs", {}) if isinstance(plan, Mapping) else {}
    source_registry = source_registry if isinstance(source_registry, Mapping) else {}
    event_by_activity = {
        str(event.get("activity_id", "") or ""): event
        for event in events
        if isinstance(event, Mapping)
        and str(event.get("activity_id", "") or "")
    }

    def source_ids_for_origin(
        origin: ValueOrigin,
    ) -> tuple[list[str], bool]:
        identity = (
            origin.app.lower(),
            canonical_entity_name(
                origin.app,
                origin.entity,
            ),
            tool_identity(origin.source_tool, origin.app),
        )
        candidates = [
            (str(source_id), source)
            for source_id, source in source_registry.items()
            if isinstance(source, Mapping)
            and (
                str(source.get("app", "")).lower(),
                canonical_entity_name(
                    str(source.get("app", "")),
                    str(source.get("entity", "")),
                ),
                tool_identity(
                    str(
                        source.get("source_action")
                        or source.get("source_tool")
                        or ""
                    ),
                    str(source.get("app", "")),
                ),
            )
            == identity
        ]
        event = event_by_activity.get(
            str(origin.source_activity_id or ""),
            {},
        )
        plan_step_id = str(event.get("plan_step_id", "") or "")
        tool_call_id = str(
            event.get("tool_call_id")
            or event.get("source_tool_call_id")
            or ""
        )
        filtered = []
        for source_id, source in candidates:
            declared_activity = str(
                source.get("source_activity_id", "") or ""
            )
            declared_call = str(
                source.get("source_tool_call_id")
                or source.get("tool_call_id")
                or ""
            )
            declared_step = str(
                source.get("producer_step", "") or ""
            )
            if (
                declared_activity
                and origin.source_activity_id
                and declared_activity != origin.source_activity_id
            ):
                continue
            if (
                declared_call
                and tool_call_id
                and declared_call != tool_call_id
            ):
                continue
            if (
                declared_step
                and plan_step_id
                and declared_step != plan_step_id
            ):
                continue
            filtered.append(source_id)
        return filtered, len(filtered) > 1

    resolutions: list[dict[str, Any]] = []
    for parameter, raw_rule in resource_parameters.items():
        if not isinstance(raw_rule, Mapping) or str(raw_rule.get("mode", "")).lower() != "derived":
            continue
        semantic_type = str(raw_rule.get("semantic_type", "identifier"))
        allowed_refs = [
            {
                "app": str(item.get("app", "")).lower(),
                "entity": canonical_entity_name(
                    str(item.get("app", "")),
                    str(item.get("entity", "")),
                ),
                "source_action": tool_identity(
                    str(item.get("source_action", "")),
                    str(item.get("app", "")),
                ),
                "source_path": (
                    normalize_resource_source_path(str(item.get("source_path", "")))
                    if str(item.get("source_path", "")).strip()
                    else ""
                ),
            }
            for item in raw_rule.get("allowed_source_refs", [])
            if isinstance(item, Mapping) and item.get("source_action")
        ]

        def origin_is_allowed(origin: ValueOrigin) -> bool:
            source_path = normalize_resource_source_path(origin.source_path)
            return any(
                origin.app.lower() == ref["app"]
                and canonical_entity_name(
                    origin.app,
                    origin.entity,
                )
                == ref["entity"]
                and tool_identity(
                    origin.source_tool,
                    origin.app,
                )
                == ref["source_action"]
                and (
                    not ref["source_path"]
                    or _resource_path_matches(
                        source_path,
                        ref["source_path"],
                    )
                )
                for ref in allowed_refs
            )

        origins: list[ValueOrigin] = []
        all_required_source_ids: set[str] = set()
        matched_required_source_ids: set[str] = set()
        unresolved_value_count = 0
        ambiguous_value_count = 0
        ambiguous_source_instance_count = 0
        for value in _flatten_scalars(inputs.get(str(parameter))):
            all_value_origins = origins_for_value(value_index, value)
            canonical_value = canonicalize_resource_value(
                value,
                semantic_type,
            )
            if canonical_value:
                all_value_origins.extend(
                    origin
                    for records in value_index.values()
                    for origin in records
                    if canonicalize_resource_value(
                        origin.value,
                        semantic_type,
                    )
                    == canonical_value
                    or (
                        origin.container_key
                        and canonicalize_resource_value(
                            origin.container_key,
                            semantic_type,
                        )
                        == canonical_value
                    )
                )
            all_value_origins = list(
                {
                    (
                        origin.app.lower(),
                        canonical_entity_name(
                            origin.app,
                            origin.entity,
                        ),
                        origin.source_tool,
                        origin.entity_id,
                        normalize_resource_source_path(origin.source_path),
                        str(origin.value),
                    ): origin
                    for origin in all_value_origins
                }.values()
            )
            value_origins = [origin for origin in all_value_origins if origin_is_allowed(origin)]
            if not value_origins and canonical_value:
                value_origins = [
                    origin
                    for records in value_index.values()
                    for origin in records
                    if origin_is_allowed(origin)
                    and (
                        value_occurs_in_origin(
                            value,
                            origin,
                            semantic_type,
                        )
                        or (
                            bool(origin.container_key)
                            and value_occurs_in_origin(
                                value,
                                replace(
                                    origin,
                                    value=origin.container_key,
                                ),
                                semantic_type,
                            )
                        )
                    )
                ]
                all_value_origins.extend(value_origins)
            required_source_ids = {
                str(item)
                for item in raw_rule.get(
                    "required_sources",
                    [],
                )
                if str(item).strip()
            }
            all_required_source_ids.update(
                required_source_ids
            )
            required_identities = {
                (
                    str(source.get("app", "")).lower(),
                    canonical_entity_name(
                        str(source.get("app", "")),
                        str(source.get("entity", "")),
                    ),
                    tool_identity(
                        str(source.get("source_action", "")),
                        str(source.get("app", "")),
                    ),
                )
                for source_id, source in source_registry.items()
                if str(source_id) in required_source_ids
                and isinstance(source, Mapping)
            }
            if required_identities:
                matched_required_origins = [
                    origin
                    for records in value_index.values()
                    for origin in records
                    if (
                        origin.app.lower(),
                        canonical_entity_name(
                            origin.app,
                            origin.entity,
                        ),
                        tool_identity(
                            origin.source_tool,
                            origin.app,
                        ),
                    )
                    in required_identities
                    and origin_is_allowed(origin)
                    and (
                        value_occurs_in_origin(
                            value,
                            origin,
                            semantic_type,
                        )
                        or (
                            bool(origin.container_key)
                            and value_occurs_in_origin(
                                value,
                                replace(
                                    origin,
                                    value=origin.container_key,
                                ),
                                semantic_type,
                            )
                        )
                    )
                ]
                value_origins.extend(matched_required_origins)
                all_value_origins.extend(
                    matched_required_origins
                )
                for required_origin in matched_required_origins:
                    source_ids, _ambiguous = source_ids_for_origin(
                        required_origin
                    )
                    matched_required_source_ids.update(
                        source_ids
                    )
            if not value_origins:
                unresolved_value_count += 1
            origins.extend(value_origins)
        if not origins:
            continue
        origins = list(
            {
                (
                    origin.app.lower(),
                    canonical_entity_name(origin.app, origin.entity),
                    origin.source_tool,
                    origin.entity_id,
                    normalize_resource_source_path(origin.source_path),
                ): origin
                for origin in origins
            }.values()
        )
        matching_source_ids: set[str] = set()
        for origin in origins:
            source_ids, ambiguous = source_ids_for_origin(origin)
            if ambiguous or not source_ids:
                ambiguous_source_instance_count += 1
                continue
            matching_source_ids.update(source_ids)
        matching_source_ids_list = sorted(matching_source_ids)
        resolutions.append(
            {
                "parameter": str(parameter),
                "semantic_type": semantic_type,
                "status": (
                    "resolved"
                    if (
                        unresolved_value_count == 0
                        and ambiguous_value_count == 0
                        and ambiguous_source_instance_count == 0
                    )
                    else "incomplete"
                ),
                "generation_kind": "copy",
                "validation_mode": "structured",
                "source_refs": [
                    {
                        **(
                            {
                                "source_id": (
                                    matching_source_ids_list[0]
                                )
                            }
                            if len(origins) == 1
                            and len(matching_source_ids_list) == 1
                            else {}
                        ),
                        "app": origin.app,
                        "entity": origin.entity,
                        "source_action": origin.source_tool,
                        "entity_id": origin.entity_id,
                        "source_path": origin.source_path,
                        "source_activity_id": (
                            origin.source_activity_id
                        ),
                        **(
                            {
                                "plan_step_id": str(
                                    event_by_activity.get(
                                        str(
                                            origin.source_activity_id
                                            or ""
                                        ),
                                        {},
                                    ).get("plan_step_id", "")
                                    or ""
                                )
                            }
                            if event_by_activity.get(
                                str(origin.source_activity_id or ""),
                                {},
                            ).get("plan_step_id")
                            else {}
                        ),
                    }
                    for origin in origins
                ],
                "source_evidence": [
                    {
                        "app": origin.app,
                        "entity": origin.entity,
                        "source_action": origin.source_tool,
                        "entity_id": origin.entity_id,
                        "source_path": origin.source_path,
                        "source_activity_id": (
                            origin.source_activity_id
                        ),
                        "extracted_text": str(origin.value),
                        "confidentiality": origin.level,
                    }
                    for origin in origins
                ],
                "used_source_ids": matching_source_ids_list,
                "matched_required_sources": sorted(
                    matched_required_source_ids
                ),
                "unmatched_required_sources": sorted(
                    all_required_source_ids
                    - matched_required_source_ids
                ),
                "source_paths": sorted({normalize_resource_source_path(origin.source_path) for origin in origins}),
                "explanation": ("控制器通过数据流索引确认资源参数来自已授权的工具输出字段。"),
                "confidence": 1.0,
                "unresolved_value_count": unresolved_value_count,
                "ambiguous_value_count": ambiguous_value_count,
                "ambiguous_source_instance_count": (
                    ambiguous_source_instance_count
                ),
            }
        )
    return resolutions


def _plain_data(value: Any) -> Any:
    """Convert Pydantic and tuple containers into field-projectable data."""
    if hasattr(value, "model_dump"):
        return _plain_data(value.model_dump(mode="json"))
    if isinstance(value, Mapping):
        return {str(key): _plain_data(item) for key, item in value.items()}
    if isinstance(value, list | tuple | set):
        return [_plain_data(item) for item in value]
    return value


def validate_resource_access(
    contract: Mapping[str, Any] | None,
    event: Mapping[str, Any],
    *,
    source_registry: Mapping[str, Any] | None = None,
    user_instruction: str = "",
) -> list[str]:
    """Validate concrete selector arguments against the data_access grant."""
    if not isinstance(contract, Mapping):
        return ["data_access_unavailable"]
    inputs = event.get("inputs")
    inputs = inputs if isinstance(inputs, Mapping) else {}
    resolutions = {
        str(item.get("parameter", "")): item
        for item in event.get("parameter_resolutions", [])
        if isinstance(item, Mapping)
    }
    failures: list[str] = []
    resource_parameters = contract.get("resource_parameters", {})
    if not isinstance(resource_parameters, Mapping):
        resource_parameters = {}
    for parameter, raw_rule in resource_parameters.items():
        if not isinstance(raw_rule, Mapping):
            failures.append(f"invalid_resource_rule:{parameter}")
            continue
        values = _flatten_scalars(inputs.get(parameter))
        if not values:
            failures.append(f"resource_value_missing:{parameter}")
            continue
        mode = str(raw_rule.get("mode", "literal")).lower()
        semantic_type = str(raw_rule.get("semantic_type", "identifier"))
        if mode == "literal":
            allowed = {
                canonicalize_resource_value(item, semantic_type)
                for item in raw_rule.get("allowed_values", [])
                if item not in (None, "")
            }
            if (
                str(parameter).strip().casefold()
                in SEARCH_SELECTOR_PARAMETERS
            ):
                # A search term is a discovery selector, not the identity of
                # the record being accessed. The APP, entity and visible-field
                # grant still bound what the search is allowed to expose.
                continue
            unauthorized_values = [
                item
                for item in values
                if canonicalize_resource_value(
                    item,
                    semantic_type,
                )
                not in allowed
                and not value_occurs_in_trusted_text(
                    item,
                    user_instruction,
                    semantic_type,
                )
            ]
            if unauthorized_values:
                failures.append(f"resource_not_authorized:{parameter}")
            continue

        resolution = resolutions.get(str(parameter), {})
        source_refs = [item for item in resolution.get("source_refs", []) if isinstance(item, Mapping)]
        provenance_refs = [
            item
            for item in resolution.get("provenance_refs", [])
            if isinstance(item, Mapping)
            and str(item.get("source_path", "") or "").strip()
        ]
        if provenance_refs:
            # A generic binding resolver may identify the right APP/entity/
            # action before the resource resolver adds field precision. The
            # provenance refs are the authoritative instance-specific paths.
            source_refs = provenance_refs
        allowed_refs = [
            {
                "app": str(item.get("app", "")).lower(),
                "entity": canonical_entity_name(
                    str(item.get("app", "")),
                    str(item.get("entity", "")),
                ),
                "source_action": tool_identity(
                    str(item.get("source_action", "")),
                    str(
                        item.get(
                            "source_app",
                            item.get("app", ""),
                        )
                    ),
                ),
                "source_path": (
                    normalize_resource_source_path(str(item.get("source_path", "")))
                    if str(item.get("source_path", "")).strip()
                    else ""
                ),
            }
            for item in raw_rule.get("allowed_source_refs", [])
            if isinstance(item, Mapping)
        ]
        observed_refs = [
            {
                "app": str(
                    item.get(
                        "source_app",
                        item.get("app", ""),
                    )
                ).lower(),
                "entity": canonical_entity_name(
                    str(
                        item.get(
                            "source_app",
                            item.get("app", ""),
                        )
                    ),
                    str(
                        item.get(
                            "source_entity",
                            item.get("entity", ""),
                        )
                    ),
                ),
                "source_action": tool_identity(
                    str(
                        item.get(
                            "source_action",
                            item.get("tool", ""),
                        )
                    ),
                    str(
                        item.get(
                            "source_app",
                            item.get("app", ""),
                        )
                    ),
                ),
                "source_path": normalize_resource_source_path(
                    str(
                        item.get(
                            "source_path",
                            "$",
                        )
                    )
                ),
            }
            for item in source_refs
        ]

        def observed_is_allowed(observed: Mapping[str, str]) -> bool:
            return any(
                observed["app"] == allowed["app"]
                and observed["entity"] == allowed["entity"]
                and observed["source_action"] == allowed["source_action"]
                and (
                    not allowed["source_path"]
                    or _resource_path_matches(
                        observed["source_path"],
                        allowed["source_path"],
                    )
                )
                for allowed in allowed_refs
            )

        prompt_grounded = bool(user_instruction.strip()) and all(
            value_occurs_in_trusted_text(
                item,
                user_instruction,
                semantic_type,
            )
            for item in values
        )
        source_authorized = prompt_grounded or not (
            resolution.get("status") != "resolved"
            or int(resolution.get("unresolved_value_count", 0) or 0) > 0
            or int(resolution.get("ambiguous_value_count", 0) or 0) > 0
            or int(
                resolution.get(
                    "ambiguous_source_instance_count",
                    0,
                )
                or 0
            )
            > 0
            or not observed_refs
            or any(not observed_is_allowed(item) for item in observed_refs)
        )
        if not source_authorized:
            failures.append(f"resource_source_not_authorized:{parameter}")
        else:
            if prompt_grounded:
                # The immutable user instruction is a trusted source. When a
                # normalized selector is explicitly present there, it is
                # already grounded and need not also be copied verbatim from
                # one planned APP field.
                continue
            required = {str(item) for item in raw_rule.get("required_sources", []) if str(item).strip()}
            observed_source_ids = {str(item.get("source_id", "")) for item in source_refs if item.get("source_id")}
            observed_source_ids.update(str(item) for item in resolution.get("used_source_ids", []) if item)
            observed_source_ids.update(
                str(item.get("source_id", ""))
                for item in resolution.get("provenance_refs", [])
                if isinstance(item, Mapping) and item.get("source_id")
            )
            required_source_refs = {
                str(item.get("source_id", "")): item
                for item in raw_rule.get(
                    "required_source_refs",
                    [],
                )
                if isinstance(item, Mapping)
                and str(item.get("source_id", "")).strip()
            }

            def required_source_is_observed(
                source_id: str,
            ) -> bool:
                if source_id in observed_source_ids:
                    return True
                reference = required_source_refs.get(
                    source_id
                )
                if not isinstance(reference, Mapping) and isinstance(
                    source_registry,
                    Mapping,
                ):
                    reference = source_registry.get(source_id)
                if not isinstance(reference, Mapping):
                    return False
                expected_app = str(
                    reference.get("app", "")
                ).lower()
                expected_entity = canonical_entity_name(
                    expected_app,
                    str(reference.get("entity", "")),
                )
                expected_action = tool_identity(
                    str(reference.get("source_action", "")),
                    expected_app,
                )
                expected_path = normalize_resource_source_path(
                    str(reference.get("source_path", ""))
                )
                return any(
                    observed["app"] == expected_app
                    and observed["entity"] == expected_entity
                    and observed["source_action"]
                    == expected_action
                    and (
                        not expected_path
                        or _resource_path_matches(
                            observed["source_path"],
                            expected_path,
                        )
                    )
                    for observed in observed_refs
                )

            raw_required_groups = raw_rule.get(
                "required_source_groups",
                [],
            )
            if not isinstance(raw_required_groups, list):
                failures.append(
                    f"resource_required_source_group_invalid:{parameter}"
                )
                raw_required_groups = []
            required_groups: list[Mapping[str, Any]] = []
            invalid_group_ids: set[str] = set()
            for group_index, group in enumerate(raw_required_groups):
                if not isinstance(group, Mapping):
                    failures.append(
                        "resource_required_source_group_invalid:"
                        f"{parameter}:{group_index}"
                    )
                    continue
                group_id = str(
                    group.get("id") or f"group_{group_index}"
                )
                mode = str(group.get("mode", "all")).lower()
                if mode not in {"any", "all"}:
                    failures.append(
                        "resource_required_source_group_invalid_mode:"
                        f"{parameter}:{group_id}:{mode}"
                    )
                    invalid_group_ids.add(group_id)
                    continue
                group_ids = {
                    str(source_id)
                    for source_id in group.get(
                        "source_ids",
                        group.get("sources", []),
                    )
                    if str(source_id).strip()
                }
                if not group_ids:
                    failures.append(
                        "resource_required_source_group_invalid:"
                        f"{parameter}:{group_id}:empty"
                    )
                    invalid_group_ids.add(group_id)
                    continue
                if source_registry:
                    known_ids = {
                        str(item) for item in source_registry
                    }
                else:
                    known_ids = {
                        str(item.get("source_id"))
                        for item in group.get("source_refs", [])
                        if isinstance(item, Mapping)
                        and item.get("source_id")
                    } | {
                        str(item.get("source_id"))
                        for item in allowed_refs
                        if item.get("source_id")
                    }
                unknown_ids = group_ids - known_ids
                if unknown_ids:
                    failures.append(
                        "resource_required_source_group_invalid:"
                        f"{parameter}:{group_id}:unknown:"
                        f"{sorted(unknown_ids)}"
                    )
                    invalid_group_ids.add(group_id)
                    continue
                required_groups.append(group)
            required = required - {
                source_id
                for group in required_groups
                if str(group.get("mode", "")).lower() == "any"
                for source_id in group.get(
                    "source_ids",
                    group.get("sources", []),
                )
            }
            # During normal execution the plan synchronizer replaces
            # non-origin planner hints with the observed authorized source.
            # This fallback keeps direct contract validation from treating
            # such a hint as a hard requirement; explicit source instances
            # and groups remain mandatory.
            unmatched_without_explicit_ref = {
                str(source_id)
                for source_id in resolution.get(
                    "unmatched_required_sources",
                    [],
                )
                if str(source_id)
                and str(source_id) not in required_source_refs
            }
            required = required - unmatched_without_explicit_ref
            missing_required = {
                source_id
                for source_id in required
                if not required_source_is_observed(
                    source_id
                )
            }
            if missing_required:
                failures.append(
                    f"resource_required_source_missing:{parameter}"
                )
            for group in required_groups:
                group_id = str(group.get("id", ""))
                if group_id in invalid_group_ids:
                    continue
                group_ids = {
                    str(source_id)
                    for source_id in group.get(
                        "source_ids",
                        group.get("sources", []),
                    )
                    if str(source_id).strip()
                }
                matched = {
                    source_id
                    for source_id in group_ids
                    if required_source_is_observed(
                        source_id
                    )
                }
                satisfied = (
                    bool(matched)
                    if str(group.get("mode", "all")).lower() == "any"
                    else group_ids.issubset(matched)
                )
                if not satisfied:
                    failures.append(
                        "resource_required_source_group_missing:"
                        f"{parameter}:"
                        f"{group.get('id', '')}"
                    )
    return list(dict.fromkeys(failures))


def project_agent_exposure(
    result: Any,
    contract: Mapping[str, Any] | None,
    *,
    activity_id: str = "",
) -> tuple[Any, dict[str, Any]]:
    """Return only authorized output fields for Agent-visible context."""
    if not isinstance(contract, Mapping):
        return result, {
            "passed": False,
            "reason": "data_access_unavailable",
            "withheld_fields": [],
            "opaque_fields": [],
        }
    projection = contract.get("projection")
    if not isinstance(projection, Mapping):
        return result, {
            "passed": False,
            "reason": "data_access_projection_unavailable",
            "withheld_fields": [],
            "opaque_fields": [],
        }
    plain = _plain_data(result)
    max_exposure_level = str(contract.get("max_exposure_level", "internal")).lower()
    planned_max_exposure_level = max_exposure_level
    app = str(contract.get("app", ""))
    entity = str(contract.get("entity", ""))
    visible_patterns = {normalize_data_path(path) for path in contract.get("visible_fields", [])}
    analysis_patterns = {
        normalize_data_path(path)
        for path in contract.get("analysis_fields", [])
        if str(path).strip()
    }
    dynamic_mapping_policy_paths = [
        str(path)
        for path in contract.get(
            "dynamic_mapping_policy_paths",
            [],
        )
        if str(path).strip()
    ]
    contract_content_detection = contract.get("content_detection", True) is not False
    runtime_hidden: set[str] = set()
    inspected_policies: dict[str, dict[str, Any]] = {}
    sensitive_entities_by_path: dict[str, list[dict[str, Any]]] = {}

    def policy_for_exposure(path: str) -> dict[str, Any]:
        if not dynamic_mapping_policy_paths:
            policy = field_policy(app, entity, path)
            if not contract_content_detection:
                return {
                    **policy,
                    "content_detection": False,
                }
            return policy
        return combined_field_policy(
            app,
            entity,
            dynamic_mapping_policy_paths,
            content_detection=contract_content_detection,
        )

    def path_is_visible(path: str) -> bool:
        normalized = normalize_data_path(path)
        return any(
            normalized == pattern or normalized.startswith(f"{pattern}.") or normalized.startswith(f"{pattern}[")
            for pattern in visible_patterns
        )

    def path_is_analysis(path: str) -> bool:
        normalized = normalize_data_path(path)
        return any(
            normalized == pattern
            or normalized.startswith(f"{pattern}.")
            or normalized.startswith(f"{pattern}[")
            for pattern in analysis_patterns
        )

    sensitive_content_exposed: list[dict[str, Any]] = []
    detector_required = False

    def requires_content_detector(value: Any, path: str) -> bool:
        if not app or not entity or not path_is_visible(path):
            return False
        if isinstance(value, dict):
            return any(
                requires_content_detector(
                    child,
                    f"{path}.{key}",
                )
                for key, child in value.items()
            )
        if isinstance(value, list):
            return any(requires_content_detector(child, f"{path}[{index}]") for index, child in enumerate(value))
        if not isinstance(value, str):
            return False
        policy = policy_for_exposure(path)
        return policy_allows_span_detection(policy)

    detector_required = requires_content_detector(plain, "$")
    if detector_required:
        try:
            ensure_sensitivity_detector_ready()
        except Exception as exc:
            return result, {
                "passed": False,
                "reason": f"sensitivity_detector_unavailable:{exc}",
                "withheld_fields": [],
                "opaque_fields": [],
            }

    def permitted_for_inspection(path: str) -> bool:
        return path_is_visible(path)

    def inspect(value: Any, path: str) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                inspect(child, f"{path}.{key}")
            return
        if isinstance(value, list):
            for index, child in enumerate(value):
                inspect(child, f"{path}[{index}]")
            return
        if not app or not entity:
            return
        if not permitted_for_inspection(path):
            return
        base_policy = policy_for_exposure(path)
        policy = (
            base_policy
            if (
                not policy_allows_span_detection(base_policy)
                or _is_structured_scalar(value)
            )
            else elevate_policy_for_content(base_policy, value)
        )
        inspected_policies[path] = policy
        entities = [
            dict(item)
            for item in policy.get("gliner_entities", [])
            if isinstance(item, Mapping)
            and int(item.get("end", 0) or 0)
            > int(item.get("start", 0) or 0)
        ]
        if entities:
            sensitive_entities_by_path[path] = entities
        if CONFIDENTIALITY_LEVELS.get(
            str(policy.get("level", max_exposure_level)),
            3,
        ) > CONFIDENTIALITY_LEVELS.get(max_exposure_level, 0):
            sensitive_high_entities = [
                item
                for item in entities
                if CONFIDENTIALITY_LEVELS.get(
                    minimum_level_for_categories(
                        [str(item.get("category", ""))]
                    ),
                    3,
                )
                > CONFIDENTIALITY_LEVELS.get(max_exposure_level, 0)
            ]
            if not sensitive_high_entities and path_is_analysis(path):
                sensitive_content_exposed.append(
                    {
                        "path": path,
                        "start": 0,
                        "end": len(value),
                        "category": ",".join(
                            sorted(
                                str(category)
                                for category in policy.get(
                                    "categories",
                                    [],
                                )
                                if str(category)
                            )
                        ),
                        "level": str(
                            policy.get(
                                "level",
                                max_exposure_level,
                            )
                        ),
                        "score": float(
                            policy.get("score", 0.0) or 0.0
                        ),
                        "text": value,
                        "analysis_required": True,
                    }
                )
            elif not sensitive_high_entities:
                runtime_hidden.add(path)

    inspect(plain, "$")
    adjusted_projection = copy.deepcopy(dict(projection))
    hidden_fields = list(adjusted_projection.get("hidden_fields", []))
    for path in runtime_hidden:
        hidden_fields.append(path)
    adjusted_projection["hidden_fields"] = list(dict.fromkeys(hidden_fields))
    projected, hidden, opaque = project_with_plan(
        plain,
        adjusted_projection,
    )
    references: dict[str, dict[str, Any]] = {}
    sensitive_span_redactions: list[dict[str, Any]] = []

    def apply_sensitive_span_references(
        text: str,
        path: str,
    ) -> str:
        entities = sensitive_entities_by_path.get(path, [])
        if not entities:
            return text

        for entity_item in entities:
            start = max(
                0,
                min(len(text), int(entity_item.get("start", 0) or 0)),
            )
            end = max(
                start,
                min(
                    len(text),
                    int(entity_item.get("end", start) or start),
                ),
            )
            if end <= start:
                continue
            category = str(entity_item.get("category", "") or "")
            entity_level = minimum_level_for_categories([category])
            details = {
                "path": path,
                "start": start,
                "end": end,
                "category": category,
                "level": entity_level,
                "score": float(entity_item.get("score", 0.0) or 0.0),
                "text": text[start:end],
                "analysis_required": path_is_analysis(path),
            }
            if CONFIDENTIALITY_LEVELS.get(
                entity_level,
                3,
            ) <= CONFIDENTIALITY_LEVELS.get(
                max_exposure_level,
                0,
            ) or path_is_analysis(path):
                sensitive_content_exposed.append(details)

        candidates = [
            {
                **entity_item,
                "start": max(
                    0,
                    min(
                        len(text),
                        int(entity_item.get("start", 0) or 0),
                    ),
                ),
                "end": max(
                    0,
                    min(
                        len(text),
                        int(entity_item.get("end", 0) or 0),
                    ),
                ),
            }
            for entity_item in entities
        ]
        candidates = [
            entity
            for entity in candidates
            if int(entity["end"]) > int(entity["start"])
        ]
        candidates.sort(
            key=lambda item: (
                int(item["start"]),
                -int(item["end"]),
            )
        )
        grouped: list[dict[str, Any]] = []
        for entity_item in candidates:
            category = str(entity_item.get("category", "") or "")
            level = minimum_level_for_categories([category])
            if (
                CONFIDENTIALITY_LEVELS.get(level, 3)
                <= CONFIDENTIALITY_LEVELS.get(max_exposure_level, 0)
                or path_is_analysis(path)
            ):
                continue
            if grouped and int(entity_item["start"]) < int(grouped[-1]["end"]):
                grouped[-1]["end"] = max(
                    int(grouped[-1]["end"]),
                    int(entity_item["end"]),
                )
                grouped[-1]["categories"].add(category)
                grouped[-1]["score"] = max(
                    float(grouped[-1]["score"]),
                    float(entity_item.get("score", 0.0) or 0.0),
                )
            else:
                grouped.append(
                    {
                        "start": int(entity_item["start"]),
                        "end": int(entity_item["end"]),
                        "categories": {category},
                        "score": float(
                            entity_item.get("score", 0.0) or 0.0
                        ),
                    }
                )
        if not grouped:
            return text

        pieces: list[str] = []
        cursor = 0
        for span in grouped:
            start = int(span["start"])
            end = int(span["end"])
            if start < cursor:
                continue
            categories = sorted(
                category
                for category in span["categories"]
                if category
            )
            level = minimum_level_for_categories(categories)
            reference = (
                f"{SENSITIVE_REFERENCE_PREFIX}"
                f"{app}:{entity}:{activity_id}:{path}"
                f"#span:{start}-{end}]]"
            )
            value = text[start:end]
            source_policy = inspected_policies.get(
                path,
                policy_for_exposure(path),
            )
            references[reference] = {
                "value": value,
                "app": app,
                "entity": entity,
                "source_action": str(contract.get("source_action", "")),
                "source_path": path,
                "source_activity_id": activity_id,
                "start": start,
                "end": end,
                "span_start": start,
                "span_end": end,
                "confidentiality": level,
                "categories": categories,
                "span_detection": policy_allows_span_detection(
                    source_policy
                ),
            }
            sensitive_span_redactions.append(
                {
                    "path": path,
                    "start": start,
                    "end": end,
                    "category": ",".join(categories),
                    "level": level,
                    "score": float(span["score"]),
                    "controller_reference": reference,
                }
            )
            pieces.append(text[cursor:start])
            pieces.append(reference)
            cursor = end
        if not pieces:
            return text
        pieces.append(text[cursor:])
        return "".join(pieces)

    def semanticize(
        projected_value: Any,
        raw_value: Any,
        path: str,
    ) -> Any:
        is_hidden = isinstance(projected_value, str) and (
            projected_value == "[HIDDEN]" or projected_value.startswith("[HIDDEN:")
        )
        is_opaque = isinstance(projected_value, Mapping) and set(projected_value) == {"$ref"}
        if is_hidden or is_opaque:
            normalized_path = normalize_data_path(path)
            policy = inspected_policies.get(path)
            if policy is None:
                policy = inspected_policies.get(normalized_path)
            if policy is None:
                policy = policy_for_exposure(path)
            reference = f"{SENSITIVE_REFERENCE_PREFIX}{app}:{entity}:{activity_id}:{path}]]"
            references[reference] = {
                "value": copy.deepcopy(raw_value),
                "app": app,
                "entity": entity,
                "source_action": str(contract.get("source_action", "")),
                "source_path": path,
                "source_activity_id": activity_id,
                "confidentiality": str(policy.get("level", "secret")),
                "categories": list(policy.get("categories", [])),
                "span_detection": policy_allows_span_detection(
                    policy
                ),
            }
            return reference
        if (
            isinstance(projected_value, str)
            and path_is_visible(path)
            and path in sensitive_entities_by_path
        ):
            projected_value = apply_sensitive_span_references(
                projected_value,
                path,
            )
        if isinstance(projected_value, dict):
            raw_mapping = raw_value if isinstance(raw_value, Mapping) else {}
            return {
                key: semanticize(
                    child,
                    raw_mapping.get(key),
                    f"{path}.{key}",
                )
                for key, child in projected_value.items()
            }
        if isinstance(projected_value, list):
            raw_items = raw_value if isinstance(raw_value, list) else []
            return [
                semanticize(
                    child,
                    raw_items[index] if index < len(raw_items) else None,
                    f"{path}[{index}]",
                )
                for index, child in enumerate(projected_value)
            ]
        return projected_value

    projected_hidden_paths: set[str] = set()
    projected_opaque_paths: set[str] = set()

    def collect_projection_markers(
        value: Any,
        path: str,
    ) -> None:
        if isinstance(value, str) and value.startswith("[HIDDEN"):
            projected_hidden_paths.add(path)
            return
        if (
            isinstance(value, Mapping)
            and set(value) == {"$ref"}
        ):
            projected_opaque_paths.add(path)
            return
        if isinstance(value, Mapping):
            for key, child in value.items():
                collect_projection_markers(
                    child,
                    f"{path}.{key}",
                )
            return
        if isinstance(value, list):
            for index, child in enumerate(value):
                collect_projection_markers(
                    child,
                    f"{path}[{index}]",
                )

    collect_projection_markers(projected, "$")
    projected = semanticize(projected, plain, "$")
    user_hidden_values: list[dict[str, Any]] = []
    seen_hidden_values: set[tuple[str, str, str]] = set()

    def append_user_hidden_value(
        source_path: str,
        raw_value: Any,
        visibility: str,
        *,
        level: str = "",
        categories: Sequence[str] = (),
        reference: str = "",
    ) -> None:
        policy = inspected_policies.get(source_path)
        if policy is None:
            policy = policy_for_exposure(source_path)
        raw_value = copy.deepcopy(raw_value)
        actual_level = str(
            level
            or policy.get("level", "unknown")
            or "unknown"
        )
        actual_categories = list(
            categories
            or policy.get("categories", [])
            or []
        )
        try:
            value_key = json.dumps(
                raw_value,
                ensure_ascii=False,
                sort_keys=True,
                default=str,
            )
        except Exception:
            value_key = str(raw_value)
        dedupe_key = (
            normalize_data_path(source_path),
            actual_level,
            value_key,
        )
        if dedupe_key in seen_hidden_values:
            return
        seen_hidden_values.add(dedupe_key)
        user_hidden_values.append(
            {
                "field": source_path,
                "value": raw_value,
                "level": actual_level,
                "categories": actual_categories,
                "visibility": visibility,
                "reference": reference,
            }
        )

    for reference, details in references.items():
        source_path = str(details.get("source_path", "") or "")
        if not source_path:
            continue
        visibility = ""
        if any(
            _resource_path_matches(source_path, pattern)
            for pattern in hidden
        ) or any(
            _resource_path_matches(source_path, pattern)
            for pattern in projected_hidden_paths
        ):
            visibility = "hidden"
        elif any(
            _resource_path_matches(source_path, pattern)
            for pattern in opaque
        ) or any(
            _resource_path_matches(source_path, pattern)
            for pattern in projected_opaque_paths
        ):
            visibility = "reference"
        if not visibility:
            continue
        append_user_hidden_value(
            source_path,
            details.get("value"),
            visibility,
            level=str(
                details.get("confidentiality", "") or ""
            ),
            categories=list(
                details.get("categories", []) or []
            ),
            reference=reference,
        )

    def collect_omitted_values(
        raw_value: Any,
        projected_value: Any,
        path: str,
        present: bool,
    ) -> None:
        if not present:
            if isinstance(raw_value, Mapping):
                if raw_value:
                    for key, child in raw_value.items():
                        collect_omitted_values(
                            child,
                            None,
                            f"{path}.{key}",
                            False,
                        )
                else:
                    append_user_hidden_value(
                        path,
                        raw_value,
                        "hidden",
                    )
                return
            if isinstance(raw_value, list):
                if raw_value:
                    for index, child in enumerate(raw_value):
                        collect_omitted_values(
                            child,
                            None,
                            f"{path}[{index}]",
                            False,
                        )
                else:
                    append_user_hidden_value(
                        path,
                        raw_value,
                        "hidden",
                    )
                return
            append_user_hidden_value(
                path,
                raw_value,
                "hidden",
            )
            return
        if isinstance(raw_value, Mapping):
            projected_mapping = (
                projected_value
                if isinstance(projected_value, Mapping)
                else {}
            )
            for key, child in raw_value.items():
                collect_omitted_values(
                    child,
                    projected_mapping.get(key),
                    f"{path}.{key}",
                    key in projected_mapping,
                )
            return
        if isinstance(raw_value, list):
            projected_items = (
                projected_value
                if isinstance(projected_value, list)
                else []
            )
            for index, child in enumerate(raw_value):
                collect_omitted_values(
                    child,
                    (
                        projected_items[index]
                        if index < len(projected_items)
                        else None
                    ),
                    f"{path}[{index}]",
                    index < len(projected_items),
                )

    collect_omitted_values(plain, projected, "$", True)
    user_hidden_values.sort(
        key=lambda item: (
            0 if item["visibility"] == "hidden" else 1,
            str(item["field"]),
        )
    )
    exposed_levels = [
        str(item.get("level", "internal")).lower()
        for item in sensitive_content_exposed
    ]
    analysis_exposure_level = max(
        exposed_levels,
        key=lambda item: CONFIDENTIALITY_LEVELS.get(item, 3),
        default="",
    )
    if (
        analysis_exposure_level
        and CONFIDENTIALITY_LEVELS.get(
            analysis_exposure_level,
            3,
        )
        > CONFIDENTIALITY_LEVELS.get(max_exposure_level, 0)
    ):
        max_exposure_level = analysis_exposure_level
    return projected, {
        "passed": True,
        "reason": ("sensitive_field_withheld" if runtime_hidden else "field_scope_applied"),
        "visible_fields": list(contract.get("visible_fields", [])),
        "requested_visible_fields": list(contract.get("requested_visible_fields", [])),
        "dynamic_entity_map": bool(contract.get("dynamic_entity_map", False)),
        "dynamic_mapping_policy_paths": list(contract.get("dynamic_mapping_policy_paths", [])),
        "content_detection": (contract.get("content_detection", True) is not False),
        "max_exposure_level": max_exposure_level,
        "planned_max_exposure_level": planned_max_exposure_level,
        "analysis_fields": sorted(analysis_patterns),
        "analysis_exposure_level": analysis_exposure_level,
        "analysis_exposure_raised": (
            bool(analysis_exposure_level)
            and CONFIDENTIALITY_LEVELS.get(
                analysis_exposure_level,
                3,
            )
            > CONFIDENTIALITY_LEVELS.get(
                planned_max_exposure_level,
                0,
            )
        ),
        "runtime_hidden_sensitive_fields": sorted(runtime_hidden),
        "runtime_sensitive_policies": {
            path: copy.deepcopy(inspected_policies.get(path, {})) for path in sorted(runtime_hidden)
        },
        "sensitive_span_redactions": sensitive_span_redactions,
        "sensitive_content_exposed": sensitive_content_exposed,
        "reference_placeholders": sorted(references),
        "_sensitive_references": references,
        "user_hidden_values": user_hidden_values,
        "withheld_fields": hidden,
        "opaque_fields": opaque,
    }
