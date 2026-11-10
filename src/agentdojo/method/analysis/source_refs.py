"""Canonical identity rules for controller-owned data source references."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from ..modeling.data_sensitivity import canonical_entity_name
from ..modeling.policy import tool_identity
from .access_plan import schema_paths


def normalize_source_path(path: Any) -> str:
    """Normalize concrete array indexes to the wildcard evidence path."""
    value = str(path or "").strip() or "$"
    value = value.replace("[]", "[*]")
    return re.sub(r"\[[0-9]+\]", "[*]", value)


def source_ref_path_matches(actual: Any, expected: Any) -> bool:
    return normalize_source_path(actual) == normalize_source_path(expected)


def canonicalize_schema_path(
    path: Any,
    output_schema: Mapping[str, Any] | None,
) -> str:
    """Map planner path spellings onto the actual tool output structure."""
    scalar_types = {
        "str",
        "string",
        "int",
        "integer",
        "float",
        "number",
        "bool",
        "boolean",
        "null",
        "none",
    }

    def schema_type_at(
        source_schema: Mapping[str, Any],
        source_path: str,
    ) -> str:
        current: Mapping[str, Any] = source_schema
        for match in re.finditer(r"\[\*\]|\.([^.\[\]]+)", source_path):
            if match.group(0) == "[*]":
                if str(current.get("type", "")).lower() != "array":
                    return ""
                items = current.get("items")
                if not isinstance(items, Mapping):
                    return ""
                current = items
                continue
            if str(current.get("type", "")).lower() != "object":
                return ""
            fields = current.get("fields")
            if not isinstance(fields, Mapping):
                return ""
            child = fields.get(str(match.group(1)))
            if not isinstance(child, Mapping):
                return ""
            nested_schema = child.get("type_schema", child)
            if not isinstance(nested_schema, Mapping):
                return ""
            current = nested_schema
        return str(current.get("type", "")).lower()

    normalized = normalize_source_path(path)
    if not isinstance(output_schema, Mapping):
        return normalized
    known_paths = {
        normalize_source_path(item)
        for item in schema_paths(output_schema)
    }
    if normalized in known_paths:
        return normalized

    candidate = normalized
    while "." in candidate:
        parent = candidate.rsplit(".", 1)[0]
        if schema_type_at(output_schema, parent) in scalar_types:
            # Scalar containers have no object field corresponding to a
            # planner-supplied suffix. The useful value is the scalar item.
            return parent
        break

    schema_type = str(output_schema.get("type", ""))
    if normalized not in {"$", "$[*]"} and (
        schema_type not in {"array", "object", "union", "unknown", ""}
        or (schema_type == "object" and output_schema.get("dynamic") is True)
    ):
        return "$"

    candidates: list[str] = []
    if not normalized.startswith("$"):
        candidates.append(f"$[*].{normalized.lstrip('.')}")
        candidates.append(f"$.{normalized.lstrip('.')}")
    elif normalized.startswith("$.") and schema_type == "array":
        candidates.append(f"$[*]{normalized[1:]}")
    elif normalized in {"$", "$[*]"}:
        candidates.append("$[*]")
    for candidate in candidates:
        if candidate in known_paths:
            return candidate
    return normalized


def source_ref_identity(
    source_ref: Mapping[str, Any],
    *,
    include_path: bool = False,
) -> tuple[str, ...]:
    """Return the logical APP/entity/tool identity of a source reference."""
    app = str(source_ref.get("app", "") or "").strip().lower()
    entity = canonical_entity_name(
        app,
        str(source_ref.get("entity", "") or "").strip(),
    )
    action = tool_identity(
        str(
            source_ref.get("source_action")
            or source_ref.get("source_tool")
            or ""
        ),
        app,
    )
    result: tuple[str, ...] = (app, entity, action)
    if include_path:
        raw_path = str(
            source_ref.get("source_path", "") or ""
        ).strip()
        result += (
            normalize_source_path(raw_path) if raw_path else "",
        )
    return result


def source_ref_instance_key(
    source_ref: Mapping[str, Any],
) -> tuple[str, ...]:
    """Return a stable key including the concrete producer instance."""
    return (
        *source_ref_identity(source_ref, include_path=True),
        str(
            source_ref.get("source_id")
            or source_ref.get("id")
            or ""
        ),
        str(source_ref.get("producer_step", "") or ""),
        str(source_ref.get("source_activity_id", "") or ""),
        str(
            source_ref.get("source_tool_call_id")
            or source_ref.get("tool_call_id")
            or ""
        ),
    )


def source_refs_match(
    actual: Mapping[str, Any],
    expected: Mapping[str, Any],
    *,
    include_instance: bool = False,
) -> bool:
    """Compare references using canonical entity/tool/path semantics.

    Empty optional fields on ``expected`` act as scopes, while populated fields
    must match exactly after canonicalization.
    """
    actual_app = str(actual.get("app", "") or "").strip().lower()
    expected_app = str(expected.get("app", "") or "").strip().lower()
    if expected_app and actual_app != expected_app:
        return False
    if expected.get("entity"):
        if canonical_entity_name(
            actual_app,
            str(actual.get("entity", "") or ""),
        ) != canonical_entity_name(
            expected_app,
            str(expected.get("entity", "") or ""),
        ):
            return False
    expected_action = str(
        expected.get("source_action")
        or expected.get("source_tool")
        or ""
    )
    if expected_action and source_ref_identity(
        actual
    )[2] != source_ref_identity(expected)[2]:
        return False
    expected_path = str(expected.get("source_path", "") or "").strip()
    if expected_path and not source_ref_path_matches(
        actual.get("source_path", ""),
        expected_path,
    ):
        return False
    if include_instance:
        for key in ("source_id", "producer_step"):
            expected_value = str(expected.get(key, "") or "")
            actual_value = str(actual.get(key, "") or "")
            if expected_value and actual_value != expected_value:
                return False
    return True
