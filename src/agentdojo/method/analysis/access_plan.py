"""LLM-produced data access plans and deterministic field projection."""

from __future__ import annotations

import datetime
import re
import types
from enum import Enum
from typing import Any, Mapping, Union, get_args, get_origin

from pydantic import BaseModel

from ..modeling.policy import security_thresholds

ALLOWED_DECISIONS = {
    "ALLOW_OBJECT",
    "PROJECT",
    "OPAQUE_ONLY",
    "HIDE_ALL",
}

LOW_CONFIDENCE_THRESHOLD = float(
    security_thresholds().get("field_plan_min_confidence", 0.55)
)


def semantic_type_for_annotation(annotation: Any) -> str:
    """Return a generic controller normalization type for a field."""
    if annotation is datetime.datetime:
        return "datetime"
    if annotation is datetime.date:
        return "date"
    if annotation in {int, float}:
        return "number"
    return ""


def schema_for_type(annotation: Any) -> dict[str, Any]:
    """Convert a Python return annotation into a planner-friendly field schema."""
    if annotation is None:
        return {"type": "unknown"}

    origin = get_origin(annotation)
    args = get_args(annotation)

    if origin in (Union, types.UnionType):
        candidates = [item for item in args if item is not type(None)]
        if len(candidates) == 1:
            return schema_for_type(candidates[0])
        return {
            "type": "union",
            "variants": [schema_for_type(item) for item in candidates],
        }

    if origin in (list, tuple, set):
        item_type = args[0] if args else str
        return {"type": "array", "items": schema_for_type(item_type)}

    if origin is dict:
        value_type = args[1] if len(args) > 1 else str
        return {
            "type": "object",
            "dynamic": True,
            "value_schema": schema_for_type(value_type),
        }

    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        fields = {}
        for name, field in annotation.model_fields.items():
            item = {
                "type_schema": schema_for_type(field.annotation),
                "description": field.description or "",
                "required": bool(field.is_required()),
            }
            semantic_type = semantic_type_for_annotation(field.annotation)
            if semantic_type:
                item["semantic_type"] = semantic_type
            if not item["required"]:
                try:
                    default = field.get_default(call_default_factory=True)
                    item["default"] = (
                        default
                        if isinstance(
                            default,
                            (str, int, float, bool, type(None)),
                        )
                        else str(default)
                    )
                except Exception:
                    item["default"] = None
            fields[name] = item
        return {
            "type": "object",
            "model": annotation.__name__,
            "fields": fields,
        }

    if isinstance(annotation, type) and issubclass(annotation, Enum):
        return {
            "type": "enum",
            "semantic_type": "enum",
            "variants": [item.value for item in annotation],
        }

    type_name = getattr(annotation, "__name__", str(annotation))
    return {"type": type_name}


def schema_paths(schema: Mapping[str, Any], prefix: str = "$") -> list[str]:
    """Enumerate all concrete field paths represented by a type schema."""
    schema_type = schema.get("type")
    paths = [prefix]
    if schema_type == "array":
        paths.extend(
            schema_paths(
                schema.get("items") or {},
                f"{prefix}[*]",
            )
        )
    elif schema_type == "object" and schema.get("fields"):
        for name, child in schema["fields"].items():
            child_schema = child.get("type_schema", child)
            paths.extend(
                schema_paths(
                    child_schema,
                    f"{prefix}.{name}",
                )
            )
    return list(dict.fromkeys(paths))


def schema_field_names(schema: Mapping[str, Any]) -> set[str]:
    """Return statically declared fields at the top record level.

    Nested dictionaries may be dynamically keyed, so nested raw keys are never
    admitted to privileged context based on a flat name allow-set.
    """
    current: Mapping[str, Any] = schema
    items = current.get("items")
    if isinstance(items, Mapping):
        current = items
    fields = current.get("fields")
    if not isinstance(fields, Mapping):
        return set()
    return {str(name) for name in fields}


def _normalise_path(path: str, schema: Mapping[str, Any]) -> str:
    value = str(path or "").strip()
    if not value:
        return ""
    value = value.replace("[]", "[*]")
    value = re.sub(r"\[[0-9]+\]", "[*]", value)
    if value.startswith("$."):
        return value
    if value.startswith("$"):
        return value
    if value.startswith("."):
        return f"${value}"
    root = "$[*]" if schema.get("type") == "array" else "$"
    return f"{root}.{value}"


def _plan_paths(items: Any, schema: Mapping[str, Any]) -> list[str]:
    if not isinstance(items, list):
        return []
    result = []
    for item in items:
        if isinstance(item, Mapping):
            raw_path = item.get("path")
        else:
            raw_path = item
        path = _normalise_path(str(raw_path or ""), schema)
        if path:
            result.append(path)
    return list(dict.fromkeys(result))


def validate_access_plan(
    plan: Mapping[str, Any],
    schema: Mapping[str, Any],
    *,
    task_data_plan: Mapping[str, Any] | None = None,
) -> tuple[dict[str, Any], list[str]]:
    """Validate and normalise a planner result against the output schema."""
    warnings: list[str] = []
    known_paths = set(schema_paths(schema))
    decision = str(plan.get("decision", "PROJECT")).upper()
    if decision not in ALLOWED_DECISIONS:
        warnings.append(f"unknown_decision:{decision}")
        decision = "PROJECT"

    visible = _plan_paths(plan.get("visible_fields", []), schema)
    hidden = _plan_paths(plan.get("hidden_fields", []), schema)
    opaque = _plan_paths(plan.get("opaque_fields", []), schema)

    def valid(path: str) -> bool:
        return path == "$" or path in known_paths

    for label, paths in (
        ("visible", visible),
        ("hidden", hidden),
        ("opaque", opaque),
    ):
        invalid = [path for path in paths if not valid(path)]
        if invalid:
            warnings.append(f"invalid_{label}_paths:{invalid}")

    visible = [path for path in visible if valid(path)]
    hidden = [path for path in hidden if valid(path)]
    opaque = [path for path in opaque if valid(path)]

    if decision == "PROJECT" and not visible:
        # A projection plan with no valid visible field would hide everything.
        # Treat it as an explicit safe minimum instead of silently exposing data.
        warnings.append("project_without_visible_fields")

    subgoal_id = str(plan.get("subgoal_id", "") or "")
    confidence = plan.get("confidence")
    try:
        confidence_value = (
            float(confidence) if confidence is not None else None
        )
    except (TypeError, ValueError):
        confidence_value = None
        warnings.append("invalid_confidence")

    if task_data_plan is not None:
        valid_subgoals = {
            str(item.get("id"))
            for item in task_data_plan.get("subgoals", [])
            if isinstance(item, Mapping) and item.get("id")
        }
        if not subgoal_id or subgoal_id not in valid_subgoals:
            warnings.append(f"invalid_subgoal_id:{subgoal_id or '<missing>'}")
            decision = "HIDE_ALL"
            visible = []
            hidden = []
            opaque = []
        elif confidence_value is None:
            warnings.append("missing_confidence_opaque_only")
            decision = "OPAQUE_ONLY"
            opaque = list(visible) or ["$"]
            visible = []
        elif (
            confidence_value is not None
            and confidence_value < LOW_CONFIDENCE_THRESHOLD
        ):
            warnings.append("low_confidence_opaque_only")
            decision = "OPAQUE_ONLY"
            opaque = list(visible) or ["$"]
            visible = []

    validated = {
        "decision": decision,
        "visible_fields": visible,
        "hidden_fields": hidden,
        "opaque_fields": opaque,
        "subgoal_id": subgoal_id,
        "reason": str(plan.get("reason", "")),
        "confidence": confidence_value,
        "planner": str(plan.get("planner", "llm")),
        "warnings": warnings,
    }
    return validated, warnings


def _actual_to_plan_path(path: str) -> str:
    value = str(path or "$")
    if not value.startswith("$"):
        value = f"${value}"
    value = re.sub(r"\[[0-9]+\]", "[*]", value)
    return re.sub(
        r"\.([^.\[]+)",
        lambda match: "."
        + re.sub(
            r"[^a-zA-Z0-9_*]+",
            "_",
            match.group(1).strip(),
        ).lower(),
        value,
    )


def _is_descendant(path: str, parent: str) -> bool:
    return path == parent or path.startswith(f"{parent}.") or path.startswith(
        f"{parent}["
    )


def actual_path_for_projection(path: str) -> str:
    """Convert a data path to the ``$``-rooted plan representation."""
    value = str(path or "")
    if not value:
        return "$"
    if value.startswith("$"):
        return _actual_to_plan_path(value)
    return _actual_to_plan_path(f"${value}")


def classify_projection_path(
    path: str,
    plan: Mapping[str, Any] | None,
) -> str:
    """Classify one concrete data path as visible, opaque or withheld.

    The order is significant: explicit hidden paths override opaque and
    visible paths, and opaque paths override visible parents. This gives the
    planner a deterministic way to expose a record while withholding one of
    its sensitive fields.
    """
    if not isinstance(plan, Mapping):
        return "visible"
    projection_path = actual_path_for_projection(path)
    hidden = {
        str(item) for item in plan.get("hidden_fields", []) if item
    }
    opaque = {
        str(item) for item in plan.get("opaque_fields", []) if item
    }
    visible = {
        str(item) for item in plan.get("visible_fields", []) if item
    }
    decision = str(plan.get("decision", "PROJECT")).upper()

    if projection_path == "$" or any(
        _is_descendant(projection_path, ref) for ref in hidden
    ):
        return "withheld"
    if any(
        _is_descendant(projection_path, ref) for ref in opaque
    ):
        return "opaque"
    if decision == "HIDE_ALL":
        return "withheld"
    if decision == "ALLOW_OBJECT":
        return "visible"
    if decision == "OPAQUE_ONLY":
        return "withheld"
    if any(
        _is_descendant(projection_path, ref)
        or _is_descendant(ref, projection_path)
        for ref in visible
    ):
        return "visible"
    return "withheld"


def project_with_plan(
    value: Any,
    plan: Mapping[str, Any],
    *,
    include_opaque_values: bool = False,
) -> tuple[Any, list[str], list[str]]:
    """Apply a validated plan without any model-generated transformation.

    ``include_opaque_values`` is reserved for the isolated analysis boundary.
    It keeps opaque field values available to the no-tool Reader so it can
    derive task facts, while the normal projection still returns only a
    reference. Hidden fields remain absent in both modes.
    """
    decision = str(plan.get("decision", "PROJECT"))
    hidden = set(plan.get("hidden_fields", []))
    opaque = set(plan.get("opaque_fields", []))
    if decision == "ALLOW_OBJECT" and not hidden and not opaque:
        return value, [], []
    if decision == "HIDE_ALL":
        return "[HIDDEN]", ["$"], []
    if decision == "OPAQUE_ONLY" and not include_opaque_values:
        if not opaque:
            return {"$ref": "$"}, [], ["$"]
        visible: set[str] = set()
    elif decision == "ALLOW_OBJECT":
        visible = {"$"}
    else:
        visible = set(plan.get("visible_fields", []))
    if "$" in opaque:
        return {"$ref": "$"}, [], ["$"]
    if "$" in hidden:
        return "[HIDDEN]", ["$"], []

    hidden_paths: list[str] = []
    opaque_paths: list[str] = []

    def matches_hidden(actual_path: str, plan_path: str) -> bool:
        return any(
            actual_path == ref
            or _is_descendant(actual_path, ref)
            or _is_descendant(plan_path, ref)
            for ref in hidden
        )

    def walk(item: Any, path: str, *, in_object: bool = False) -> Any:
        plan_path = _actual_to_plan_path(path)
        if plan_path != "$" and matches_hidden(path, plan_path):
            hidden_paths.append(path)
            return "[HIDDEN]"
        if any(_is_descendant(plan_path, ref) for ref in opaque):
            opaque_paths.append(path)
            return item if include_opaque_values else {"$ref": path}

        if isinstance(item, dict):
            projected = {}
            for key, child in item.items():
                child_path = f"{path}.{key}"
                child_plan_path = _actual_to_plan_path(child_path)
                explicitly_hidden = matches_hidden(
                    child_path,
                    child_plan_path,
                )
                explicitly_visible = any(
                    _is_descendant(child_plan_path, ref)
                    or _is_descendant(ref, child_plan_path)
                    for ref in visible
                )
                should_visit_child = explicitly_visible or any(
                    ref.startswith(f"{child_plan_path}.")
                    or ref.startswith(f"{child_plan_path}[")
                    for ref in visible
                )
                if decision == "HIDE_ALL":
                    projected[key] = "[HIDDEN]"
                    hidden_paths.append(child_path)
                elif explicitly_hidden:
                    projected[key] = f"[HIDDEN:{key}]"
                    hidden_paths.append(child_path)
                elif decision == "OPAQUE_ONLY":
                    if include_opaque_values and any(
                        _is_descendant(child_plan_path, ref)
                        for ref in opaque
                    ):
                        projected[key] = walk(child, child_path)
                    else:
                        projected[key] = f"[HIDDEN:{key}]"
                        hidden_paths.append(child_path)
                elif explicitly_visible:
                    projected[key] = walk(child, child_path)
                elif should_visit_child:
                    projected[key] = walk(child, child_path)
                elif child_plan_path in opaque:
                    projected[key] = (
                        walk(child, child_path)
                        if include_opaque_values
                        else {"$ref": child_path}
                    )
                    opaque_paths.append(child_path)
                else:
                    projected[key] = f"[HIDDEN:{key}]"
                    hidden_paths.append(child_path)
            return projected

        if isinstance(item, list):
            return [
                walk(child, f"{path}[{index}]")
                for index, child in enumerate(item)
            ]
        scalar_visible = (
            "$" in visible
            or any(
                _is_descendant(plan_path, ref)
                or _is_descendant(ref, plan_path)
                for ref in visible
            )
        )
        if not scalar_visible:
            hidden_paths.append(path)
            return "[HIDDEN]"
        return item

    return walk(value, "$"), hidden_paths, opaque_paths


def parse_plan_json(text: str) -> dict[str, Any]:
    """Extract the first JSON object from a model response."""
    import json

    stripped = str(text or "").strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```(?:json)?\s*", "", stripped)
        stripped = re.sub(r"\s*```$", "", stripped)
    start = stripped.find("{")
    end = stripped.rfind("}")
    if start < 0 or end < start:
        raise ValueError("Planner response contains no JSON object")
    value = json.loads(stripped[start : end + 1])
    if not isinstance(value, dict):
        raise ValueError("Planner JSON must be an object")
    return value
