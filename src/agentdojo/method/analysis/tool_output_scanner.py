"""Ring 1 field-aware tool-output scanning and chunk quarantine."""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass, field
from typing import Any, Mapping

from ..modeling.labels import make_injection
from .injection_scanner import (
    INDIRECT_INJECTION_PLACEHOLDER,
    InjectionScanResult,
    InjectionScanner,
)

REDACTION_PLACEHOLDER = INDIRECT_INJECTION_PLACEHOLDER
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}$"
)
_DATETIME_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}(?:[T\s]\d{2}:\d{2}(?::\d{2})?)?$"
)
_MACHINE_IDENTIFIER_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9_.:/+-]*$"
)
MACHINE_FIELD_TYPES = {
    "enum",
    "bool",
    "int",
    "float",
    "date",
    "datetime",
}


def _normalise_scan_path(path: str) -> str:
    return re.sub(r"\[\d+\]", "[*]", str(path or "$"))


def _machine_field_paths(
    schema: Mapping[str, Any],
    prefix: str = "$",
) -> set[str]:
    result: set[str] = set()
    schema_type = str(schema.get("type", ""))
    semantic_type = str(schema.get("semantic_type", ""))
    if (
        schema_type in MACHINE_FIELD_TYPES
        or semantic_type in MACHINE_FIELD_TYPES
    ):
        result.add(_normalise_scan_path(prefix))
    if schema_type == "array":
        items = schema.get("items")
        if isinstance(items, Mapping):
            result.update(
                _machine_field_paths(items, f"{prefix}[*]")
            )
    elif schema_type == "object":
        fields = schema.get("fields")
        if isinstance(fields, Mapping):
            for field_name, field_schema in fields.items():
                if not isinstance(field_schema, Mapping):
                    continue
                value_schema = field_schema.get("type_schema")
                if isinstance(value_schema, Mapping):
                    result.update(
                        _machine_field_paths(
                            value_schema,
                            f"{prefix}.{field_name}",
                        )
                    )
    return result


@dataclass
class ToolOutputScan:
    sanitized_value: Any
    source_flagged: bool = False
    max_score: float = 0.0
    detector: str = ""
    available: bool = True
    incomplete: bool = False
    field_statuses: dict[str, str] = field(default_factory=dict)
    flagged_fields: list[str] = field(default_factory=list)
    quarantined_fields: list[str] = field(default_factory=list)
    risky_entities: list[str] = field(default_factory=list)
    unscanned_fields: list[str] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)
    chunk_evidence: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return bool(self.quarantined_fields)

    def information_flow(self) -> dict[str, Any]:
        return make_injection(
            source_flagged=bool(
                self.risky_entities or self.quarantined_fields
            ),
            max_score=self.max_score,
            detector=self.detector,
            field_statuses=self.field_statuses,
            evidence_refs=self.evidence_refs,
            available=self.available,
            flagged_fields=self.flagged_fields,
            quarantined_fields=self.quarantined_fields,
            unscanned_fields=self.unscanned_fields,
            risky_entities=self.risky_entities,
            incomplete=self.incomplete,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_flagged": self.source_flagged,
            "max_score": round(self.max_score, 6),
            "detector": self.detector,
            "available": self.available,
            "incomplete": self.incomplete,
            "field_statuses": dict(self.field_statuses),
            "flagged_fields": list(self.flagged_fields),
            "quarantined_fields": list(self.quarantined_fields),
            "risky_entities": list(self.risky_entities),
            "unscanned_fields": list(self.unscanned_fields),
            "evidence_refs": list(self.evidence_refs),
            "chunk_evidence": list(self.chunk_evidence),
            "errors": list(self.errors),
        }


def _jsonable(value: Any) -> Any:
    if isinstance(value, BaseException):
        return str(value)
    if hasattr(value, "model_dump"):
        return _jsonable(value.model_dump(mode="python"))
    if isinstance(value, dict):
        return {str(key): _jsonable(child) for key, child in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(child) for child in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _should_scan(text: str) -> bool:
    stripped = text.strip()
    if any(
        pattern.fullmatch(stripped)
        for pattern in (_EMAIL_RE, _UUID_RE, _DATETIME_RE)
    ):
        return False
    if (
        _MACHINE_IDENTIFIER_RE.fullmatch(stripped)
        and not any(character.isspace() for character in stripped)
        and any(character in "_.:/+-" for character in stripped)
        and any(character.isdigit() for character in stripped)
    ):
        return False
    return any(character.isalpha() for character in stripped)


def _redact_chunks(text: str, scan: InjectionScanResult) -> str:
    chunks = sorted(scan.chunks, key=lambda item: (item.start, item.end))
    if not chunks:
        return text
    parts: list[str] = []
    cursor = 0
    for chunk in chunks:
        start = max(cursor, min(len(text), int(chunk.start)))
        end = max(start, min(len(text), int(chunk.end)))
        if start > cursor:
            parts.append(text[cursor:start])
        if parts and not parts[-1].endswith((" ", "\n", "\r", "\t")):
            parts.append(" ")
        parts.append(REDACTION_PLACEHOLDER)
        if end < len(text) and not text[end].isspace():
            parts.append(" ")
        cursor = end
    if cursor < len(text):
        parts.append(text[cursor:])
    return "".join(parts)


def _direct_entity_path(path: str) -> str:
    """Return the concrete APP entity root containing a flagged field."""
    value = str(path or "$")
    match = re.match(
        r"^(\$(?:\.[A-Za-z0-9_]+)?\[\d+\])",
        value,
    )
    return match.group(1) if match else "$"


def scan_tool_output(
    value: Any,
    *,
    scanner: InjectionScanner,
    tool_name: str = "",
    schema: Mapping[str, Any] | None = None,
) -> ToolOutputScan:
    """Scan string leaves in one model batch and replace suspicious chunks."""
    result = ToolOutputScan(sanitized_value=copy.deepcopy(value))
    jsonable = _jsonable(value)
    pending: list[tuple[str, str]] = []
    machine_paths = (
        _machine_field_paths(schema)
        if isinstance(schema, Mapping)
        else set()
    )

    def collect(item: Any, path: str) -> None:
        if isinstance(item, str):
            if _normalise_scan_path(path) in machine_paths:
                result.field_statuses[path] = "not_applicable"
            elif _should_scan(item):
                pending.append((path, item))
            else:
                result.field_statuses[path] = "not_applicable"
        elif isinstance(item, dict):
            for key, child in item.items():
                collect(child, f"{path}.{key}" if path else str(key))
        elif isinstance(item, list):
            for index, child in enumerate(item):
                collect(child, f"{path}[{index}]")

    collect(jsonable, "$")
    scans = scanner.scan_many([text for _path, text in pending])
    scan_by_path = {
        path: scan for (path, _text), scan in zip(pending, scans)
    }

    def transform(item: Any, path: str) -> Any:
        if isinstance(item, str):
            scan = scan_by_path.get(path)
            if scan is None:
                return item
            result.detector = scan.detector
            result.max_score = max(result.max_score, scan.score)
            if not scan.available:
                result.available = False
                result.incomplete = True
                result.source_flagged = True
                result.field_statuses[path] = "quarantined_unavailable"
                result.flagged_fields.append(path)
                result.quarantined_fields.append(path)
                result.unscanned_fields.append(path)
                if scan.error:
                    result.errors.append(scan.error)
                return REDACTION_PLACEHOLDER
            if scan.truncated:
                result.incomplete = True
                result.source_flagged = True
                result.field_statuses[path] = "quarantined_incomplete"
                result.flagged_fields.append(path)
                result.quarantined_fields.append(path)
                result.unscanned_fields.append(path)
                return REDACTION_PLACEHOLDER
            if not scan.suspected:
                result.field_statuses[path] = "scanned_clean"
                return item

            result.source_flagged = True
            result.field_statuses[path] = "quarantined"
            result.flagged_fields.append(path)
            result.quarantined_fields.append(path)
            for chunk in scan.chunks:
                evidence_ref = (
                    f"{tool_name}:{path}:chunk:{chunk.index}"
                    if tool_name
                    else f"{path}:chunk:{chunk.index}"
                )
                result.evidence_refs.append(evidence_ref)
                result.chunk_evidence.append(
                    {
                        "field": path,
                        "chunk_index": chunk.index,
                        "start": chunk.start,
                        "end": chunk.end,
                        "score": round(chunk.score, 6),
                        "evidence_ref": evidence_ref,
                    }
                )
            return _redact_chunks(item, scan)
        if isinstance(item, dict):
            return {
                key: transform(child, f"{path}.{key}" if path else str(key))
                for key, child in item.items()
            }
        if isinstance(item, list):
            return [
                transform(child, f"{path}[{index}]")
                for index, child in enumerate(item)
            ]
        return item

    result.sanitized_value = transform(jsonable, "$")
    result.flagged_fields = list(dict.fromkeys(result.flagged_fields))
    result.quarantined_fields = list(
        dict.fromkeys(result.quarantined_fields)
    )
    result.risky_entities = list(
        dict.fromkeys(
            _direct_entity_path(path)
            for path in result.quarantined_fields
        )
    )
    result.unscanned_fields = list(dict.fromkeys(result.unscanned_fields))
    result.evidence_refs = list(dict.fromkeys(result.evidence_refs))
    return result
