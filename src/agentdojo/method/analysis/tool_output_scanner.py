"""Ring 1 field-aware tool-output scanning and chunk quarantine."""

from __future__ import annotations

import copy
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from ..modeling.data_sensitivity import field_policy
from ..modeling.labels import make_injection
from .data_access import SENSITIVE_REFERENCE_PATTERN
from .injection_metrics import merge_quarantine_metrics
from .injection_scanner import (
    _INJECTION_CONTROL_MARKER_RE,
    INDIRECT_INJECTION_PLACEHOLDER,
    InjectionScanner,
    redact_injection_chunks_with_metrics,
)

REDACTION_PLACEHOLDER = INDIRECT_INJECTION_PLACEHOLDER
MACHINE_FIELD_TYPES = {
    "enum",
    "bool",
    "int",
    "float",
    "number",
    "date",
    "datetime",
    "identifier",
    "email",
    "phone",
    "url",
    "uuid",
}
NON_LANGUAGE_CATEGORIES = {
    "email",
    "phone",
    "iban",
    "slack_channel",
    "slack_user",
    "file_sharing_permission",
    "financial_amount",
    "government_identifier",
    "passport_number",
    "credit_card",
    "personal_name",
    "address",
    "location",
    "calendar",
}


def _should_scan(text: Any) -> bool:
    """Return whether a string leaf can carry natural-language instructions."""
    if not isinstance(text, str) or not text.strip():
        return False
    value = text.strip()
    if not re.search(r"[A-Za-z\u4e00-\u9fff]", value):
        return False
    if re.search(
        r"ignore[_ -]+(?:all[_ -]+)?previous|"
        r"忽略(?:之前|以上|所有)",
        value,
        re.IGNORECASE,
    ):
        return True
    if re.search(r"https?://|www\.", value, re.IGNORECASE):
        return True
    cjk_characters = len(re.findall(r"[\u4e00-\u9fff]", value))
    if not re.search(r"\s", value):
        # A single token or a structured one-line value is metadata unless
        # it contains enough CJK text or one of the control phrases above.
        return cjk_characters >= 4
    machine_identifier = re.fullmatch(
        r"[a-z][a-z0-9]*(?:[-_][a-z0-9]+)+",
        value,
    )
    return machine_identifier is None


def _normalise_scan_path(path: str) -> str:
    return re.sub(r"\[\d+\]", "[*]", str(path or "$"))


def _machine_field_paths(
    schema: Mapping[str, Any],
    prefix: str = "$",
) -> set[str]:
    result: set[str] = set()
    schema_type = str(schema.get("type", ""))
    semantic_type = str(schema.get("semantic_type", ""))
    if schema_type in MACHINE_FIELD_TYPES or semantic_type in MACHINE_FIELD_TYPES:
        result.add(_normalise_scan_path(prefix))
    if schema_type == "array":
        items = schema.get("items")
        if isinstance(items, Mapping):
            result.update(_machine_field_paths(items, f"{prefix}[*]"))
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
    primary_detector: str = ""
    fallback_detector: str = ""
    fallback_available: bool = False
    fallback_executed: bool = False
    coverage_scope: str = "primary_only"
    coverage_complete: bool = True
    available: bool = True
    incomplete: bool = False
    field_statuses: dict[str, str] = field(default_factory=dict)
    flagged_fields: list[str] = field(default_factory=list)
    quarantined_fields: list[str] = field(default_factory=list)
    risky_entities: list[str] = field(default_factory=list)
    unscanned_fields: list[str] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)
    chunk_evidence: list[dict[str, Any]] = field(default_factory=list)
    field_metrics: dict[str, dict[str, Any]] = field(default_factory=dict)
    quarantine_metrics: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return bool(self.quarantined_fields)

    def information_flow(self) -> dict[str, Any]:
        return make_injection(
            source_flagged=bool(self.risky_entities or self.quarantined_fields),
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
            primary_detector=self.primary_detector,
            fallback_detector=self.fallback_detector,
            fallback_available=self.fallback_available,
            fallback_executed=self.fallback_executed,
            coverage_scope=self.coverage_scope,
            coverage_complete=self.coverage_complete,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_flagged": self.source_flagged,
            "max_score": round(self.max_score, 6),
            "detector": self.detector,
            "primary_detector": self.primary_detector,
            "fallback_detector": self.fallback_detector,
            "fallback_available": self.fallback_available,
            "fallback_executed": self.fallback_executed,
            "coverage_scope": self.coverage_scope,
            "coverage_complete": self.coverage_complete,
            "available": self.available,
            "incomplete": self.incomplete,
            "field_statuses": dict(self.field_statuses),
            "flagged_fields": list(self.flagged_fields),
            "quarantined_fields": list(self.quarantined_fields),
            "risky_entities": list(self.risky_entities),
            "unscanned_fields": list(self.unscanned_fields),
            "evidence_refs": list(self.evidence_refs),
            "chunk_evidence": list(self.chunk_evidence),
            "field_metrics": {str(path): dict(metrics) for path, metrics in self.field_metrics.items()},
            "quarantine_metrics": dict(self.quarantine_metrics),
            "errors": list(self.errors),
        }


def _jsonable(value: Any) -> Any:
    if isinstance(value, BaseException):
        return str(value)
    if hasattr(value, "model_dump"):
        return _jsonable(value.model_dump(mode="python"))
    if isinstance(value, dict):
        return {str(key): _jsonable(child) for key, child in value.items()}
    if isinstance(value, list | tuple | set):
        return [_jsonable(child) for child in value]
    if isinstance(value, str | int | float | bool) or value is None:
        return value
    return str(value)


def _direct_entity_path(path: str) -> str:
    """Return the concrete APP entity root containing a flagged field."""
    value = str(path or "$")
    match = re.match(
        r"^(\$(?:\.[A-Za-z0-9_]+)?\[\d+\])",
        value,
    )
    return match.group(1) if match else "$"


def _collect_string_fields(value: Any) -> dict[str, str]:
    result: dict[str, str] = {}

    def walk(item: Any, path: str) -> None:
        if isinstance(item, str):
            result[path] = item
        elif isinstance(item, dict):
            for key, child in item.items():
                walk(child, f"{path}.{key}" if path else str(key))
        elif isinstance(item, list):
            for index, child in enumerate(item):
                walk(child, f"{path}[{index}]")

    walk(value, "$")
    return result


_CONTROL_ENVELOPE_RE = re.compile(
    r"<(information|system|instructions|important)\b[^>]*>"
    r".*?"
    r"</\1\s*>",
    re.IGNORECASE | re.DOTALL,
)
_CONTROL_ENVELOPE_OPEN_RE = re.compile(
    r"<(information|system|instructions|important)\b[^>]*>",
    re.IGNORECASE,
)


def _expand_injection_spans(
    text: str,
    chunks: Sequence[Any],
) -> list[dict[str, int | float]]:
    """Expand local detector hits to complete control envelopes."""
    envelopes = [
        (match.start(), match.end())
        for match in _CONTROL_ENVELOPE_RE.finditer(text)
    ]
    for match in _CONTROL_ENVELOPE_OPEN_RE.finditer(text):
        closing_tag = re.compile(
            rf"</{re.escape(match.group(1))}\s*>",
            re.IGNORECASE,
        )
        if not closing_tag.search(text, match.end()):
            envelopes.append((match.start(), len(text)))
    coarse_units: list[tuple[int, int]] = []
    sentence_start = 0
    for match in re.finditer(
        r"(?:[.!?](?=\s|$)|\u3002|\uff01|\uff1f|\r?\n)",
        text,
    ):
        sentence_end = match.end()
        if sentence_end > sentence_start:
            coarse_units.append(
                (sentence_start, sentence_end)
            )
            sentence_start = sentence_end
    if sentence_start < len(text):
        coarse_units.append((sentence_start, len(text)))
    sentence_units: list[tuple[int, int]] = []
    for unit_start, unit_end in coarse_units:
        unit = text[unit_start:unit_end]
        marker_positions = [
            unit_start + match.start()
            for match in _INJECTION_CONTROL_MARKER_RE.finditer(unit)
        ]
        cursor = unit_start
        for marker_start in marker_positions:
            if marker_start > cursor:
                sentence_units.append((cursor, marker_start))
            cursor = marker_start
        if cursor < unit_end:
            sentence_units.append((cursor, unit_end))
    expanded: list[dict[str, int | float]] = []
    for chunk in chunks:
        start = max(0, int(getattr(chunk, "start", 0) or 0))
        end = min(len(text), int(getattr(chunk, "end", start) or start))
        score = float(getattr(chunk, "score", 0.0) or 0.0)
        if end <= start:
            continue
        envelope = next(
            (
                (envelope_start, envelope_end)
                for envelope_start, envelope_end in envelopes
                if envelope_start <= start < envelope_end
                or envelope_start < end <= envelope_end
            ),
            None,
        )
        if envelope is not None:
            start, end = envelope
        elif sentence_units:
            unit_index = next(
                (
                    index
                    for index, (unit_start, unit_end) in enumerate(
                        sentence_units
                    )
                    if unit_start <= start < unit_end
                    or unit_start < end <= unit_end
                ),
                None,
            )
            if unit_index is not None:
                start = sentence_units[unit_index][0]
                end = sentence_units[unit_index][1]
        expanded.append(
            {
                "start": start,
                "end": end,
                "score": score,
            }
        )
    expanded.sort(key=lambda item: (int(item["start"]), int(item["end"])))
    merged: list[dict[str, int | float]] = []
    for item in expanded:
        start = int(item["start"])
        end = int(item["end"])
        score = float(item["score"])
        if merged and start <= int(merged[-1]["end"]):
            merged[-1]["end"] = max(int(merged[-1]["end"]), end)
            merged[-1]["score"] = max(float(merged[-1]["score"]), score)
        else:
            merged.append({"start": start, "end": end, "score": score})
    return merged


def _replace_string_paths(
    value: Any,
    paths: set[str],
    replacement: str,
) -> Any:
    """Return a copy with selected concrete string paths replaced."""
    if not paths:
        return value
    tokens_by_path = {
        path: [
            (str(key) if key else int(index))
            for key, index in re.findall(
                r"\.([^.\[\]]+)|\[(\d+)\]",
                path,
            )
        ]
        for path in paths
    }

    def walk(
        item: Any,
        tokens: list[str | int],
        active_paths: set[str],
    ) -> Any:
        if not tokens:
            return replacement if active_paths else item
        token = tokens[0]
        if isinstance(token, int):
            if not isinstance(item, list) or token >= len(item):
                return item
            copied = list(item)
            copied[token] = walk(
                item[token],
                tokens[1:],
                active_paths,
            )
            return copied
        if not isinstance(item, dict) or token not in item:
            return item
        copied = dict(item)
        copied[token] = walk(
            item[token],
            tokens[1:],
            active_paths,
        )
        return copied

    result = copy.deepcopy(value)
    for path, tokens in tokens_by_path.items():
        result = walk(result, tokens, {path})
    return result


def quarantine_tool_output_fields(
    value: Any,
    fields: Sequence[str],
    *,
    placeholder: str = REDACTION_PLACEHOLDER,
) -> tuple[Any, bool]:
    """Fail closed by replacing every flagged projected field."""
    paths = {
        str(path)
        for path in fields
        if str(path).strip()
    }
    sanitized = _replace_string_paths(
        value,
        paths,
        replacement=placeholder,
    )
    return sanitized, sanitized != value


def scan_tool_output(
    value: Any,
    *,
    scanner: InjectionScanner,
    tool_name: str = "",
    schema: Mapping[str, Any] | None = None,
    app: str = "",
    entity: str = "",
) -> ToolOutputScan:
    """Scan only natural-language leaves and replace suspicious chunks."""
    result = ToolOutputScan(
        sanitized_value=copy.deepcopy(value),
        primary_detector=str(getattr(scanner, "detector_name", "")),
        fallback_detector=str(getattr(scanner, "fallback_detector_name", "")),
        fallback_available=bool(getattr(scanner, "fallback_available", False)),
        coverage_scope=str(getattr(scanner, "coverage_scope", "primary_only")),
    )
    jsonable = _jsonable(value)
    pending: list[tuple[str, str]] = []
    machine_paths = _machine_field_paths(schema) if isinstance(schema, Mapping) else set()

    def collect(item: Any, path: str) -> None:
        if isinstance(item, str):
            normalized_path = _normalise_scan_path(path)
            policy = field_policy(app, entity, path) if app and entity else {}
            categories = {str(item) for item in policy.get("categories", []) if item}
            if (
                normalized_path in machine_paths
                or categories & NON_LANGUAGE_CATEGORIES
                or SENSITIVE_REFERENCE_PATTERN.fullmatch(item)
                or item == INDIRECT_INJECTION_PLACEHOLDER
                or not _should_scan(item)
            ):
                result.field_statuses[path] = "not_applicable"
            else:
                pending.append((path, item))
        elif isinstance(item, dict):
            for key, child in item.items():
                collect(child, f"{path}.{key}" if path else str(key))
        elif isinstance(item, list):
            for index, child in enumerate(item):
                collect(child, f"{path}[{index}]")

    collect(jsonable, "$")
    scans = scanner.scan_many([text for _path, text in pending])
    scan_by_path = {path: scan for (path, _text), scan in zip(pending, scans)}
    unscanned_paths = {path for path, _text in pending if path not in scan_by_path}
    if unscanned_paths:
        result.available = False
        result.incomplete = True
        result.source_flagged = True
        for path in sorted(unscanned_paths):
            result.field_statuses[path] = "quarantined_unscanned"
            result.flagged_fields.append(path)
            result.quarantined_fields.append(path)
            result.unscanned_fields.append(path)
        result.errors.append("scanner_returned_incomplete_batch")
    field_metrics: dict[str, dict[str, Any]] = {}

    def transform(item: Any, path: str) -> Any:
        if isinstance(item, str):
            scan = scan_by_path.get(path)
            if scan is None:
                if path in unscanned_paths:
                    return REDACTION_PLACEHOLDER
                return item
            result.detector = scan.detector
            result.fallback_executed = bool(result.fallback_executed or getattr(scan, "fallback_executed", False))
            result.coverage_complete = bool(
                result.coverage_complete
                and getattr(
                    scan,
                    "coverage_complete",
                    scan.available and not scan.truncated,
                )
            )
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
                sanitized, metrics = redact_injection_chunks_with_metrics(
                    item,
                    {
                        "chunks": [
                            {
                                "start": 0,
                                "end": len(item),
                                "score": scan.score,
                            }
                        ]
                    },
                    placeholder=REDACTION_PLACEHOLDER,
                )
                field_metrics[path] = metrics
                return sanitized
            if scan.truncated:
                result.incomplete = True
                result.source_flagged = True
                result.field_statuses[path] = "quarantined_incomplete"
                result.flagged_fields.append(path)
                result.quarantined_fields.append(path)
                result.unscanned_fields.append(path)
                sanitized, metrics = redact_injection_chunks_with_metrics(
                    item,
                    {
                        "chunks": [
                            {
                                "start": 0,
                                "end": len(item),
                                "score": scan.score,
                            }
                        ]
                    },
                    placeholder=REDACTION_PLACEHOLDER,
                )
                field_metrics[path] = metrics
                return sanitized
            if not scan.suspected:
                result.field_statuses[path] = "scanned_clean"
                return item

            language_chunks = [
                chunk
                for chunk in scan.chunks
                if _should_scan(chunk.text)
            ]
            if scan.chunks and not language_chunks:
                result.field_statuses[path] = "scanned_clean"
                return item

            result.source_flagged = True
            result.field_statuses[path] = "quarantined"
            result.flagged_fields.append(path)
            result.quarantined_fields.append(path)
            source_chunks = language_chunks or scan.chunks
            source_spans = [
                (
                    int(span["start"])
                    if isinstance(span, Mapping)
                    else int(getattr(span, "start", 0) or 0),
                    int(span["end"])
                    if isinstance(span, Mapping)
                    else int(getattr(span, "end", 0) or 0),
                )
                for span in source_chunks
            ]
            localized_spans, fallback_reviewed = (
                scanner.localize_injection_spans(
                    item,
                    source_spans,
                )
            )
            if fallback_reviewed:
                result.fallback_executed = True
                scan.fallback_executed = True
            if localized_spans:
                expanded_spans = [
                    {
                        "start": int(span.start),
                        "end": int(span.end),
                        "score": float(span.score),
                    }
                    for span in localized_spans
                ]
                result.detector = (
                    f"{scan.detector}+{scan.fallback_detector}"
                )
                scan.detector = result.detector
                result.max_score = max(
                    result.max_score,
                    max(
                        float(span.score)
                        for span in localized_spans
                    ),
                )
            else:
                expanded_spans = _expand_injection_spans(
                    item,
                    source_chunks,
                )
                if not expanded_spans:
                    expanded_spans = [
                        {
                            "start": 0,
                            "end": len(item),
                            "score": float(scan.score),
                        }
                    ]
                if fallback_reviewed:
                    following_spans, _ = (
                        scanner.review_adjacent_units(
                            item,
                            source_spans,
                        )
                    )
                else:
                    following_spans = []
                if following_spans:
                    result.detector = (
                        f"{scan.detector}+{scan.fallback_detector}"
                    )
                    scan.detector = result.detector
                    expanded_spans.extend(
                        {
                            "start": int(span.start),
                            "end": int(span.end),
                            "score": float(span.score),
                        }
                        for span in following_spans
                    )
                    result.max_score = max(
                        result.max_score,
                        max(
                            float(span.score)
                            for span in following_spans
                        ),
                    )
                expanded_spans.sort(
                    key=lambda span: (
                        int(span["start"]),
                        int(span["end"]),
                    )
                )
            for index, span in enumerate(expanded_spans):
                start = int(span["start"])
                end = int(span["end"])
                evidence_ref = (
                    f"{tool_name}:{path}:chunk:{index}"
                    if tool_name
                    else f"{path}:chunk:{index}"
                )
                result.evidence_refs.append(evidence_ref)
                result.chunk_evidence.append(
                    {
                        "field": path,
                        "chunk_index": index,
                        "start": start,
                        "end": end,
                        "text": item[start:end],
                        "score": round(float(span["score"]), 6),
                        "evidence_ref": evidence_ref,
                    }
                )
            sanitized, metrics = redact_injection_chunks_with_metrics(
                item,
                {"chunks": expanded_spans},
                placeholder=REDACTION_PLACEHOLDER,
            )
            field_metrics[path] = metrics
            return sanitized
        if isinstance(item, dict):
            return {key: transform(child, f"{path}.{key}" if path else str(key)) for key, child in item.items()}
        if isinstance(item, list):
            return [transform(child, f"{path}[{index}]") for index, child in enumerate(item)]
        return item

    result.sanitized_value = transform(jsonable, "$")
    sanitized_fields = _collect_string_fields(result.sanitized_value)
    rescan_paths = [path for path in result.quarantined_fields if path in sanitized_fields]
    if rescan_paths:
        rescans = list(scanner.scan_many([sanitized_fields[path] for path in rescan_paths]))
        for index, path in enumerate(rescan_paths):
            rescan = rescans[index] if index < len(rescans) else None
            metrics = field_metrics.setdefault(
                path,
                merge_quarantine_metrics([]),
            )
            if rescan is None:
                metrics.update(
                    {
                        "sanitized_rescan_available": False,
                        "sanitized_rescan_score": 0.0,
                        "sanitized_residual_suspected": False,
                        "sanitized_rescan_unavailable": True,
                    }
                )
                result.available = False
                result.incomplete = True
                result.errors.append(f"residual_rescan_missing:{path}")
                continue
            metrics.update(
                {
                    "sanitized_rescan_available": rescan.available,
                    "sanitized_rescan_score": rescan.score,
                    "sanitized_residual_suspected": rescan.suspected,
                    "sanitized_rescan_unavailable": not rescan.available,
                }
            )
            if rescan.suspected or not rescan.available:
                result.incomplete = True
                if rescan.suspected:
                    result.errors.append(f"residual_injection_after_redaction:{path}")
                else:
                    result.available = False
                    result.errors.append(f"residual_rescan_unavailable:{path}")
    residual_paths = {
        path
        for path, metrics in field_metrics.items()
        if metrics.get("sanitized_rescan_unavailable", False)
    }
    if residual_paths:
        result.sanitized_value = _replace_string_paths(
            result.sanitized_value,
            residual_paths,
            REDACTION_PLACEHOLDER,
        )
        for path in residual_paths:
            metrics = field_metrics[path]
            metrics["fallback_field_quarantine"] = True
            metrics["sanitized_length"] = len(REDACTION_PLACEHOLDER)
    result.field_metrics = {path: dict(metrics) for path, metrics in field_metrics.items()}
    result.quarantine_metrics = merge_quarantine_metrics(field_metrics.values())
    result.flagged_fields = list(dict.fromkeys(result.flagged_fields))
    result.quarantined_fields = list(dict.fromkeys(result.quarantined_fields))
    result.risky_entities = list(dict.fromkeys(_direct_entity_path(path) for path in result.quarantined_fields))
    result.unscanned_fields = list(dict.fromkeys(result.unscanned_fields))
    result.evidence_refs = list(dict.fromkeys(result.evidence_refs))
    result.coverage_complete = bool(result.coverage_complete and result.available and not result.incomplete)
    return result
