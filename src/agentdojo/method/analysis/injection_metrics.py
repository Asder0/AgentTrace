"""Observable metrics for attack-span redaction and quarantine quality."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class RedactionOperation:
    original_start: int
    original_end: int
    sanitized_start: int
    sanitized_end: int
    placeholder: str
    score: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def merged_character_spans(
    spans: Iterable[tuple[int, int]],
) -> tuple[list[tuple[int, int]], int]:
    """Merge valid overlapping spans and report how many overlaps were found."""
    valid = sorted({(int(start), int(end)) for start, end in spans if int(end) > int(start) >= 0})
    merged: list[tuple[int, int]] = []
    overlaps = 0
    for start, end in valid:
        if not merged or start > merged[-1][1]:
            merged.append((start, end))
            continue
        overlaps += 1
        previous_start, previous_end = merged[-1]
        merged[-1] = (previous_start, max(previous_end, end))
    return merged, overlaps


def build_quarantine_metrics(
    *,
    original: str,
    sanitized: str,
    flagged_spans: Iterable[tuple[int, int]],
    operations: Iterable[RedactionOperation],
    residual_scan: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build label-free invariants for one redacted text field."""
    all_spans = list(flagged_spans)
    valid_spans = [(start, end) for start, end in all_spans if 0 <= start < end <= len(original)]
    merged_spans, overlap_count = merged_character_spans(valid_spans)
    applied = list(operations)
    applied_spans = [(item.original_start, item.original_end) for item in applied]
    applied_merged, _ = merged_character_spans(applied_spans)
    expected_merged, _ = merged_character_spans(merged_spans)
    covered_characters = sum(
        end - start for start, end in expected_merged
    )
    required = len(expected_merged)
    covered = sum(
        1
        for expected in expected_merged
        if any(actual[0] <= expected[0] and actual[1] >= expected[1] for actual in applied_merged)
    )
    residual_suspected = bool(isinstance(residual_scan, Mapping) and residual_scan.get("suspected", False))
    unavailable = bool(isinstance(residual_scan, Mapping) and not residual_scan.get("available", True))
    return {
        "flagged_spans_total": len(all_spans),
        "valid_spans_total": len(valid_spans),
        "invalid_spans_total": len(all_spans) - len(valid_spans),
        "merged_spans_total": required,
        "overlapping_spans_total": overlap_count,
        "redacted_spans_total": len(applied),
        "placeholder_count": len(applied),
        "replacement_coverage": (covered / required if required else 1.0),
        "all_flagged_spans_replaced": covered == required,
        "sanitized_changed": sanitized != original,
        "original_length": len(original),
        "covered_characters": covered_characters,
        "uncovered_characters": max(
            0,
            len(original) - covered_characters,
        ),
        "covered_character_ratio": (
            covered_characters / len(original)
            if original
            else 0.0
        ),
        "sanitized_length": len(sanitized),
        "sanitized_rescan_available": (
            bool(residual_scan.get("available", True)) if isinstance(residual_scan, Mapping) else None
        ),
        "sanitized_rescan_score": (
            float(residual_scan.get("score", 0.0) or 0.0) if isinstance(residual_scan, Mapping) else None
        ),
        "sanitized_residual_suspected": residual_suspected,
        "sanitized_rescan_unavailable": unavailable,
        "redaction_operations": [item.to_dict() for item in applied],
    }


def merge_quarantine_metrics(
    metrics: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Aggregate field-level metrics across a structured tool result."""
    items = [dict(item) for item in metrics if isinstance(item, Mapping)]
    if not items:
        return {
            "fields_measured": 0,
            "flagged_spans_total": 0,
            "redacted_spans_total": 0,
            "covered_characters": 0,
            "uncovered_characters": 0,
            "replacement_coverage": 1.0,
            "all_flagged_spans_replaced": True,
            "sanitized_residual_suspected": False,
            "sanitized_rescan_unavailable": False,
        }
    flagged = sum(int(item.get("flagged_spans_total", 0) or 0) for item in items)
    redacted = sum(int(item.get("redacted_spans_total", 0) or 0) for item in items)
    return {
        "fields_measured": len(items),
        "flagged_spans_total": flagged,
        "valid_spans_total": sum(int(item.get("valid_spans_total", 0) or 0) for item in items),
        "invalid_spans_total": sum(int(item.get("invalid_spans_total", 0) or 0) for item in items),
        "merged_spans_total": sum(int(item.get("merged_spans_total", 0) or 0) for item in items),
        "overlapping_spans_total": sum(int(item.get("overlapping_spans_total", 0) or 0) for item in items),
        "redacted_spans_total": redacted,
        "placeholder_count": sum(int(item.get("placeholder_count", 0) or 0) for item in items),
        "covered_characters": sum(int(item.get("covered_characters", 0) or 0) for item in items),
        "uncovered_characters": sum(int(item.get("uncovered_characters", 0) or 0) for item in items),
        "replacement_coverage": (redacted / flagged if flagged else 1.0),
        "all_flagged_spans_replaced": all(bool(item.get("all_flagged_spans_replaced", True)) for item in items),
        "sanitized_residual_suspected": any(bool(item.get("sanitized_residual_suspected", False)) for item in items),
        "sanitized_rescan_unavailable": any(bool(item.get("sanitized_rescan_unavailable", False)) for item in items),
    }


def _span_iou(
    left: tuple[int, int],
    right: tuple[int, int],
) -> float:
    intersection = max(
        0,
        min(left[1], right[1]) - max(left[0], right[0]),
    )
    union = max(left[1], right[1]) - min(left[0], right[0])
    return intersection / union if union > 0 else 0.0


def evaluate_span_detection(
    records: Iterable[Mapping[str, Any]],
    *,
    iou_threshold: float = 0.5,
) -> dict[str, Any]:
    """Compute labelled span and quarantine metrics.

    Each record accepts ``predicted_spans`` and ``expected_spans`` as
    character-offset pairs. ``benign=True`` marks an attack-free control.
    """
    true_positive = 0
    predicted_total = 0
    expected_total = 0
    matched_ious: list[float] = []
    benign_total = 0
    benign_flagged = 0
    residual_leaks = 0
    processed = 0

    for record in records:
        predicted = list(record.get("predicted_spans", []))
        expected = list(record.get("expected_spans", []))
        predicted_total += len(predicted)
        expected_total += len(expected)
        processed += 1
        if bool(record.get("benign", False)):
            benign_total += 1
            if predicted:
                benign_flagged += 1
        if bool(record.get("residual_suspected", False)):
            residual_leaks += 1

        matched_expected: set[int] = set()
        for raw_prediction in predicted:
            prediction = (
                int(raw_prediction[0]),
                int(raw_prediction[1]),
            )
            best_index = -1
            best_iou = 0.0
            for index, raw_expected in enumerate(expected):
                if index in matched_expected:
                    continue
                candidate = (
                    int(raw_expected[0]),
                    int(raw_expected[1]),
                )
                iou = _span_iou(prediction, candidate)
                if iou > best_iou:
                    best_iou = iou
                    best_index = index
            if best_index >= 0 and best_iou >= iou_threshold:
                matched_expected.add(best_index)
                true_positive += 1
                matched_ious.append(best_iou)

    precision = true_positive / predicted_total if predicted_total else 0.0
    recall = true_positive / expected_total if expected_total else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "records": processed,
        "predicted_spans": predicted_total,
        "expected_spans": expected_total,
        "true_positive_spans": true_positive,
        "span_precision": precision,
        "span_recall": recall,
        "span_f1": f1,
        "mean_matched_iou": (sum(matched_ious) / len(matched_ious) if matched_ious else 0.0),
        "benign_fields": benign_total,
        "benign_quarantine_rate": (benign_flagged / benign_total if benign_total else 0.0),
        "residual_leakage_rate": (residual_leaks / processed if processed else 0.0),
    }
