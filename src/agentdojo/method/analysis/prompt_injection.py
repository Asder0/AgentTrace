"""Ring 0: chunked small-model direct-prompt injection detection.

The same lightweight classifier used for Ring 1 scans sentence-aware chunks.
No keyword or synonym security rule participates in the decision.
"""

from __future__ import annotations

from typing import Any

from ..modeling.policy import security_thresholds

PROMPT_INJECTION_THRESHOLD = float(
    security_thresholds().get(
        "prompt_injection_min_judge_confidence",
        0.30,
    )
)


def _valid_judgment(
    judge_result: dict[str, Any] | None,
    threshold: float,
) -> bool:
    return bool(
        judge_result
        and judge_result.get("injection") is not None
        and float(judge_result.get("confidence", 0.0) or 0.0) >= threshold
    )


def check_prompt_for_injection(
    prompt: str,
    threshold: float = PROMPT_INJECTION_THRESHOLD,
    options: dict | None = None,
    judge_result: dict | None = None,
    scan_result: dict | None = None,
) -> bool:
    if not prompt or not isinstance(prompt, str):
        return True
    if scan_result is not None:
        return bool(not scan_result.get("suspected", False))
    if _valid_judgment(judge_result, threshold):
        return not bool(judge_result.get("injection"))
    return False


def check_prompt_for_injection_with_details(
    prompt: str,
    threshold: float = PROMPT_INJECTION_THRESHOLD,
    options: dict | None = None,
    judge_result: dict | None = None,
    scan_result: dict | None = None,
) -> dict:
    result = {
        "passed": True,
        "safety_score": 1.0,
        "detection_method": "empty_prompt",
        "prompt_length": 0,
        "judge_confidence": None,
        "judge_threshold": threshold,
    }
    if not prompt or not isinstance(prompt, str):
        return result
    result["prompt_length"] = len(prompt)
    if scan_result is not None:
        available = bool(scan_result.get("available", True))
        score = float(scan_result.get("score", 0.0) or 0.0)
        suspected = bool(scan_result.get("suspected", False))
        result.update(
            {
                "passed": available and not suspected,
                "safety_score": score if suspected else (1.0 - score if available else 0.0),
                "detection_method": (
                    "small_model_chunked" if available else "small_model_unavailable"
                ),
                "evidence_spans": list(scan_result.get("evidence_spans", [])),
                "injection_target": "instruction_hierarchy",
                "reason": (
                    str(scan_result.get("error", ""))
                    if not available
                    else (
                        "A prompt-injection classifier flagged one or more text chunks."
                        if suspected
                        else "No prompt-injection chunk exceeded the configured threshold."
                    )
                ),
                "judge_confidence": score if available else None,
                "chunk_count": int(scan_result.get("chunk_count", 0) or 0),
                "scanner_truncated": bool(scan_result.get("truncated", False)),
            }
        )
        return result
    if judge_result and judge_result.get("error"):
        result["judge_error"] = judge_result["error"]

    if _valid_judgment(judge_result, threshold):
        injection = bool(judge_result.get("injection"))
        confidence = float(judge_result.get("confidence", 0.0) or 0.0)
        result.update(
            {
                "passed": not injection,
                "safety_score": (
                    1.0 - confidence if injection else confidence
                ),
                "detection_method": "main_llm_judge",
                "evidence_spans": judge_result.get("evidence_spans", []),
                "injection_target": judge_result.get("target", "none"),
                "reason": judge_result.get("reason", ""),
                "judge_confidence": confidence,
            }
        )
        return result

    confidence = (
        float(judge_result.get("confidence", 0.0) or 0.0)
        if judge_result
        else None
    )
    result.update(
        {
            "passed": False,
            "safety_score": confidence if confidence is not None else 0.0,
            "detection_method": "main_llm_uncertain",
            "judge_confidence": confidence,
            "reason": (
                "The semantic prompt-injection judgement was unavailable or "
                "below the confidence threshold."
            ),
        }
    )
    return result
