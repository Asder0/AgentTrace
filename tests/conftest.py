"""Shared test configuration."""

from __future__ import annotations

import pytest

from agentdojo.method.analysis.injection_scanner import (
    configure_injection_classifier,
    reset_injection_scanner,
)


class _DeterministicTestInjectionClassifier:
    """Small deterministic classifier used to keep tests fully offline."""

    model_name = "test-prompt-injection-classifier"
    tokenizer = None

    def classify(self, text: str) -> float:
        normalized = " ".join(str(text).lower().split())
        suspicious_markers = (
            "ignore previous instructions",
            "ignore all previous instructions",
            "ignore your previous instructions",
            "system_message",
        )
        if any(marker in normalized for marker in suspicious_markers):
            return 0.98
        return 0.01


@pytest.fixture(autouse=True)
def _offline_injection_classifier():
    configure_injection_classifier(_DeterministicTestInjectionClassifier())
    yield
    reset_injection_scanner()
