"""Optional GLiNER-based sensitive-category enrichment."""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .labels import CONFIDENTIALITY_LEVELS, make_confidentiality
from .policy import security_thresholds

GLINER_MODEL_PATH_ENV = "AGENTDOJO_GLINER_MODEL_PATH"
DEFAULT_GLINER_THRESHOLD = float(
    security_thresholds().get(
        "gliner_sensitivity_threshold",
        0.45,
    )
)
DEFAULT_GLINER_MODEL_DIR = Path(__file__).resolve().parents[4] / "models" / "gliner_multi-v2.1"
DEFAULT_GLINER_CACHE_DIR = Path(__file__).resolve().parents[4] / "models" / ".hf-cache"

_LABEL_CATEGORIES = {
    "person name": "personal_name",
    "full name": "personal_name",
    "姓名": "personal_name",
    "address": "address",
    "地址": "address",
    "phone number": "phone",
    "电话号码": "phone",
    "email address": "email",
    "电子邮件地址": "email",
    "bank account number": "financial_data",
    "银行账号": "financial_data",
    "credit card number": "credit_card",
    "银行卡号": "credit_card",
    "password": "credential",
    "密码": "credential",
    "verification code": "verification_code",
    "验证码": "verification_code",
    "passport number": "passport_number",
    "护照号码": "passport_number",
    "government identifier": "government_identifier",
    "身份证号码": "government_identifier",
}
_ENGLISH_LABELS = [label for label in _LABEL_CATEGORIES if not any("\u4e00" <= char <= "\u9fff" for char in label)]
_CJK_LABELS = [label for label in _LABEL_CATEGORIES if any("\u4e00" <= char <= "\u9fff" for char in label)]


@dataclass(frozen=True)
class SensitiveEntity:
    category: str
    text: str
    start: int
    end: int
    score: float


class GLiNERSensitivityDetector:
    """Lazy optional detector; disabled unless a local model path is set."""

    def __init__(
        self,
        model_path: str | Path | None = None,
        *,
        threshold: float = DEFAULT_GLINER_THRESHOLD,
    ) -> None:
        configured = os.getenv(GLINER_MODEL_PATH_ENV, "").strip()
        self.model_path = Path(model_path or configured or DEFAULT_GLINER_MODEL_DIR)
        self.threshold = float(threshold)
        self._model: Any = None
        self._lock = threading.Lock()
        self._cache: dict[str, list[SensitiveEntity]] = {}

    @property
    def enabled(self) -> bool:
        return True

    def _load(self) -> Any:
        if not self.enabled:
            return None
        if self._model is not None:
            return self._model
        with self._lock:
            if self._model is not None:
                return self._model
            try:
                from gliner import GLiNER
            except ImportError as exc:
                raise RuntimeError(
                    "GLiNER sensitivity enrichment requires `pip install 'agentdojo[privacy]'`."
                ) from exc
            path = self.model_path
            if path is None or not path.exists():
                raise FileNotFoundError(f"GLiNER model directory does not exist: {path}")
            self._model = GLiNER.from_pretrained(
                str(path),
                cache_dir=DEFAULT_GLINER_CACHE_DIR,
                local_files_only=True,
                low_cpu_mem_usage=True,
            )
            return self._model

    def ensure_ready(self) -> None:
        """Load the mandatory local detector or raise a hard error."""
        self._load()

    def detect(self, text: str) -> list[SensitiveEntity]:
        model = self._load()
        value = str(text)
        if model is None or not value.strip():
            return []
        cached = self._cache.get(value)
        if cached is not None:
            return list(cached)
        has_cjk = any("\u4e00" <= char <= "\u9fff" for char in value)
        has_latin = any(("a" <= char.lower() <= "z") for char in value)
        if has_cjk:
            label_groups = [_CJK_LABELS]
            if has_latin:
                label_groups.append(_ENGLISH_LABELS)
        else:
            label_groups = [_ENGLISH_LABELS]
        entities = [
            item
            for labels in label_groups
            for item in model.predict_entities(
                value,
                labels,
                threshold=self.threshold,
            )
        ]
        detected = [
            SensitiveEntity(
                category=_LABEL_CATEGORIES.get(
                    str(item.get("label", "")).lower(),
                    "",
                ),
                text=str(item.get("text", "")),
                start=int(item.get("start", 0) or 0),
                end=int(item.get("end", 0) or 0),
                score=float(item.get("score", 0.0) or 0.0),
            )
            for item in entities
            if item.get("label") and str(item.get("label", "")).lower() in _LABEL_CATEGORIES
        ]
        detected = list(
            {
                (
                    item.category,
                    item.start,
                    item.end,
                    item.text,
                ): item
                for item in sorted(
                    detected,
                    key=lambda entity: entity.score,
                )
            }.values()
        )
        self._cache[value] = list(detected)
        return detected


def elevate_policy_for_content(
    policy: dict[str, Any],
    value: Any,
) -> dict[str, Any]:
    """Raise, never lower, a field policy using local GLiNER categories."""
    if (
        policy.get("content_detection") is False
        or str(policy.get("level", "secret")).lower() == "public"
    ):
        return {
            **policy,
            "source": f"{policy.get('source', 'field_policy')}+content_policy_exempt",
        }
    detector = _DEFAULT_DETECTOR
    if detector is None or not detector.enabled or not isinstance(value, str):
        return policy
    entities = detector.detect(value)
    if not entities:
        return policy
    categories = sorted(
        {
            *[str(item) for item in policy.get("categories", [])],
            *[item.category for item in entities],
        }
    )
    current = str(policy.get("level", "secret")).lower()
    elevated = make_confidentiality(
        level=current,
        categories=categories,
    )
    required = str(elevated.get("level", current))
    if CONFIDENTIALITY_LEVELS.get(required, 3) < CONFIDENTIALITY_LEVELS.get(current, 3):
        required = current
    return {
        **policy,
        "level": required,
        "categories": categories,
        "source": f"{policy.get('source', 'field_policy')}+gliner",
        "gliner_entities": [
            {
                "category": item.category,
                "start": item.start,
                "end": item.end,
                "score": item.score,
            }
            for item in entities
        ],
    }


_DEFAULT_DETECTOR = GLiNERSensitivityDetector()


def ensure_sensitivity_detector_ready() -> None:
    _DEFAULT_DETECTOR.ensure_ready()
