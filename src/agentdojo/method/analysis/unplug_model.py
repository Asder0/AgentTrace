"""Offline adapter for the Unplug-tiny-v1 dual-head injection model.

The checkpoint uses a custom DeBERTa-v2 architecture with a document head
and a BIOES token head.  The minimal model definition below follows the
Apache-2.0 Unplug SDK implementation and is kept local so AgentDojo does not
depend on the full Unplug guard runtime.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agentdojo.model_assets import resolve_injection_model_path


@dataclass(frozen=True)
class NativeInjectionSpan:
    start: int
    end: int
    score: float


@dataclass
class NativeInjectionPrediction:
    doc_score: float = 0.0
    spans: list[NativeInjectionSpan] = field(default_factory=list)
    span_threshold: float = 0.45
    doc_threshold: float = 0.9
    doc_score_source: str = "doc_head"


class _DualHeadOutput:
    def __init__(self, logits: Any, doc_logits: Any) -> None:
        self.logits = logits
        self.doc_logits = doc_logits


def _build_dual_head_model_class() -> Any:
    """Create the custom Transformers class after torch is available."""
    from torch import nn
    from transformers.models.deberta_v2.modeling_deberta_v2 import (
        DebertaV2Model,
        DebertaV2PreTrainedModel,
    )

    class DebertaV2ForDualHead(DebertaV2PreTrainedModel):
        def __init__(self, config: Any) -> None:
            super().__init__(config)
            self.num_labels = int(config.num_labels)
            self.num_doc_labels = int(getattr(config, "num_doc_labels", 2))
            self.deberta = DebertaV2Model(config)
            dropout = getattr(
                config,
                "cls_dropout",
                getattr(config, "hidden_dropout_prob", 0.1),
            )
            self.dropout = nn.Dropout(float(dropout))
            self.token_classifier = nn.Linear(
                config.hidden_size,
                self.num_labels,
            )
            self.doc_classifier = nn.Linear(
                config.hidden_size,
                self.num_doc_labels,
            )
            self.post_init()

        def forward(
            self,
            input_ids: Any = None,
            attention_mask: Any = None,
            token_type_ids: Any = None,
            position_ids: Any = None,
            inputs_embeds: Any = None,
            labels: Any = None,
            doc_labels: Any = None,
            output_attentions: bool | None = None,
            output_hidden_states: bool | None = None,
            return_dict: bool | None = None,
            **_: Any,
        ) -> _DualHeadOutput:
            outputs = self.deberta(
                input_ids,
                attention_mask=attention_mask,
                token_type_ids=token_type_ids,
                position_ids=position_ids,
                inputs_embeds=inputs_embeds,
                output_attentions=output_attentions,
                output_hidden_states=output_hidden_states,
                return_dict=True,
            )
            sequence_output = outputs.last_hidden_state
            token_logits = self.token_classifier(self.dropout(sequence_output))
            doc_logits = self.doc_classifier(self.dropout(sequence_output[:, 0, :]))
            return _DualHeadOutput(token_logits, doc_logits)

    return DebertaV2ForDualHead


class UnplugTinyClassifier:
    """Lazy, local-only Unplug-tiny document and span classifier."""

    model_name = "Unplug-AI/unplug-tiny-v1"
    safe_label = "SAFE"

    def __init__(
        self,
        model_path: str | Path | None = None,
        *,
        span_threshold: float = 0.45,
        doc_threshold: float = 0.9,
    ) -> None:
        self.model_path = model_path
        self.span_threshold = float(span_threshold)
        self.doc_threshold = float(doc_threshold)
        self._model: Any = None
        self._tokenizer: Any = None
        self._id2label: dict[int, str] = {}
        self._label2id: dict[str, int] = {}
        self._doc_positive_index = 1
        self._max_length = 512
        self._lock = threading.Lock()

    @property
    def tokenizer(self) -> Any:
        self._load()
        return self._tokenizer

    @property
    def max_length(self) -> int:
        self._load()
        return self._max_length

    def _load(self) -> None:
        if self._model is not None:
            return
        with self._lock:
            if self._model is not None:
                return
            try:
                import torch
                from transformers import AutoConfig, AutoTokenizer
            except ImportError as exc:
                raise RuntimeError(
                    "Unplug injection scanning requires `pip install 'agentdojo[transformers]'`."
                ) from exc

            path = Path(self.model_path) if self.model_path else resolve_injection_model_path()
            config = AutoConfig.from_pretrained(
                path,
                local_files_only=True,
            )
            if not bool(getattr(config, "dual_head", False)):
                raise RuntimeError(f"Unplug checkpoint at {path} is not a dual-head model.")
            tokenizer = AutoTokenizer.from_pretrained(
                path,
                local_files_only=True,
                use_fast=True,
                clean_up_tokenization_spaces=False,
            )
            model_class = _build_dual_head_model_class()
            device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
            model = model_class.from_pretrained(
                path,
                local_files_only=True,
                use_safetensors=True,
                torch_dtype=torch.float32,
            )
            model.to(device)
            model.eval()

            label2id = {str(label): int(index) for label, index in (config.label2id or {}).items()}
            if not any(label in label2id for label in ("B-INJ", "I-INJ", "E-INJ", "S-INJ")):
                raise RuntimeError("Unplug checkpoint has no injection BIOES labels.")
            self._id2label = {int(index): str(label) for index, label in (config.id2label or {}).items()}
            self._label2id = label2id
            self._doc_positive_index = int(getattr(config, "doc_positive_index", 1))
            self._max_length = int(getattr(config, "max_position_embeddings", 512))
            self._model = model
            self._tokenizer = tokenizer

    def warmup(self) -> None:
        self.predict("AgentTrace prompt injection detector warmup")

    def classify(self, text: str) -> float:
        return self.predict(text).doc_score

    def classify_many(self, texts: list[str]) -> list[float]:
        return [prediction.doc_score for prediction in self.predict_many(texts)]

    def predict(self, text: str) -> NativeInjectionPrediction:
        return self.predict_many([text])[0]

    def predict_many(
        self,
        texts: list[str],
    ) -> list[NativeInjectionPrediction]:
        if not texts:
            return []
        self._load()
        import torch

        predictions = [
            NativeInjectionPrediction(
                span_threshold=self.span_threshold,
                doc_threshold=self.doc_threshold,
            )
            for _ in texts
        ]
        encoding = self._tokenizer(
            texts,
            return_offsets_mapping=True,
            truncation=True,
            max_length=self._max_length,
            stride=max(16, min(64, self._max_length // 8)),
            padding=True,
            return_overflowing_tokens=True,
            return_tensors="pt",
        )
        overflow_map = encoding.pop(
            "overflow_to_sample_mapping",
            torch.arange(len(texts)),
        ).tolist()
        offset_mapping = encoding.pop("offset_mapping")
        device = next(self._model.parameters()).device
        inputs = {key: value.to(device) for key, value in encoding.items()}
        with torch.no_grad():
            outputs = self._model(**inputs)
            token_probs = torch.softmax(outputs.logits, dim=-1)
            doc_probs = torch.softmax(outputs.doc_logits, dim=-1)

        for row, sample_index in enumerate(overflow_map):
            prediction = predictions[int(sample_index)]
            doc_score = float(doc_probs[row][self._doc_positive_index].item())
            if doc_score >= prediction.doc_score:
                prediction.doc_score = doc_score
            prediction.spans.extend(
                self._decode_spans(
                    offset_mapping[row].tolist(),
                    token_probs[row],
                )
            )
        for prediction in predictions:
            prediction.spans = _merge_native_spans(prediction.spans)
        return predictions

    def _decode_spans(
        self,
        offsets: list[tuple[int, int]],
        probabilities: Any,
    ) -> list[NativeInjectionSpan]:
        injection_ids = {
            int(self._label2id[label]) for label in ("B-INJ", "I-INJ", "E-INJ", "S-INJ") if label in self._label2id
        }
        current: NativeInjectionSpan | None = None
        spans: list[NativeInjectionSpan] = []
        for index, (start, end) in enumerate(offsets):
            if start == end == 0:
                continue
            values = probabilities[index]
            predicted = int(values.argmax().item())
            score = max(float(values[label_id].item()) for label_id in injection_ids)
            label = self._id2label.get(predicted, "O")
            is_injection = predicted in injection_ids and score >= self.span_threshold
            if not is_injection:
                if current is not None:
                    spans.append(current)
                    current = None
                continue
            if label.startswith("S-"):
                if current is not None:
                    spans.append(current)
                spans.append(NativeInjectionSpan(start, end, score))
                current = None
            elif label.startswith("B-"):
                if current is not None:
                    spans.append(current)
                current = NativeInjectionSpan(start, end, score)
            elif label.startswith(("I-", "E-")):
                if current is None:
                    current = NativeInjectionSpan(start, end, score)
                else:
                    current = NativeInjectionSpan(
                        current.start,
                        end,
                        max(current.score, score),
                    )
                if label.startswith("E-"):
                    spans.append(current)
                    current = None
        if current is not None:
            spans.append(current)
        return spans


def _merge_native_spans(
    spans: list[NativeInjectionSpan],
) -> list[NativeInjectionSpan]:
    merged: list[NativeInjectionSpan] = []
    for span in sorted(spans, key=lambda item: (item.start, item.end)):
        if not merged or span.start > merged[-1].end:
            merged.append(span)
            continue
        previous = merged[-1]
        merged[-1] = NativeInjectionSpan(
            previous.start,
            max(previous.end, span.end),
            max(previous.score, span.score),
        )
    return merged
