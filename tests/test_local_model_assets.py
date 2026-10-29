"""Offline prompt-injection model loading tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentdojo import model_assets
from agentdojo.method.analysis import injection_scanner
from agentdojo.method.analysis.injection_scanner import (
    TransformersInjectionClassifier,
)


def _create_model_assets(model_dir: Path) -> None:
    model_dir.mkdir(parents=True)
    (model_dir / "config.json").write_text("{}", encoding="utf-8")
    (model_dir / "model.safetensors").write_bytes(b"weights")
    (model_dir / "tokenizer.json").write_text("{}", encoding="utf-8")


def test_default_model_id_resolves_to_project_local_directory(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    model_dir = tmp_path / "model"
    _create_model_assets(model_dir)
    monkeypatch.delenv(model_assets.INJECTION_MODEL_PATH_ENV, raising=False)
    monkeypatch.setattr(
        model_assets,
        "DEFAULT_INJECTION_MODEL_DIR",
        model_dir,
    )

    resolved = model_assets.resolve_injection_model_path(
        model_assets.DEFAULT_INJECTION_MODEL_ID
    )

    assert resolved == model_dir.resolve()


def test_model_path_environment_variable_takes_precedence(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    model_dir = tmp_path / "custom-model"
    _create_model_assets(model_dir)
    monkeypatch.setenv(model_assets.INJECTION_MODEL_PATH_ENV, str(model_dir))

    assert model_assets.resolve_injection_model_path() == model_dir.resolve()


def test_incomplete_local_model_fails_without_network_fallback(tmp_path: Path) -> None:
    model_dir = tmp_path / "incomplete-model"
    model_dir.mkdir()
    (model_dir / "config.json").write_text("{}", encoding="utf-8")

    with pytest.raises(FileNotFoundError, match="local files"):
        model_assets.resolve_injection_model_path(model_dir)


def test_transformers_classifier_loads_local_path_and_forces_offline(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    model_dir = tmp_path / "model"
    _create_model_assets(model_dir)
    monkeypatch.delenv(model_assets.INJECTION_MODEL_PATH_ENV, raising=False)
    monkeypatch.setattr(
        model_assets,
        "DEFAULT_INJECTION_MODEL_DIR",
        model_dir,
    )
    calls: dict[str, object] = {}

    class FakePipeline:
        tokenizer = None

        def __call__(self, text: str, **_kwargs: object) -> list[dict[str, object]]:
            calls["text"] = text
            return [{"label": "SAFE", "score": 0.99}]

    def fake_build(pipeline_factory: object, model_path: str, device: object) -> FakePipeline:
        calls["model"] = model_path
        calls["device"] = device
        return FakePipeline()

    monkeypatch.setattr(
        injection_scanner,
        "_build_local_text_classification_pipeline",
        fake_build,
    )

    classifier = TransformersInjectionClassifier()
    classifier.warmup()

    assert calls["model"] == str(model_dir.resolve())


def test_pipeline_builder_sets_local_files_only() -> None:
    calls: dict[str, object] = {}

    def fake_pipeline(task: str, **kwargs: object) -> object:
        calls["task"] = task
        calls.update(kwargs)
        return object()

    injection_scanner._build_local_text_classification_pipeline(
        fake_pipeline,
        "C:/local/model",
        "cpu",
    )

    assert calls == {
        "task": "text-classification",
        "model": "C:/local/model",
        "device": "cpu",
        "local_files_only": True,
    }
