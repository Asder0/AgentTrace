"""Local model asset resolution.

The visualization runtime must not depend on Hugging Face availability at
startup or during task execution. Model files therefore live under the
project's ``models`` directory and are loaded with ``local_files_only=True``.
"""

from __future__ import annotations

import os
from pathlib import Path

DEFAULT_INJECTION_MODEL_ID = "Horizon-Labs/prompt-injection-guard-small"
DEFAULT_INJECTION_MODEL_DIRNAME = "prompt-injection-guard-small"
INJECTION_MODEL_PATH_ENV = "AGENTDOJO_PI_MODEL_PATH"

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_INJECTION_MODEL_DIR = (
    PROJECT_ROOT / "models" / DEFAULT_INJECTION_MODEL_DIRNAME
)


def missing_injection_model_files(model_dir: Path) -> list[str]:
    """Return missing files that prevent a directory from loading offline."""
    missing: list[str] = []
    if not model_dir.is_dir():
        return [str(model_dir)]
    if not (model_dir / "config.json").is_file():
        missing.append("config.json")
    if not any(model_dir.glob("*.safetensors")) and not any(
        model_dir.glob("pytorch_model*.bin")
    ):
        missing.append("model weights (*.safetensors or pytorch_model*.bin)")
    if not (
        (model_dir / "tokenizer.json").is_file()
        or (model_dir / "spm.model").is_file()
        or (model_dir / "sentencepiece.bpe.model").is_file()
        or (model_dir / "vocab.txt").is_file()
    ):
        missing.append("tokenizer assets")
    return missing


def resolve_injection_model_path(model_path: str | Path | None = None) -> Path:
    """Resolve the local prompt-injection model without any network fallback.

    Resolution order:

    1. ``AGENTDOJO_PI_MODEL_PATH`` for machines with a different asset location.
    2. An explicitly supplied local path.
    3. The checked-out project's standard local model directory.

    A Hugging Face model identifier is intentionally not treated as a valid
    fallback. Failing with a precise asset error is preferable to a task
    hanging on an unstable network connection.
    """
    configured = os.getenv(INJECTION_MODEL_PATH_ENV, "").strip()
    requested = configured or (str(model_path).strip() if model_path else "")
    if requested:
        candidate = (
            DEFAULT_INJECTION_MODEL_DIR
            if requested == DEFAULT_INJECTION_MODEL_ID
            else Path(requested).expanduser()
        )
    else:
        candidate = DEFAULT_INJECTION_MODEL_DIR

    resolved = candidate.resolve()
    missing = missing_injection_model_files(resolved)
    if missing:
        raise FileNotFoundError(
            "Prompt-injection detector must be loaded from local files. "
            f"Missing or incomplete model directory: {resolved}. "
            f"Missing: {', '.join(missing)}. "
            f"Place the model assets there or set {INJECTION_MODEL_PATH_ENV}."
        )
    return resolved
