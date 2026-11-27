from pathlib import Path

import pytest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
LOCAL_COMMAND_DOCS = [
    "README.md",
    "start_guide.md",
    "TESTING_GUIDE.md",
    "method.md",
    "docs/development.md",
    "docs/concepts/appworld_task_migration.md",
    "docs/testing/curated_security_scenarios.md",
    "docs/testing/cross_app_security_metrics.md",
    "CLAUDE.md",
]


@pytest.mark.parametrize("relative_path", LOCAL_COMMAND_DOCS)
def test_local_commands_use_conda_agent(relative_path: str) -> None:
    text = (REPOSITORY_ROOT / relative_path).read_text(encoding="utf-8")

    assert "conda activate agent" in text
    assert ".venv\\Scripts\\python.exe" not in text
    assert ".venv/Scripts/python.exe" not in text
    assert "C:\\Users\\86534\\.conda\\envs\\agent" not in text
