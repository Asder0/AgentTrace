"""Composite task definitions spanning AgentDojo APP domains."""

from .cross_app import (
    CROSS_APP_TASKS,
    CrossAppStep,
    CrossAppTask,
    get_cross_app_scenarios,
)

__all__ = [
    "CROSS_APP_TASKS",
    "CrossAppStep",
    "CrossAppTask",
    "get_cross_app_scenarios",
]
