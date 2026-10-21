"""存储视图：导出 AgentDojo 各 suite 的初始/当前环境快照并计算差异。

- 初始快照：从原版 YAML 重新加载（injection 占位符使用默认值）
- 当前快照：agent 执行过程中实际使用的环境实例（含工具调用造成的修改）
- 差异：递归比较两份快照，标记 added / removed / changed
"""

from __future__ import annotations

import time
from typing import Any, Optional

from . import mock_apps
from .app_domains import APP_DOMAINS

_ID_KEYS = ("id_", "id", "filename", "subject", "title", "name")
_MAX_CHANGES = 500

_initial_cache: dict[str, dict] = {}


def _jsonable(value: Any) -> Any:
    """把 pydantic 模型 / 日期等转换为可 JSON 序列化的结构。"""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(item) for item in value]
    if hasattr(value, "model_dump"):
        try:
            return value.model_dump(mode="json")
        except TypeError:
            return _jsonable(value.model_dump())
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)


def snapshot_env(env: Any) -> dict:
    """将环境对象导出为 JSON 友好的字典。"""
    if env is None:
        return {}
    if hasattr(env, "model_dump"):
        try:
            return env.model_dump(mode="json")
        except TypeError:
            return _jsonable(env.model_dump())
    return _jsonable(env)


def get_initial_snapshot(suite_name: str) -> dict:
    """suite 初始数据快照（缓存，因为初始 YAML 不会随执行改变）。"""
    if suite_name not in _initial_cache:
        _initial_cache[suite_name] = snapshot_env(mock_apps.get_initial_env(suite_name))
    return _initial_cache[suite_name]


def get_current_snapshot(suite_name: str) -> dict:
    """suite 当前数据快照（agent 执行后的实际状态）。"""
    return snapshot_env(mock_apps.get_current_env(suite_name))


def _list_id_key(items: list) -> Optional[str]:
    dict_items = [item for item in items if isinstance(item, dict)]
    if not dict_items:
        return None
    for key in _ID_KEYS:
        if all(key in item for item in dict_items):
            return key
    return None


def _append_change(changes: list, path: str, kind: str, before: Any, after: Any) -> None:
    if len(changes) >= _MAX_CHANGES:
        return
    changes.append({
        "path": path or "$",
        "kind": kind,
        "before": _jsonable(before),
        "after": _jsonable(after),
    })


def _diff(initial: Any, current: Any, path: str, changes: list) -> None:
    if len(changes) >= _MAX_CHANGES:
        return

    if isinstance(initial, dict) and isinstance(current, dict):
        for key in sorted(set(initial.keys()) | set(current.keys())):
            child_path = f"{path}.{key}" if path else key
            if key not in initial:
                _append_change(changes, child_path, "added", None, current[key])
            elif key not in current:
                _append_change(changes, child_path, "removed", initial[key], None)
            else:
                _diff(initial[key], current[key], child_path, changes)
        return

    if isinstance(initial, list) and isinstance(current, list):
        id_key = _list_id_key(initial) or _list_id_key(current)
        if id_key:
            initial_map = {
                str(item.get(id_key)): item
                for item in initial
                if isinstance(item, dict)
            }
            current_map = {
                str(item.get(id_key)): item
                for item in current
                if isinstance(item, dict)
            }
            for item_id in sorted(set(initial_map) | set(current_map)):
                child_path = f"{path}[{item_id}]"
                if item_id not in initial_map:
                    _append_change(changes, child_path, "added", None, current_map[item_id])
                elif item_id not in current_map:
                    _append_change(changes, child_path, "removed", initial_map[item_id], None)
                else:
                    _diff(initial_map[item_id], current_map[item_id], child_path, changes)
            return

        if initial == current:
            return
        if len(initial) > 20 or len(current) > 20:
            _append_change(
                changes,
                path,
                "changed",
                {"length": len(initial), "sample": initial[:3]},
                {"length": len(current), "sample": current[:3]},
            )
            return
        for index in range(max(len(initial), len(current))):
            child_path = f"{path}[{index}]"
            if index >= len(initial):
                _append_change(changes, child_path, "added", None, current[index])
            elif index >= len(current):
                _append_change(changes, child_path, "removed", initial[index], None)
            else:
                _diff(initial[index], current[index], child_path, changes)
        return

    if initial != current:
        _append_change(changes, path, "changed", initial, current)


def diff_snapshots(initial: dict, current: dict) -> dict:
    """比较初始与当前快照，返回 changes 列表与统计。"""
    changes: list = []
    _diff(initial, current, "", changes)
    counts = {"added": 0, "removed": 0, "changed": 0}
    for change in changes:
        counts[change["kind"]] = counts.get(change["kind"], 0) + 1
    return {
        "changes": changes,
        "counts": counts,
        "total": sum(counts.values()),
        "truncated": len(changes) >= _MAX_CHANGES,
    }


def summarize_snapshot(snapshot: dict) -> list:
    """汇总顶层字段的规模，供 suites 列表展示。"""
    summary = []
    for key, value in snapshot.items():
        entry = {"key": key, "type": type(value).__name__}
        if isinstance(value, dict):
            entry["count"] = len(value)
            entry["collections"] = {
                str(child_key): len(child_value)
                for child_key, child_value in value.items()
                if isinstance(child_value, (list, dict))
            }
        elif isinstance(value, list):
            entry["count"] = len(value)
        else:
            entry["count"] = 1
        summary.append(entry)
    return summary


def get_suite_storage(suite_name: str, include: str = "both") -> dict:
    """获取某个 suite 的存储视图数据。

    include: "both" | "initial" | "current"
    """
    if suite_name not in mock_apps.SUITE_NAMES:
        raise ValueError(f"Unknown suite: {suite_name}")

    payload: dict = {
        "suite": suite_name,
        "label": APP_DOMAINS[suite_name]["label"],
        "tools": APP_DOMAINS[suite_name]["tools"],
        "generated_at": time.strftime("%H:%M:%S"),
    }

    initial = get_initial_snapshot(suite_name)
    current = get_current_snapshot(suite_name)

    if include in ("both", "initial"):
        payload["initial"] = initial
    if include in ("both", "current"):
        payload["current"] = current
    if include == "both":
        payload["diff"] = diff_snapshots(initial, current)

    return payload


def list_suite_storage() -> list:
    """列出四个 suite 的存储概要。"""
    result = []
    for suite_name in mock_apps.SUITE_NAMES:
        initial = get_initial_snapshot(suite_name)
        current = get_current_snapshot(suite_name)
        diff = diff_snapshots(initial, current)
        result.append({
            "suite": suite_name,
            "label": APP_DOMAINS[suite_name]["label"],
            "color": APP_DOMAINS[suite_name]["color"],
            "tool_count": len(APP_DOMAINS[suite_name]["tools"]),
            "summary": summarize_snapshot(current),
            "change_total": diff["total"],
            "change_counts": diff["counts"],
            "has_changes": diff["total"] > 0,
        })
    return result
