"""环境变更视图：导出任务基线/当前环境快照并计算 Agent 行为造成的差异。

- 任务基线：测试数据准备完成、Agent 开始执行前捕获
- 当前快照：agent 执行过程中实际使用的环境实例（含工具调用造成的修改）
- 差异：递归比较两份快照，标记 added / removed / changed
"""

from __future__ import annotations

import difflib
import json
import re
import time
from typing import Any, Iterable, Optional

from ..modeling.data_sensitivity import (
    APP_LEVELS,
    entity_level,
    field_categories,
    field_level,
)
from . import mock_apps
from .app_domains import APP_DOMAINS

_ID_KEYS = ("id_", "id", "filename", "subject", "title", "name")
_MAX_CHANGES = 500

_initial_cache: dict[str, dict] = {}
_task_baselines: dict[str, dict] = {}
_task_baseline_times: dict[str, str] = {}
_INBOX_PATH_ALIASES = (
    ("inbox.initial_emails[", "inbox.emails."),
    ("inbox.received[", "inbox.emails."),
    ("inbox.sent[", "inbox.emails."),
    ("inbox.drafts[", "inbox.emails."),
)


def _container_model_ids(value: Any) -> set[int]:
    if isinstance(value, dict):
        items = value.values()
    elif isinstance(value, (list, tuple, set)):
        items = value
    else:
        return set()
    return {
        id(item)
        for item in items
        if hasattr(type(item), "model_fields")
    }


def _model_snapshot(model: Any) -> dict:
    """Serialize declared fields only and collapse alias containers."""
    fields = getattr(type(model), "model_fields", {})
    values = {
        str(name): getattr(model, name, None)
        for name in fields
    }
    item_ids = {
        name: _container_model_ids(value)
        for name, value in values.items()
    }
    omitted: set[str] = {
        name
        for name in values
        if name.startswith("initial_")
        and name.removeprefix("initial_") in values
    }
    for source, source_ids in item_ids.items():
        if not source_ids or source in omitted:
            continue
        for target, target_ids in item_ids.items():
            if target == source or target in omitted or not target_ids:
                continue
            source_is_list = isinstance(values[source], (list, tuple))
            target_is_dict = isinstance(values[target], dict)
            if (
                source_ids == target_ids
                and source_is_list
                and target_is_dict
            ):
                omitted.add(source)
                break
    return {
        name: _jsonable(value)
        for name, value in values.items()
        if name not in omitted
    }


def _jsonable(value: Any) -> Any:
    """把 pydantic 模型 / 日期等转换为可 JSON 序列化的结构。"""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(item) for item in value]
    if hasattr(type(value), "model_fields"):
        return _model_snapshot(value)
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)


def snapshot_env(env: Any) -> dict:
    """将环境对象导出为 JSON 友好的字典。"""
    if env is None:
        return {}
    if hasattr(type(env), "model_fields"):
        return _model_snapshot(env)
    return _jsonable(env)


def get_initial_snapshot(suite_name: str) -> dict:
    """suite 初始数据快照（缓存，因为初始 YAML 不会随执行改变）。"""
    if suite_name not in _initial_cache:
        _initial_cache[suite_name] = snapshot_env(mock_apps.get_initial_env(suite_name))
    return _initial_cache[suite_name]


def get_current_snapshot(suite_name: str) -> dict:
    """suite 当前数据快照（agent 执行后的实际状态）。"""
    return snapshot_env(mock_apps.get_current_env(suite_name))


def capture_task_baseline(
    suite_names: Optional[Iterable[str]] = None,
) -> None:
    """在测试数据准备完成后、Agent 执行前记录任务基线。"""
    names = tuple(suite_names or mock_apps.SUITE_NAMES)
    captured_at = time.strftime("%H:%M:%S")
    for suite_name in names:
        if suite_name not in mock_apps.SUITE_NAMES:
            continue
        _task_baselines[suite_name] = snapshot_env(
            mock_apps.get_current_env(suite_name)
        )
        _task_baseline_times[suite_name] = captured_at


def reset_task_baselines() -> None:
    _task_baselines.clear()
    _task_baseline_times.clear()


def get_task_baseline(suite_name: str) -> tuple[dict, str]:
    """返回任务基线；未显式捕获时以当前状态为基线，避免历史误报。"""
    if suite_name not in _task_baselines:
        _task_baselines[suite_name] = snapshot_env(
            mock_apps.get_current_env(suite_name)
        )
        _task_baseline_times[suite_name] = time.strftime("%H:%M:%S")
    return _task_baselines[suite_name], _task_baseline_times[suite_name]


def export_task_snapshots(
    suite_names: Optional[Iterable[str]] = None,
) -> dict[str, dict]:
    """导出任务基线与执行后快照，供历史 trace 回放。"""
    names = tuple(suite_names or mock_apps.SUITE_NAMES)
    captured_at = time.strftime("%H:%M:%S")
    snapshots: dict[str, dict] = {}
    for suite_name in names:
        if suite_name not in mock_apps.SUITE_NAMES:
            continue
        baseline, baseline_captured_at = get_task_baseline(suite_name)
        current = get_current_snapshot(suite_name)
        snapshots[suite_name] = {
            "initial": baseline,
            "current": current,
            "diff": diff_snapshots(baseline, current, suite_name),
            "baseline_captured_at": baseline_captured_at,
            "captured_at": captured_at,
            "baseline_source": "task_start_after_fixtures",
        }
    return snapshots


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


def _normalized_token(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value or "").lower()).strip("_")


def _entity_for_change(suite_name: str, path: str) -> str:
    root = _normalized_token(re.split(r"[.\[]", path or "$", maxsplit=1)[0])
    candidates = list(APP_LEVELS.get(suite_name, {}))
    if not root or not candidates:
        return root or "unknown"

    root_singular = root[:-1] if root.endswith("s") else root
    root_tokens = set(root_singular.split("_"))
    best = ""
    best_score = 0
    for entity in candidates:
        normalized = _normalized_token(entity)
        singular = normalized[:-1] if normalized.endswith("s") else normalized
        if root == normalized:
            score = 100
        elif root_singular == singular:
            score = 90
        elif normalized in root or root in normalized:
            score = 60
        else:
            entity_tokens = set(singular.split("_"))
            score = 30 * len(root_tokens & entity_tokens)
        if score > best_score:
            best = entity
            best_score = score
    return best or root


def _change_metadata(suite_name: str, path: str) -> dict:
    entity = _entity_for_change(suite_name, path)
    leaf = re.split(r"\.(?=[^.]+$)", path or "", maxsplit=1)
    field = leaf[-1] if len(leaf) > 1 else ""
    field = re.sub(r"\[\d+\]", "", field or "")
    field_path = f"$.{field}" if field else "$"
    return {
        "entity": entity,
        "field": field,
        "sensitivity": {
            "level": field_level(suite_name, entity, field_path),
            "categories": field_categories(
                suite_name,
                entity,
                field_path,
            ),
            "field_path": field_path,
            "entity": entity,
            "entity_level": entity_level(suite_name, entity),
        },
    }


def _canonical_change_path(path: str) -> str:
    value = str(path or "")
    for alias, canonical in _INBOX_PATH_ALIASES:
        if value.startswith(alias):
            suffix = value[len(alias):].replace("]", "", 1)
            return f"{canonical}{suffix}"
    return value


def _deduplicate_changes(changes: list) -> list:
    """Collapse computed/alias paths that represent the same stored object."""
    deduplicated: dict[tuple[str, str], dict] = {}
    for change in changes:
        source_path = str(change.get("path") or "")
        canonical = _canonical_change_path(source_path)
        key = (canonical, str(change.get("kind") or ""))
        candidate = {
            **change,
            "path": canonical,
            "source_paths": [source_path],
        }
        existing = deduplicated.get(key)
        if existing is None:
            deduplicated[key] = candidate
            continue
        existing["source_paths"] = list(dict.fromkeys([
            *existing.get("source_paths", []),
            source_path,
        ]))
        if (
            ".emails." in canonical
            and source_path == canonical
        ):
            deduplicated[key] = candidate
    return list(deduplicated.values())


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

        def sequence_key(value: Any) -> str:
            return json.dumps(
                _jsonable(value),
                ensure_ascii=False,
                sort_keys=True,
                default=str,
            )

        matcher = difflib.SequenceMatcher(
            a=[sequence_key(item) for item in initial],
            b=[sequence_key(item) for item in current],
            autojunk=False,
        )
        for tag, initial_start, initial_end, current_start, current_end in matcher.get_opcodes():
            if tag == "equal":
                continue
            if tag == "delete":
                for index in range(initial_start, initial_end):
                    _append_change(
                        changes,
                        f"{path}[{index}]",
                        "removed",
                        initial[index],
                        None,
                    )
                continue
            if tag == "insert":
                for index in range(current_start, current_end):
                    _append_change(
                        changes,
                        f"{path}[{index}]",
                        "added",
                        None,
                        current[index],
                    )
                continue
            paired = min(
                initial_end - initial_start,
                current_end - current_start,
            )
            for offset in range(paired):
                _diff(
                    initial[initial_start + offset],
                    current[current_start + offset],
                    f"{path}[{current_start + offset}]",
                    changes,
                )
            for index in range(initial_start + paired, initial_end):
                _append_change(
                    changes,
                    f"{path}[{index}]",
                    "removed",
                    initial[index],
                    None,
                )
            for index in range(current_start + paired, current_end):
                _append_change(
                    changes,
                    f"{path}[{index}]",
                    "added",
                    None,
                    current[index],
                )
        return

    if initial != current:
        _append_change(changes, path, "changed", initial, current)


def diff_snapshots(
    initial: dict,
    current: dict,
    suite_name: Optional[str] = None,
) -> dict:
    """比较初始与当前快照，返回 changes 列表与统计。"""
    changes: list = []
    _diff(initial, current, "", changes)
    raw_change_count = len(changes)
    changes = _deduplicate_changes(changes)
    if suite_name:
        for change in changes:
            change.update(_change_metadata(suite_name, str(change.get("path") or "")))
    counts = {"added": 0, "removed": 0, "changed": 0}
    for change in changes:
        counts[change["kind"]] = counts.get(change["kind"], 0) + 1
    return {
        "changes": changes,
        "counts": counts,
        "total": sum(counts.values()),
        "raw_change_count": raw_change_count,
        "truncated": raw_change_count >= _MAX_CHANGES,
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
        "color": APP_DOMAINS[suite_name]["color"],
        "tools": APP_DOMAINS[suite_name]["tools"],
        "generated_at": time.strftime("%H:%M:%S"),
        "baseline_source": "task_start_after_fixtures",
    }

    initial, baseline_captured_at = get_task_baseline(suite_name)
    current = get_current_snapshot(suite_name)
    payload["baseline_captured_at"] = baseline_captured_at

    if include in ("both", "initial"):
        payload["initial"] = initial
    if include in ("both", "current"):
        payload["current"] = current
    if include == "both":
        payload["diff"] = diff_snapshots(initial, current, suite_name)

    return payload


def list_suite_storage() -> list:
    """列出四个 suite 的存储概要。"""
    result = []
    for suite_name in mock_apps.SUITE_NAMES:
        initial, _ = get_task_baseline(suite_name)
        current = get_current_snapshot(suite_name)
        diff = diff_snapshots(initial, current, suite_name)
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
