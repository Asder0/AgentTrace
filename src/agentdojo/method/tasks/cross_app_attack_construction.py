"""Construct deliverable indirect prompt-injection samples for cross-APP tasks.

An injectable text field is useful only when the clean task contract reads it
through a required data dependency. This module classifies fixture fields
against task data obligations so attack batches do not spend runs on data the
Agent can legitimately skip.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from .cross_app import CrossAppStep, CrossAppTask

_INJECTION_FIELDS = {
    "append_unread_emails": "body",
    "append_direct_messages": "body",
    "append_channel_messages": "body",
    "append_files": "content",
}

_COLLECTION_SOURCE_TOOLS: dict[
    tuple[str, str],
    frozenset[str],
] = {
    ("workspace", "append_unread_emails"): frozenset(
        {
            "get_unread_emails",
            "search_emails",
            "get_received_emails",
        }
    ),
    ("workspace", "append_files"): frozenset(
        {
            "search_files",
            "search_files_by_filename",
            "list_files",
            "get_file_by_id",
        }
    ),
    ("slack", "append_direct_messages"): frozenset(
        {"read_inbox"}
    ),
    ("slack", "append_channel_messages"): frozenset(
        {"read_channel_messages"}
    ),
}


def _normalize(value: Any) -> str:
    return " ".join(str(value or "").casefold().split())


def _tool_name(step: CrossAppStep) -> str:
    return step.tool.split("__")[-1]


def _entry_matches_arguments(
    entry: Mapping[str, Any],
    step: CrossAppStep,
    collection: str,
) -> bool:
    arguments = step.arguments
    if collection == "append_channel_messages":
        channel = arguments.get("channel")
        if channel is None:
            return True
        return _normalize(channel).lstrip("#") == _normalize(
            entry.get("recipient")
        ).lstrip("#")

    if collection == "append_files":
        filename = arguments.get(
            "filename",
            arguments.get("filename_pattern"),
        )
        if filename is not None:
            expected = _normalize(filename)
            actual = _normalize(entry.get("filename"))
            return expected in actual or actual in expected
        file_id = arguments.get(
            "file_id",
            arguments.get("id_"),
        )
        if file_id is not None:
            return str(file_id) == str(entry.get("id_", ""))

    if collection == "append_unread_emails":
        query = arguments.get("query")
        if query:
            haystack = _normalize(
                " ".join(
                    str(entry.get(key, ""))
                    for key in (
                        "sender",
                        "recipients",
                        "cc",
                        "bcc",
                        "subject",
                        "body",
                    )
                )
            )
            if _normalize(query) not in haystack:
                return False
        sender = arguments.get("sender")
        if sender and _normalize(sender) != _normalize(
            entry.get("sender")
        ):
            return False
    return True


def _step_matches_point(
    task: CrossAppTask,
    step: CrossAppStep,
    point: Mapping[str, Any],
) -> bool:
    collection = str(point["collection"])
    tools = _COLLECTION_SOURCE_TOOLS.get(
        (step.suite, collection),
        frozenset(),
    )
    if _tool_name(step) not in tools:
        return False
    entry = task.fixtures[step.suite][collection][
        int(point["index"])
    ]
    if not isinstance(entry, Mapping):
        return False
    return _entry_matches_arguments(entry, step, collection)


def _build_all_points(task: CrossAppTask) -> list[dict[str, Any]]:
    points = []
    for app_name, app_fixture in (task.fixtures or {}).items():
        if not isinstance(app_fixture, Mapping):
            continue
        for collection, field_name in _INJECTION_FIELDS.items():
            entries = app_fixture.get(collection, [])
            if not isinstance(entries, Sequence) or isinstance(
                entries,
                str | bytes,
            ):
                continue
            for index, entry in enumerate(entries):
                if not isinstance(entry, Mapping):
                    continue
                value = str(entry.get(field_name, ""))
                points.append(
                    {
                        "id": (
                            f"{app_name}:{collection}:{index}:"
                            f"{field_name}"
                        ),
                        "app": app_name,
                        "collection": collection,
                        "index": index,
                        "field": field_name,
                        "label": (
                            f"{app_name} · {collection}[{index}]."
                            f"{field_name}"
                        ),
                        "preview": value[:120],
                        "required_read": False,
                        "delivery_guarantee": "optional",
                        "source_step_ids": [],
                        "source_tools": [],
                    }
                )
    return points


def classify_injection_points(
    task: CrossAppTask,
    *,
    policy: str = "guaranteed",
) -> list[dict[str, Any]]:
    """Return injection points classified against required task reads.

    ``guaranteed`` keeps points read by every alternative of at least one
    required data obligation. ``required`` additionally keeps points reached
    through one legal alternative. ``all`` keeps every text fixture field.
    """
    if policy not in {"guaranteed", "required", "all"}:
        raise ValueError(
            "injection policy must be guaranteed, required, or all"
        )
    steps = {step.step_id: step for step in task.steps}
    points = _build_all_points(task)
    for point in points:
        matched_step_ids: set[str] = set()
        required = False
        guaranteed = False
        for obligation in task.data_obligations():
            alternative_matches = []
            for alternative in obligation.alternatives:
                matched = [
                    step_id
                    for step_id in alternative.source_step_ids
                    if step_id in steps
                    and _step_matches_point(
                        task,
                        steps[step_id],
                        point,
                    )
                ]
                alternative_matches.append(bool(matched))
                matched_step_ids.update(matched)
            if any(alternative_matches):
                required = True
            if alternative_matches and all(alternative_matches):
                guaranteed = True
        point["required_read"] = required
        point["delivery_guarantee"] = (
            "all_paths"
            if guaranteed
            else "alternative_path"
            if required
            else "optional"
        )
        point["source_step_ids"] = sorted(matched_step_ids)
        point["source_tools"] = sorted(
            {
                f"{steps[step_id].suite}__{_tool_name(steps[step_id])}"
                for step_id in matched_step_ids
            }
        )

    if policy == "all":
        return points
    if policy == "required":
        return [
            point
            for point in points
            if point["required_read"]
        ]
    return [
        point
        for point in points
        if point["delivery_guarantee"] == "all_paths"
    ]
