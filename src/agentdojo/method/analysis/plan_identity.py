"""Stable plan identity and integrity helpers."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any


def compute_plan_hash(plan: Mapping[str, Any]) -> str:
    material = {
        key: value
        for key, value in plan.items()
        if key not in {"plan_hash", "plan_id"}
    }
    digest = hashlib.sha256(
        json.dumps(
            material,
            sort_keys=True,
            ensure_ascii=False,
            default=str,
        ).encode("utf-8")
    ).hexdigest()
    return f"sha256:{digest}"


def plan_hash_valid(plan: Mapping[str, Any] | None) -> bool:
    if not isinstance(plan, Mapping):
        return False
    stored = str(plan.get("plan_hash", "") or "")
    return bool(stored) and stored == compute_plan_hash(plan)


def finalize_plan(plan: dict[str, Any]) -> dict[str, Any]:
    digest = compute_plan_hash(plan)
    plan["plan_id"] = f"plan_{digest.removeprefix('sha256:')[:10]}"
    plan["plan_hash"] = digest
    return plan
