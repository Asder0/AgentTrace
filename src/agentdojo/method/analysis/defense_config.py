"""
Defense configuration for the 4-Ring auditing layer.

Provides runtime-adjustable switches for:
- Each ring (ring_0 .. ring_3): enable / disable the whole ring.
- Hardcoded detection methods inside each ring (regex patterns,
  keyword matching, action classification tables, etc.):
  each can be enabled / disabled independently.

All switches default to enabled, preserving the original behavior.
The configuration can be updated at runtime through
``set_method_enabled`` / ``set_ring_enabled`` / ``update_config``,
or by passing per-call ``options`` to the pipeline / detection
functions (per-call options take precedence and do not mutate the
global configuration).
"""

from typing import Any, Dict

# ---------------------------------------------------------------------------
# Configuration schema
# ---------------------------------------------------------------------------

#: Per-ring hardcoded / model-based detection methods.
#: ring_0 / ring_1 -> regex + model-based injection detection
#: ring_2         -> keyword fallback + action classification table
#: ring_3         -> regex sensitive-data detection + keyword category extraction
RING_METHODS: Dict[str, Dict[str, str]] = {
    "ring_0": {
        "regex": "regex 正则匹配（安全模式 + 指令关键词二次验证）",
        "model": "DeBERTa 模型检测",
    },
    "ring_1": {
        "regex": "regex 正则匹配（安全模式 + 指令关键词并联检测）",
        "model": "DeBERTa 模型检测",
    },
    "ring_2": {
        "keyword": "keyword 关键词相似度回退（Sentence-BERT 不可用时的硬编码回退）",
        "action_class": "动作分类表（敏感/只读操作阈值表）",
    },
    "ring_3": {
        "regex": "regex 敏感数据正则检测（SENSITIVE_PATTERNS）",
        "keyword": "keyword 关键词类别提取（D_nec / D_int 硬编码关键词表）",
    },
}

#: Default configuration. All rings and all methods are enabled.
DEFAULT_CONFIG: Dict[str, Any] = {
    "ring_0": {"enabled": True, "methods": {name: True for name in RING_METHODS["ring_0"]}},
    "ring_1": {"enabled": True, "methods": {name: True for name in RING_METHODS["ring_1"]}},
    "ring_2": {"enabled": True, "methods": {name: True for name in RING_METHODS["ring_2"]}},
    "ring_3": {"enabled": True, "methods": {name: True for name in RING_METHODS["ring_3"]}},
}


def _copy_config(config: Dict[str, Any]) -> Dict[str, Any]:
    """Deep-copy a defense config dict."""
    return {
        ring: {
            "enabled": bool(cfg.get("enabled", True)),
            "methods": {m: bool(flag) for m, flag in cfg.get("methods", {}).items()},
        }
        for ring, cfg in config.items()
        if ring in RING_METHODS
    }


_CONFIG = _copy_config(DEFAULT_CONFIG)


# ---------------------------------------------------------------------------
# Accessors
# ---------------------------------------------------------------------------

def get_config() -> Dict[str, Any]:
    """Return a deep copy of the current defense configuration."""
    return _copy_config(_CONFIG)


def get_ring_config(ring: str) -> Dict[str, Any]:
    """Return the current configuration for one ring (deep copy)."""
    ring = str(ring)
    if ring not in RING_METHODS:
        raise KeyError(f"Unknown ring: {ring!r}. Expected one of {sorted(RING_METHODS)}")
    return _copy_config({ring: _CONFIG[ring]})[ring]


def is_ring_enabled(ring: str) -> bool:
    """Whether the ring itself is enabled (global defense switch not included)."""
    ring = str(ring)
    if ring not in RING_METHODS:
        raise KeyError(f"Unknown ring: {ring!r}. Expected one of {sorted(RING_METHODS)}")
    return bool(_CONFIG[ring].get("enabled", True))


def is_method_enabled(ring: str, method: str) -> bool:
    """Whether a hardcoded detection method of a ring is enabled."""
    ring = str(ring)
    if ring not in RING_METHODS:
        raise KeyError(f"Unknown ring: {ring!r}. Expected one of {sorted(RING_METHODS)}")
    if method not in RING_METHODS[ring]:
        raise KeyError(
            f"Unknown method {method!r} for {ring!r}. "
            f"Available methods: {sorted(RING_METHODS[ring])}"
        )
    return bool(_CONFIG[ring]["methods"].get(method, True))


def effective_ring_enabled(ring: str, options: Dict[str, Any] = None) -> bool:
    """
    Resolve whether a ring runs, honoring per-call ``options`` first
    and falling back to the global configuration.
    """
    if options is not None:
        override = options.get(ring, None)
        if isinstance(override, dict) and "enabled" in override:
            return bool(override["enabled"])
    return is_ring_enabled(ring)


def effective_method_enabled(ring: str, method: str, options: Dict[str, Any] = None) -> bool:
    """
    Resolve whether a hardcoded method of a ring runs, honoring
    per-call ``options`` first and falling back to the global config.

    If the whole ring is disabled in ``options`` (or globally) the
    method is also considered disabled.
    """
    ring_cfg = None
    if options is not None and isinstance(options.get(ring), dict):
        ring_cfg = options[ring]
    if ring_cfg is not None and "methods" in ring_cfg:
        method_flags = ring_cfg["methods"]
        if isinstance(method_flags, dict) and method in method_flags:
            return bool(method_flags[method])
    return is_method_enabled(ring, method)


# ---------------------------------------------------------------------------
# Mutators (runtime toggles)
# ---------------------------------------------------------------------------

def set_ring_enabled(ring: str, enabled: bool) -> None:
    """Enable or disable a whole ring at runtime."""
    ring = str(ring)
    if ring not in RING_METHODS:
        raise KeyError(f"Unknown ring: {ring!r}. Expected one of {sorted(RING_METHODS)}")
    _CONFIG[ring]["enabled"] = bool(enabled)


def set_method_enabled(ring: str, method: str, enabled: bool) -> None:
    """Enable or disable one hardcoded detection method at runtime."""
    ring = str(ring)
    if ring not in RING_METHODS:
        raise KeyError(f"Unknown ring: {ring!r}. Expected one of {sorted(RING_METHODS)}")
    if method not in RING_METHODS[ring]:
        raise KeyError(
            f"Unknown method {method!r} for {ring!r}. "
            f"Available methods: {sorted(RING_METHODS[ring])}"
        )
    _CONFIG[ring]["methods"][method] = bool(enabled)


def update_config(partial: Dict[str, Any]) -> Dict[str, Any]:
    """
    Apply a partial configuration update and return the new config.

    Accepted shape (all fields optional):
    {
        "ring_0": {"enabled": bool, "methods": {"regex": bool, "model": bool}},
        ...
    }
    """
    if not isinstance(partial, dict):
        raise TypeError("Configuration update must be a dict")
    for ring, ring_cfg in partial.items():
        ring = str(ring)
        if ring not in RING_METHODS:
            raise KeyError(
                f"Unknown ring: {ring!r}. Expected one of {sorted(RING_METHODS)}"
            )
        if not isinstance(ring_cfg, dict):
            raise TypeError(f"Configuration for {ring!r} must be a dict")
        if "enabled" in ring_cfg:
            _CONFIG[ring]["enabled"] = bool(ring_cfg["enabled"])
        methods = ring_cfg.get("methods")
        if methods is not None:
            if not isinstance(methods, dict):
                raise TypeError(f"methods for {ring!r} must be a dict")
            for method, flag in methods.items():
                if method not in RING_METHODS[ring]:
                    raise KeyError(
                        f"Unknown method {method!r} for {ring!r}. "
                        f"Available methods: {sorted(RING_METHODS[ring])}"
                    )
                _CONFIG[ring]["methods"][method] = bool(flag)
    return get_config()


def reset_config() -> Dict[str, Any]:
    """Restore all rings and methods to the default (all enabled)."""
    global _CONFIG
    _CONFIG = _copy_config(DEFAULT_CONFIG)
    return get_config()
