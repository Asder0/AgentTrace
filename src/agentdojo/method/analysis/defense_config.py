"""
Defense configuration for the 4-Ring auditing layer.

Provides runtime-adjustable switches for:
- Each ring (ring_0 .. ring_3): enable / disable the whole ring.
- Independently switchable methods inside each ring (prompt classification,
  untrusted-flow advisories, task scope and sensitive-egress checks).

All switches default to enabled for the lightweight runtime policy.
The configuration can be updated at runtime through
``set_method_enabled`` / ``set_ring_enabled`` / ``update_config``,
or by passing per-call ``options`` to the pipeline / detection
functions (per-call options take precedence and do not mutate the
global configuration).
"""

from typing import Any

# ---------------------------------------------------------------------------
# Configuration schema
# ---------------------------------------------------------------------------

#: Lightweight runtime methods exposed by the tracing platform.
RING_METHODS: dict[str, dict[str, str]] = {
    "ring_0": {
        "small_model": "小模型分块检测用户输入中的直接提示注入",
    },
    "ring_1": {
        "chunk_scanner": "小模型分块检测工具输出中的间接提示注入",
        "untrusted_flow": "将外部不可信数据对控制参数的影响标记为黄色提醒",
    },
    "ring_2": {
        "task_scope": ("检查工具、APP、effect、资源选择器和输出字段是否属于本次任务授权"),
    },
    "ring_3": {
        "sensitive_egress": "检查敏感类别、机密等级和外发目的地",
    },
}

#: Default configuration. All rings and all methods are enabled.
DEFAULT_CONFIG: dict[str, Any] = {
    "ring_0": {"enabled": True, "methods": {name: True for name in RING_METHODS["ring_0"]}},
    "ring_1": {"enabled": True, "methods": {name: True for name in RING_METHODS["ring_1"]}},
    "ring_2": {"enabled": True, "methods": {name: True for name in RING_METHODS["ring_2"]}},
    "ring_3": {"enabled": True, "methods": {name: True for name in RING_METHODS["ring_3"]}},
}


def _copy_config(config: dict[str, Any]) -> dict[str, Any]:
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
_DIRECT_INJECTION_MODE = "quarantine"
# Interactive executions still expose the underlying confirmation events, but
# the default workflow accepts L2 holds automatically for end-user usability.
# Requirement-resolution choices are never auto-selected because they change
# the task contract rather than merely approving an already-authorized action.
_AUTO_CONFIRMATIONS = True
_PLANNING_ENABLED = True


# ---------------------------------------------------------------------------
# Accessors
# ---------------------------------------------------------------------------


def get_config() -> dict[str, Any]:
    """Return a deep copy of the current defense configuration."""
    config = _copy_config(_CONFIG)
    config["direct_injection_mode"] = _DIRECT_INJECTION_MODE
    config["auto_confirmations"] = _AUTO_CONFIRMATIONS
    config["planning_enabled"] = _PLANNING_ENABLED
    # Backward-compatible key used by older frontends and tests.
    config["user_anchor_mode"] = _DIRECT_INJECTION_MODE
    return config


def direct_injection_mode(options: dict[str, Any] | None = None) -> str:
    """Resolve Ring 0 handling for direct prompt injection.

    ``advisory`` records risk without modifying the prompt, ``quarantine``
    replaces flagged chunks before Agent invocation, and ``strict`` blocks the
    request when any chunk exceeds the threshold.
    """
    value = (
        options.get("direct_injection_mode") or options.get("user_anchor_mode") if isinstance(options, dict) else None
    ) or _DIRECT_INJECTION_MODE
    value = str(value).lower()
    return value if value in {"advisory", "quarantine", "strict"} else "quarantine"


def user_anchor_mode(options: dict[str, Any] | None = None) -> str:
    """Backward-compatible alias for :func:`direct_injection_mode`."""
    return direct_injection_mode(options)


def set_direct_injection_mode(mode: str) -> None:
    global _DIRECT_INJECTION_MODE
    value = str(mode).lower()
    if value not in {"advisory", "quarantine", "strict"}:
        raise ValueError("direct_injection_mode must be 'advisory', 'quarantine' or 'strict'")
    _DIRECT_INJECTION_MODE = value


def set_user_anchor_mode(mode: str) -> None:
    """Backward-compatible alias for the Ring 0 mode setter."""
    set_direct_injection_mode(mode)


def auto_confirmations_enabled() -> bool:
    """Whether interactive action confirmations default to approval."""
    return _AUTO_CONFIRMATIONS


def set_auto_confirmations(enabled: bool) -> None:
    """Enable or disable automatic approval of action confirmations."""
    global _AUTO_CONFIRMATIONS
    _AUTO_CONFIRMATIONS = bool(enabled)


def planning_enabled(options: dict[str, Any] | None = None) -> bool:
    if isinstance(options, dict) and "planning_enabled" in options:
        return bool(options["planning_enabled"])
    return _PLANNING_ENABLED


def set_planning_enabled(enabled: bool) -> None:
    global _PLANNING_ENABLED
    _PLANNING_ENABLED = bool(enabled)


def get_ring_config(ring: str) -> dict[str, Any]:
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
        raise KeyError(f"Unknown method {method!r} for {ring!r}. Available methods: {sorted(RING_METHODS[ring])}")
    return bool(_CONFIG[ring]["methods"].get(method, True))


def effective_ring_enabled(
    ring: str,
    options: dict[str, Any] | None = None,
) -> bool:
    """
    Resolve whether a ring runs, honoring per-call ``options`` first
    and falling back to the global configuration.
    """
    if options is not None:
        override = options.get(ring, None)
        if isinstance(override, dict) and "enabled" in override:
            return bool(override["enabled"])
    return is_ring_enabled(ring)


def effective_method_enabled(
    ring: str,
    method: str,
    options: dict[str, Any] | None = None,
) -> bool:
    """
    Resolve whether a hardcoded method of a ring runs, honoring
    per-call ``options`` first and falling back to the global config.

    If the whole ring is disabled in ``options`` (or globally) the
    method is also considered disabled.
    """
    if not effective_ring_enabled(ring, options):
        return False
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
        raise KeyError(f"Unknown method {method!r} for {ring!r}. Available methods: {sorted(RING_METHODS[ring])}")
    _CONFIG[ring]["methods"][method] = bool(enabled)


def disable_defense_layer() -> dict[str, Any]:
    """Disable all four runtime rings and the planning defense."""
    for ring in RING_METHODS:
        set_ring_enabled(ring, False)
        for method in RING_METHODS[ring]:
            set_method_enabled(ring, method, False)
    set_planning_enabled(False)
    return get_config()


def update_config(partial: dict[str, Any]) -> dict[str, Any]:
    """
    Apply a partial configuration update and return the new config.

    Accepted shape (all fields optional):
    {
        "ring_0": {"enabled": bool, "methods": {"small_model": bool}},
        ...
    }
    """
    if not isinstance(partial, dict):
        raise TypeError("Configuration update must be a dict")
    if "direct_injection_mode" in partial:
        set_direct_injection_mode(str(partial["direct_injection_mode"]))
    if "user_anchor_mode" in partial:
        set_user_anchor_mode(str(partial["user_anchor_mode"]))
    if "auto_confirmations" in partial:
        set_auto_confirmations(bool(partial["auto_confirmations"]))
    if "planning_enabled" in partial:
        set_planning_enabled(bool(partial["planning_enabled"]))
    for ring, ring_cfg in partial.items():
        if ring in {
            "user_anchor_mode",
            "direct_injection_mode",
            "auto_confirmations",
            "planning_enabled",
        }:
            continue
        ring = str(ring)
        if ring not in RING_METHODS:
            raise KeyError(f"Unknown ring: {ring!r}. Expected one of {sorted(RING_METHODS)}")
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
                        f"Unknown method {method!r} for {ring!r}. Available methods: {sorted(RING_METHODS[ring])}"
                    )
                _CONFIG[ring]["methods"][method] = bool(flag)
    return get_config()


def reset_config() -> dict[str, Any]:
    """Restore all rings and methods to the default (all enabled)."""
    global _CONFIG, _DIRECT_INJECTION_MODE, _AUTO_CONFIRMATIONS
    global _PLANNING_ENABLED
    _CONFIG = _copy_config(DEFAULT_CONFIG)
    _DIRECT_INJECTION_MODE = "quarantine"
    _AUTO_CONFIRMATIONS = True
    _PLANNING_ENABLED = True
    return get_config()
