"""Compatibility exports for the centralized APP catalog."""

from ..app_domains import (
    APP_DOMAINS,
    LEGACY_MODULE_DOMAINS,
    SUITE_DOMAINS,
    SYSTEM_APP,
    domain_for_module,
    domain_for_tool,
    infer_suite,
    normalize_graph,
    normalize_graph_nodes,
)

__all__ = [
    "APP_DOMAINS",
    "LEGACY_MODULE_DOMAINS",
    "SUITE_DOMAINS",
    "SYSTEM_APP",
    "domain_for_module",
    "domain_for_tool",
    "infer_suite",
    "normalize_graph",
    "normalize_graph_nodes",
]
