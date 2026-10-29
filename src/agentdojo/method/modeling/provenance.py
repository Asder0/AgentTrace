"""Backward provenance queries used by graph-enhanced risk decisions."""

from __future__ import annotations

from collections import deque
from typing import Any, Iterable, Mapping

import networkx as nx

from .labels import is_tainted


def node_label(graph: nx.Graph, node_id: str) -> dict[str, Any] | None:
    if node_id not in graph:
        return None
    data = graph.nodes[node_id]
    label = data.get("flow_label")
    if isinstance(label, Mapping):
        return dict(label)
    legacy = {
        "integrity": data.get("integrity"),
        "confidentiality": data.get("confidentiality"),
    }
    if isinstance(legacy["integrity"], Mapping):
        return {
            "integrity": dict(legacy["integrity"]),
            "confidentiality": dict(legacy["confidentiality"] or {}),
            "influence": {"data": True, "control": False},
        }
    return None


def backward_ancestors(
    graph: nx.Graph,
    start_id: str,
    *,
    max_depth: int = 32,
) -> tuple[dict[str, int], list[tuple[str, str, str]]]:
    """Return bounded ancestor distances and traversed edges.

    The edge tuple format is ``(source, target, relation)`` and preserves the
    graph direction so callers can explain provenance to users.
    """
    if start_id not in graph:
        return {}, []
    distances: dict[str, int] = {start_id: 0}
    traversed: list[tuple[str, str, str]] = []
    queue: deque[str] = deque([start_id])
    while queue:
        node = queue.popleft()
        depth = distances[node]
        if depth >= max_depth:
            continue
        for predecessor in graph.predecessors(node):
            if predecessor not in distances:
                distances[predecessor] = depth + 1
                queue.append(predecessor)
            relation = ""
            if graph.is_multigraph():
                relations = [
                    str(edge_data.get("relation", ""))
                    for edge_data in graph.get_edge_data(
                        predecessor, node, default={}
                    ).values()
                ]
                relation = "|".join(sorted(set(filter(None, relations))))
            else:
                relation = str(
                    graph.get_edge_data(predecessor, node, default={}).get(
                        "relation", ""
                    )
                )
            edge = (predecessor, node, relation)
            if edge not in traversed:
                traversed.append(edge)
    return distances, traversed


def taint_ancestors(
    graph: nx.Graph,
    start_id: str,
    *,
    max_depth: int = 32,
) -> dict[str, Any]:
    distances, edges = backward_ancestors(graph, start_id, max_depth=max_depth)
    tainted_nodes = [
        node_id
        for node_id in distances
        if is_tainted(node_label(graph, node_id))
        or bool(graph.nodes[node_id].get("blocked"))
    ]
    roots: list[str] = []
    for node_id in tainted_nodes:
        label = node_label(graph, node_id) or {}
        roots.extend(
            str(item)
            for item in (label.get("integrity") or {}).get("taint_roots", [])
            if item
        )
    return {
        "start_id": start_id,
        "distances": distances,
        "edges": edges,
        "tainted_node_ids": tainted_nodes,
        "taint_roots": sorted(set(roots)),
        "has_taint": bool(tainted_nodes),
    }


def shortest_risk_path(
    graph: nx.Graph,
    start_id: str,
    tainted_node_id: str,
) -> list[str]:
    if start_id not in graph or tainted_node_id not in graph:
        return []
    try:
        return nx.shortest_path(graph, tainted_node_id, start_id)
    except (nx.NetworkXNoPath, nx.NodeNotFound):
        return []


def collect_source_ids(
    graph: nx.Graph,
    node_ids: Iterable[str],
) -> list[str]:
    result: set[str] = set()
    for node_id in node_ids:
        label = node_label(graph, node_id) or {}
        for source_id in (label.get("confidentiality") or {}).get("source_ids", []):
            result.add(str(source_id))
        for source_id in (label.get("integrity") or {}).get("taint_roots", []):
            result.add(str(source_id))
    return sorted(result)
