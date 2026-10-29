"""
Environment State Semantic Parsing Module.
Compares pre/post execution environment snapshots, performs incremental parsing
and semantic noise reduction, extracting only interaction attributes and data payloads.

Based on ARGUS user-space semantic extraction concepts.
"""

import copy
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class DomainData:
    """Represents a semantic data entity extracted from environment state."""
    entity_id: str
    entity_type: str  # e.g., "email", "file", "contact", "transaction"
    attributes: Dict[str, Any] = field(default_factory=dict)
    data_payload: Optional[str] = None
    source_app: str = "unknown"
    operation: str = "unknown"  # "created", "updated", "deleted", "read"
    flow_label: Optional[Dict[str, Any]] = None


@dataclass
class EnvironmentDelta:
    """Represents the semantic diff between two environment states."""
    created: List[DomainData] = field(default_factory=list)
    updated: List[DomainData] = field(default_factory=list)
    deleted: List[DomainData] = field(default_factory=list)
    accessed: List[DomainData] = field(default_factory=list)


# UI-only attributes that should be filtered during semantic parsing. Provenance
# fields such as id, timestamp, version and metadata are intentionally retained.
_NOISE_ATTRIBUTES = {
    "render_key", "ui_state", "scroll_position", "cursor_position", "animation_state",
    "loading", "visible", "selected", "focused", "hovered",
}


class EnvironmentSnapshotParser:
    """
    Parses environment states before and after a tool execution,
    extracting semantic DomainData entities and computing deltas.
    """

    def __init__(self, source_app: str = "unknown"):
        self.source_app = source_app

    def _is_noise_attr(self, key: str) -> bool:
        """Check if an attribute key is noise (purely rendering/UI related)."""
        return key.lower() in _NOISE_ATTRIBUTES

    @staticmethod
    def _entity_type_for_key(key: str) -> str:
        """Use the observed container name instead of guessing business meaning."""
        value = str(key or "").strip()
        if not value:
            return "unknown"
        return value.split("[", 1)[0] or "unknown"

    def _semantic_filter(self, data: Dict[str, Any], prefix: str = "") -> Dict[str, Any]:
        """
        Recursively filter out noise attributes from a data dictionary.
        Only keeps interaction attributes and data payloads.
        """
        filtered = {}
        for key, value in data.items():
            full_key = f"{prefix}.{key}" if prefix else key
            if self._is_noise_attr(key):
                continue
            if isinstance(value, dict):
                nested = self._semantic_filter(value, full_key)
                if nested:  # Only keep non-empty dicts
                    filtered[key] = nested
            elif isinstance(value, list):
                filtered_items = []
                for item in value:
                    if isinstance(item, dict):
                        filtered_item = self._semantic_filter(item, full_key)
                        if filtered_item:
                            filtered_items.append(filtered_item)
                    else:
                        filtered_items.append(item)
                if filtered_items:
                    filtered[key] = filtered_items
            else:
                filtered[key] = value
        return filtered

    def _extract_domain_entities(self, state: Any, operation: str = "read") -> List[DomainData]:
        """
        Extract DomainData entities from a raw environment state.
        Attempts to identify structured data (emails, files, contacts, etc.).
        """
        entities = []
        if state is None:
            return entities

        # Handle dict-like states
        if isinstance(state, dict):
            for key, value in state.items():
                entity_type = self._entity_type_for_key(key)
                if entity_type and not isinstance(value, list):
                    attrs = self._semantic_filter(value) if isinstance(value, dict) else {"value": str(value)}
                    data_payload = str(value) if isinstance(value, (str, int, float, bool)) else None
                    entities.append(DomainData(
                        entity_id=f"{self.source_app}:{key}",
                        entity_type=entity_type,
                        attributes=attrs,
                        data_payload=data_payload,
                        source_app=self.source_app,
                        operation=operation,
                    ))
                elif isinstance(value, list):
                    for i, item in enumerate(value):
                        if isinstance(item, dict):
                            item_type = self._entity_type_for_key(key)
                            if item_type:
                                attrs = self._semantic_filter(item)
                                entities.append(DomainData(
                                    entity_id=f"{self.source_app}:{key}[{i}]",
                                    entity_type=item_type,
                                    attributes=attrs,
                                    source_app=self.source_app,
                                    operation=operation,
                                ))
                else:
                    # Fallback: 即使无法推断类型，也保留原始数据内容
                    # 确保环境变更节点有实际数据可展示
                    data_str = str(value)
                    entities.append(DomainData(
                        entity_id=f"{self.source_app}:{key}",
                        entity_type="unknown",
                        attributes={"value": data_str[:200]},
                        data_payload=data_str[:500],
                        source_app=self.source_app,
                        operation=operation,
                    ))

        # Handle object with __dict__ or model_dump
        elif hasattr(state, "model_dump"):
            try:
                dumped = state.model_dump(mode="json")
            except Exception:
                dumped = state.model_dump()
            return self._extract_domain_entities(dumped, operation)
        elif hasattr(state, "__dict__"):
            return self._extract_domain_entities(state.__dict__, operation)

        return entities

    def compute_delta(self, pre_state: Any, post_state: Any) -> EnvironmentDelta:
        """
        Compute the semantic delta between pre and post execution environment states.
        
        Args:
            pre_state: The environment state before tool execution.
            post_state: The environment state after tool execution.
            
        Returns:
            An EnvironmentDelta containing created, updated, deleted, and accessed entities.
        """
        delta = EnvironmentDelta()
        
        pre_entities = self._extract_domain_entities(pre_state, "read")
        post_entities = self._extract_domain_entities(post_state, "read")
        
        pre_map = {e.entity_id: e for e in pre_entities}
        post_map = {e.entity_id: e for e in post_entities}
        
        # Find created entities (in post but not in pre)
        for entity_id, entity in post_map.items():
            if entity_id not in pre_map:
                entity.operation = "created"
                delta.created.append(entity)
        
        # Find deleted entities (in pre but not in post)
        for entity_id, entity in pre_map.items():
            if entity_id not in post_map:
                entity.operation = "deleted"
                delta.deleted.append(entity)
        
        # Find updated entities (in both but different)
        for entity_id, entity in post_map.items():
            if entity_id in pre_map:
                pre_entity = pre_map[entity_id]
                if str(pre_entity.attributes) != str(entity.attributes):
                    entity.operation = "updated"
                    delta.updated.append(entity)
                else:
                    entity.operation = "accessed"
                    delta.accessed.append(entity)
        
        return delta


def parse_environment_delta(
    pre_environment: Any,
    post_environment: Any,
    source_app: str = "unknown"
) -> EnvironmentDelta:
    """
    Convenience function to parse environment delta between two states.
    
    Args:
        pre_environment: The environment state before execution.
        post_environment: The environment state after execution.
        source_app: The source application identifier.
        
    Returns:
        An EnvironmentDelta with semantic entity changes.
    """
    parser = EnvironmentSnapshotParser(source_app=source_app)
    return parser.compute_delta(pre_environment, post_environment)


def snapshot_environment(environment: Any) -> Any:
    """Create an immutable, JSON-friendly snapshot before tool execution.

    AgentDojo tools mutate Pydantic environment objects in place. Keeping a
    reference to the old object therefore loses every update. This helper
    normalizes the environment before execution so pre/post diffs remain valid.
    """
    if environment is None:
        return None
    if hasattr(environment, "model_dump"):
        try:
            return environment.model_dump(mode="json")
        except Exception:
            try:
                return environment.model_dump()
            except Exception:
                pass
    try:
        return copy.deepcopy(environment)
    except Exception:
        return repr(environment)
