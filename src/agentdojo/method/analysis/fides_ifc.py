"""
Ring 2: FIDES IFC Intent Consistency Check module.
Verifies that the LLM's actions are consistent with the user's original task,
detecting when an indirect prompt injection has influenced the agent to perform
unrelated actions.

Uses Sentence-BERT for semantic similarity comparison between user intent and actions.
Falls back to keyword matching if the model is unavailable.
"""

import re
from typing import Dict, Any, Optional, List
from .model_utils import compute_intent_similarity
from .defense_config import effective_method_enabled

# Similarity threshold below which an action is considered inconsistent
SIMILARITY_THRESHOLD = 0.25

# ============================================================
# Action Classification (comprehensive — covers all 30+ tools)
# ============================================================

# Sensitive/mutating actions — high risk, strict intent checking
SENSITIVE_ACTIONS: dict[str, str] = {
    "send_money": "banking",
    "schedule_transaction": "banking",
    "update_scheduled_transaction": "banking",
    "send_email": "email",
    "forward_email": "email",
    "reply_to_email": "email",
    "delete_file": "files",
    "share_file": "files",
    "create_file": "files",
    "append_to_file": "files",
    "create_calendar_event": "calendar",
    "cancel_calendar_event": "calendar",
    "reschedule_calendar_event": "calendar",
    "add_calendar_event_participants": "calendar",
    "update_password": "account",
    "update_user_info": "account",
}

# Read/query actions — need intent verification too (not blindly bypassed)
READ_ACTIONS: set[str] = {
    "get_balance", "get_iban",
    "get_most_recent_transactions", "get_scheduled_transactions",
    "search_emails", "search_contacts_by_name", "search_contacts_by_email",
    "get_received_emails", "get_sent_emails", "get_unread_emails", "get_draft_emails",
    "read_file", "list_files", "search_files", "search_files_by_filename", "get_file_by_id",
    "get_current_day", "get_day_calendar_events", "search_calendar_events",
    "get_user_info",
}

# Graduated similarity thresholds
READ_THRESHOLD = 0.10       # Read: only block if clearly malicious
NORMAL_THRESHOLD = 0.20     # Standard check
SENSITIVE_THRESHOLD = 0.35  # Sensitive: strict — intent must be close


class IntentTracker:
    """
    Tracks the user's original task intent and compares it with
    the LLM's subsequent actions to detect inconsistencies.
    """
    _instance = None
    
    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(IntentTracker, cls).__new__(cls, *args, **kwargs)
            cls._instance.user_task: Optional[str] = None
            cls._instance.actions_taken: List[str] = []
            cls._instance.injection_detected: bool = False
        return cls._instance
    
    def set_user_task(self, task: str):
        """Set the user's original task description."""
        self.user_task = task
        self.actions_taken = []
        self.injection_detected = False
    
    def record_action(self, action: str):
        """Record an action taken by the agent."""
        self.actions_taken.append(action)
    
    def reset(self):
        """Reset the tracker state."""
        self.user_task = None
        self.actions_taken = []
        self.injection_detected = False


def _extract_user_intent(event: dict) -> Optional[str]:
    """
    Extract the user's original intent from the event.
    Uses thought_prompt directly (it contains the original user query).
    Falls back to extracting from "Query:" prefix if present (legacy format).
    """
    thought_prompt = event.get('thought_prompt', '')
    
    if thought_prompt:
        text = str(thought_prompt)
        # Try legacy "Query:" prefix first
        if 'Query:' in text:
            match = re.search(r'Query:\s*(.+?)(?:\n|$)', text)
            if match:
                return match.group(1).strip()
        # Otherwise, use the entire thought_prompt as user intent
        return text.strip()
    
    # Fallback: try thought field
    thought = event.get('thought', '')
    if thought:
        text = str(thought)
        if 'Query:' in text:
            match = re.search(r'Query:\s*(.+?)(?:\n|$)', text)
            if match:
                return match.group(1).strip()
    
    return None


def _is_action_consistent_with_intent(
    action: str,
    user_intent: str,
    action_args: dict = None,
    threshold: float = SIMILARITY_THRESHOLD,
    options: dict = None,
) -> bool:
    """
    Check if an action is consistent with the user's stated intent.
    Uses Sentence-BERT semantic similarity with keyword fallback.
    """
    if not user_intent:
        return True  # Can't judge without intent
    
    # Compute semantic similarity using Sentence-BERT (or fallback)
    similarity = compute_intent_similarity(user_intent, action, action_args, options)
    
    # Graduated thresholds — no blind bypass for read actions
    if effective_method_enabled("ring_2", "action_class", options):
        if action in READ_ACTIONS:
            effective_threshold = READ_THRESHOLD       # 0.10 — only block clearly malicious
        elif action in SENSITIVE_ACTIONS:
            effective_threshold = SENSITIVE_THRESHOLD  # 0.35 — strict for mutations
        else:
            effective_threshold = NORMAL_THRESHOLD     # 0.20 — standard
    else:
        effective_threshold = NORMAL_THRESHOLD
    
    return similarity >= effective_threshold


def check_intent_consistency(
    event: dict,
    threshold: float = SIMILARITY_THRESHOLD,
    options: dict = None,
) -> bool:
    """
    Check if the current action is consistent with the user's original intent.
    Uses Sentence-BERT for semantic similarity comparison.
    
    Args:
        event: The event dictionary containing tool_intent, thought, etc.
        threshold: Similarity threshold (lower = more permissive).
        
    Returns:
        True if the action is consistent with user intent, False if suspicious.
    """
    tracker = IntentTracker()
    current_intent = event.get('tool_intent', '')
    action_args = event.get('inputs', {})
    
    # Extract user's original intent
    user_intent = _extract_user_intent(event)
    if user_intent:
        tracker.set_user_task(user_intent)
    elif not tracker.user_task:
        # No user intent available at all — can't judge, allow
        return True
    
    # Record the action
    tracker.record_action(current_intent)
    
    # Check consistency using semantic similarity
    return _is_action_consistent_with_intent(
        current_intent,
        tracker.user_task or '',
        action_args,
        threshold,
        options,
    )


def check_intent_consistency_with_details(
    event: dict,
    threshold: float = SIMILARITY_THRESHOLD,
    options: dict = None,
) -> dict:
    """
    Check if the current action is consistent with the user's original intent,
    returning full details for audit tracing.
    
    Returns:
        dict with keys:
            - passed: bool
            - user_intent: str or None
            - tool_intent: str
            - similarity_score: float
            - similarity_method: str ("sentence_bert", "keyword_fallback", or "no_intent")
            - threshold: float
            - action_type: str ("read_action", "sensitive_action", "normal_action")
            - is_sensitive: bool
    """
    result = {
        "passed": True,
        "user_intent": None,
        "tool_intent": event.get('tool_intent', ''),
        "similarity_score": 1.0,
        "similarity_method": "no_intent",
        "threshold": threshold,
        "action_type": "normal_action",
        "is_sensitive": False,
    }
    
    current_intent = event.get('tool_intent', '')
    action_args = event.get('inputs', {})
    
    # Extract user's original intent
    user_intent = _extract_user_intent(event)
    result["user_intent"] = user_intent
    
    if not user_intent:
        return result  # Can't judge without intent
    
    # Determine action type and effective threshold
    if effective_method_enabled("ring_2", "action_class", options):
        if current_intent in READ_ACTIONS:
            result["action_type"] = "read_action"
            effective_threshold = READ_THRESHOLD
        elif current_intent in SENSITIVE_ACTIONS:
            result["action_type"] = "sensitive_action"
            result["is_sensitive"] = True
            effective_threshold = SENSITIVE_THRESHOLD
        else:
            effective_threshold = NORMAL_THRESHOLD
    else:
        result["action_type"] = "normal_action"
        effective_threshold = NORMAL_THRESHOLD
    
    result["threshold"] = effective_threshold
    
    # Compute semantic similarity — ALL actions get checked, no bypass
    similarity = compute_intent_similarity(user_intent, current_intent, action_args, options)
    result["similarity_score"] = similarity
    
    # Determine method used
    encoder = getattr(__import__('agentdojo.method.analysis.model_utils', fromlist=['get_sentence_encoder']), 'get_sentence_encoder', lambda: None)()
    result["similarity_method"] = "sentence_bert" if encoder is not None else "keyword_fallback"
    
    # Check consistency with graduated threshold
    result["passed"] = similarity >= effective_threshold
    
    return result
