"""
Ring 3: AgentRaft DOE (Data Over-Exposure) data mitigation logic.
Implements the formal DOE formula:
    D_OE = (D_trans \\ (D_nec U D_int)) n D_total

where:
  D_nec   = data necessary for the tool's intended function (from tool intent)
  D_int   = data the user explicitly intended to access (from user intent)
  D_trans = data actually transmitted in tool output
  D_OE    = over-exposed data that should be redacted

Uses NER model (dslim/bert-base-NER) + regex patterns to detect sensitive data.
Only data whose category lies outside (D_nec U D_int) is redacted.
Falls back to regex-only if model unavailable.
"""
from .model_utils import (
    redact_sensitive_data,
    detect_sensitive_data,
    extract_necessary_categories,
    extract_intended_categories,
    redact_only_overexposed,
    _get_item_category,
)


def _compute_allowed_categories(
    event_complete: dict,
    nec_data: set = None,
    intent_data: set = None,
) -> set:
    """Compute D_nec U D_int = the set of allowed data categories.

    Combines tool-necessary categories and user-intended categories.
    If either is None, falls back to extracting from the event.
    """
    tool_intent = event_complete.get("tool_intent", "")

    if nec_data is None:
        d_nec = extract_necessary_categories(tool_intent)
    else:
        d_nec = nec_data

    if intent_data is None:
        thought_prompt = event_complete.get("thought_prompt", "")
        d_int = extract_intended_categories(thought_prompt)
    else:
        d_int = intent_data

    allowed = d_nec | d_int
    return allowed


def apply_doe_mitigation(
    event_complete: dict,
    result: any,
    nec_data: set = None,
    intent_data: set = None,
) -> any:
    """
    D_OE = (D_trans \\ (D_nec U D_int)) n D_total
    Removes over-exposed sensitive data from tool outputs.
    
    Uses NER model to detect entities like:
    - Credentials (passwords, tokens, API keys)
    - Personal info (emails, names)
    - Financial data (credit cards, SSNs)
    - Known secrets
    
    Falls back to regex patterns if NER model is unavailable.
    """
    if not isinstance(result, str):
        return result

    allowed = _compute_allowed_categories(event_complete, nec_data, intent_data)
    sanitized = redact_only_overexposed(result, allowed)

    if sanitized != result:
        redacted_items = set()
        for item in detect_sensitive_data(result):
            cat = _get_item_category(item["label"])
            if cat not in allowed:
                redacted_items.add(cat)
        print(
            f"AgentRaft: Redacted {len(redacted_items)} over-exposed data category(-ies) "
            f"from {event_complete.get('tool_intent', 'unknown')} output. "
            f"D_OE={redacted_items} | Allowed: {allowed}"
        )

    return sanitized


def apply_doe_mitigation_with_details(
    event_complete: dict,
    result: any,
    nec_data: set = None,
    intent_data: set = None,
) -> dict:
    """
    Apply DOE mitigation and return full details for audit tracing.

    Args:
        event_complete: Tool call event with metadata.
        result: The tool output string to sanitize.
        nec_data: Set of data categories necessary for the tool (D_nec).
        intent_data: Set of data categories the user intended (D_int).

    Returns:
        dict with keys:
            - executed: bool
            - redacted: bool
            - original_result: str or None
            - sanitized_result: any
            - sensitive_items_found: int
            - items: list of detected sensitive items
            - d_nec: sorted list of necessary categories
            - d_int: sorted list of intended categories
            - d_oe: sorted list of over-exposed categories that were redacted
            - formula_summary: str
    """
    details = {
        "executed": True,
        "redacted": False,
        "original_result": None,
        "sanitized_result": result,
        "sensitive_items_found": 0,
        "items": [],
        "d_nec": [],
        "d_int": [],
        "d_oe": [],
        "formula_summary": "",
    }

    if not isinstance(result, str):
        details["executed"] = False
        return details

    # Compute D_nec and D_int
    tool_intent = event_complete.get("tool_intent", "")
    if nec_data is None:
        d_nec = extract_necessary_categories(tool_intent)
    else:
        d_nec = nec_data
    if intent_data is None:
        thought_prompt = event_complete.get("thought_prompt", "")
        d_int = extract_intended_categories(thought_prompt)
    else:
        d_int = intent_data
    allowed = d_nec | d_int

    details["d_nec"] = sorted(d_nec)
    details["d_int"] = sorted(d_int)

    # Detect all sensitive data
    sensitive_items = detect_sensitive_data(result)
    details["items"] = sensitive_items
    details["sensitive_items_found"] = len(sensitive_items)
    details["original_result"] = result[:200] if len(result) > 200 else result

    # Apply category-aware redaction
    sanitized = redact_only_overexposed(result, allowed)
    details["sanitized_result"] = sanitized

    # Compute D_OE (over-exposed categories)
    d_oe = set()
    for item in sensitive_items:
        cat = _get_item_category(item["label"])
        if cat not in allowed:
            d_oe.add(cat)
    details["d_oe"] = sorted(d_oe)

    if sanitized != result:
        details["redacted"] = True

    details["formula_summary"] = (
        f"D_nec={d_nec} | D_int={d_int} | "
        f"D_OE={d_oe} | redacted={details['redacted']}"
    )

    return details
