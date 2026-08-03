"""
Ring 1: SkillProbe Prompt Injection Detection module.
Detects indirect prompt injection in tool outputs using:
1. DeBERTa-based text classification model (primary)
2. Regex patterns (fallback)

Based on SkillProbe's risk topology analysis, but focused on detecting
injection payloads in tool outputs rather than blocking operation sequences.

关键设计原则：
- Ring 1 只阻断包含明确指令性内容的工具输出（真正的提示注入）
- 对于结构化数据（交易记录、用户信息等），即使模型给出低分，也视为安全
- 二次验证机制：模型判定为注入后，还需检查是否包含指令性关键词
"""

import re
from typing import Optional, Tuple
from .model_utils import detect_prompt_injection

# Safe patterns that should NOT be flagged as injection (false positive reduction)
# These are checked BEFORE the model to avoid misclassifying benign content
SAFE_PATTERNS = [
    r"(?i)ignore\s+(the\s+)?(file|email|message|attachment|request|notification)",  # User legitimately ignoring something
    r"(?i)do\s+not\s+(worry|hesitate|forget)",  # Common conversational phrase
    r"(?i)please\s+ignore",  # Polite request to disregard
    r"(?i)you\s+can\s+ignore",  # Informational
]

# 指令性关键词模式：真正的提示注入必须包含这些指令性内容
# 用于并联检测（与 DeBERTa 并行，任一命中即阻断）
# 已扩展 your/the 等变体以覆盖更广泛的攻击文本
INSTRUCTION_PATTERNS = [
    # --- ignore/override patterns (with your/the/all variants) ---
    r"(?i)ignore\s+(all\s+)?(your\s+)?(previous|prior|above)\s+(instructions|directives|commands|prompts|messages)",
    r"(?i)disregard\s+(all\s+)?(your\s+)?(previous|prior|above)\s+(instructions|directives|commands|prompts)",
    r"(?i)forget\s+(all\s+)?(your\s+)?(previous|prior|above)\s+(instructions|directives|commands)",
    # --- new/override role assignments ---
    r"(?i)(new|updated|modified)\s+(system\s+)?prompt",
    r"(?i)you\s+are\s+(now\s+)?(a\s+)?(new\s+)?(AI|assistant|agent|bot|model)",
    r"(?i)act\s+as\s+(if\s+)?(you\s+are\s+)?(a\s+)?(new\s+)?",
    # --- importance flags ---
    r"(?i)this\s+is\s+(an\s+)?(important|urgent|critical)\s+(instruction|message|update|directive)",
    r"(?i)this\s+is\s+(an\s+)?(important|urgent|security)\s+(test|check|update)",
    # --- mandatory commands ---
    r"(?i)you\s+must\s+(now\s+)?(do|perform|execute|complete|follow|obey)",
    r"(?i)do\s+not\s+(follow|obey|listen|adhere|comply)",
    r"(?i)do\s+(send|forward|transfer|copy|delete)\s",
    r"(?i)from\s+now\s+on",
    r"(?i)your\s+(new\s+)?(task|mission|goal|purpose|objective)\s+is",
    # --- content manipulation ---
    r"(?i)say\s+(the\s+)?(word|phrase|text|message)\s+",
    r"(?i)repeat\s+(after\s+me|the\s+following|this\s+exact)",
    r"(?i)output\s+(the\s+)?(word|phrase|text|message|following)",
    r"(?i)start\s+(your\s+)?(response|answer|message)\s+(with|by)",
    r"(?i)end\s+(your\s+)?(response|answer|message)\s+(with|by)",
    r"(?i)include\s+(the\s+)?(word|phrase|text|following)\s+",
    r"(?i)do\s+not\s+(include|show|display|mention|reveal|tell|say)",
    r"(?i)never\s+(mention|reveal|tell|say|disclose|show)",
    # --- unauthorized actions ---
    r"(?i)send\s+(this\s+)?(email|message|information|data|text|transaction)\s+to",
    r"(?i)transfer\s+(money|funds|payment|the\s+money|the\s+funds|\$[\d,]+)\s+to",
    r"(?i)TODO:\s*(send|transfer|forward|delete|copy|share)\s",
]


def check_tool_output_for_injection(output: str, threshold: float = 0.1) -> bool:
    """
    Check if a tool output contains indirect prompt injection patterns.
    Uses DeBERTa model AND regex patterns in PARALLEL (either one detects → block).
    
    检测逻辑（并联架构 — 任一命中即阻断）：
    1. 先检查安全白名单模式，命中则直接放行
    2. DeBERTa 模型检测 + INSTRUCTION_PATTERNS 正则检测 并行执行
    3. 任一检测到注入 → 阻断
    4. 两者都未检测到 → 放行
    
    Args:
        output: The tool output string to check.
        threshold: Safety score threshold (lower = more sensitive).
        
    Returns:
        True if the output is safe (no injection detected), False if injection is detected.
    """
    if not output or not isinstance(output, str):
        return True  # Empty or non-string outputs are safe
    
    # First check safe patterns to avoid false positives
    for safe_pattern in SAFE_PATTERNS:
        if re.search(safe_pattern, output):
            return True  # Matches a known safe pattern
    
    # Parallel detection: DeBERTa model
    model_injection_detected, safety_score = detect_prompt_injection(output, threshold)
    
    # Parallel detection: regex instruction patterns (runs independently, not gated by model)
    regex_injection_detected = False
    for instr_pattern in INSTRUCTION_PATTERNS:
        if re.search(instr_pattern, output):
            regex_injection_detected = True
            break
    
    # Either detection method catches injection → block
    if model_injection_detected or regex_injection_detected:
        return False  # Injection detected by model or regex
    
    return True  # No injection detected


def check_tool_output_for_injection_with_details(output: str, threshold: float = 0.1) -> dict:
    """
    Check if a tool output contains indirect prompt injection, returning full details.
    
    Returns:
        dict with keys:
            - passed: bool (True = safe, False = injection detected)
            - safety_score: float
            - detection_method: str ("deberta_model", "safe_pattern", "regex_fallback", or "empty_output")
            - output_length: int
            - matched_pattern: str or None (if regex fallback matched)
    """
    result = {
        "passed": True,
        "safety_score": 1.0,
        "detection_method": "empty_output",
        "output_length": 0,
        "matched_pattern": None,
    }
    
    if not output or not isinstance(output, str):
        return result
    
    result["output_length"] = len(output)
    
    # First check safe patterns to avoid false positives
    for safe_pattern in SAFE_PATTERNS:
        if re.search(safe_pattern, output):
            result["safety_score"] = 1.0
            result["detection_method"] = "safe_pattern"
            result["matched_pattern"] = safe_pattern
            return result
    
    # Parallel detection: DeBERTa model
    model_injection_detected, safety_score = detect_prompt_injection(output, threshold)
    result["safety_score"] = safety_score
    
    # Parallel detection: regex instruction patterns (runs independently)
    regex_injection_detected = False
    for instr_pattern in INSTRUCTION_PATTERNS:
        if re.search(instr_pattern, output):
            regex_injection_detected = True
            result["matched_pattern"] = instr_pattern
            break
    
    # Either detection method catches injection → block (parallel OR logic)
    if regex_injection_detected and model_injection_detected:
        result["passed"] = False
        result["detection_method"] = "deberta_and_regex"
    elif regex_injection_detected:
        result["passed"] = False
        result["detection_method"] = "regex_pattern"
    elif model_injection_detected:
        result["passed"] = False
        result["detection_method"] = "deberta_model"
    else:
        result["detection_method"] = "deberta_model"
    
    return result
