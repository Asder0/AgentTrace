"""
Ring 0: Prompt Injection Detection for initial user prompt.
检测用户提交的初始 prompt 中是否包含注入指令。
复用 Ring 1 的 DeBERTa 检测模型 + 二次验证机制。

与 Ring 1 (skillprobe_topology.py) 的区别：
- Ring 0：检测 LLM **接收到的 prompt**（用户输入 + 系统消息）
- Ring 1：检测工具函数的**输出结果**（可能包含间接注入）

两者使用相同的检测模型 (protectai/deberta-v3-base-prompt-injection-v2)，
但检测阈值和二次验证策略不同：
- Ring 0：阈值更严格（0.3），因为 prompt 中的注入直接威胁初始安全边界
- Ring 1：阈值较宽松（0.1），配合二次验证避免误判结构化数据
"""

import re
from typing import Tuple
from .model_utils import detect_prompt_injection

# Ring 0 的检测阈值（比 Ring 1 更严格）
# 因为 prompt 注入直接威胁初始安全边界，宁可误报不可漏报
PROMPT_INJECTION_THRESHOLD = 0.3

# 安全模式：这些内容在 prompt 中出现时不应判定为注入
# 避免将正常的任务描述误判为注入
SAFE_PROMPT_PATTERNS = [
    r"(?i)ignore\s+(the\s+)?(file|email|message|attachment|request|notification)",  # 用户正常要求忽略某物
    r"(?i)do\s+not\s+(worry|hesitate|forget)",  # 常见对话用语
    r"(?i)please\s+ignore",  # 礼貌请求
    r"(?i)you\s+can\s+ignore",  # 告知性内容
    r"(?i)check\s+(if|whether|for)\s+",  # 检查类任务
    r"(?i)make\s+sure\s+(that\s+)?(you\s+)?(don't|do\s+not)\s+",  # 提醒类任务
]

# 指令性关键词模式：真正的 prompt 注入必须包含这些
# 用于二次验证，避免误判
INSTRUCTION_PATTERNS = [
    r"(?i)ignore\s+(all\s+)?(your\s+)?(previous|prior|above)\s+(instructions|directives|commands|prompts|messages)",
    r"(?i)disregard\s+(all\s+)?(previous|prior|above)\s+(instructions|directives|commands|prompts)",
    r"(?i)(new|updated|modified)\s+(system\s+)?prompt",
    r"(?i)you\s+are\s+(now\s+)?(a\s+)?(new\s+)?(AI|assistant|agent|bot|model)",
    r"(?i)this\s+is\s+(an\s+)?(important|urgent|critical)\s+(instruction|message|update|directive)",
    r"(?i)you\s+must\s+(now\s+)?(do|perform|execute|complete|follow|obey)",
    r"(?i)do\s+not\s+(follow|obey|listen|adhere|comply)",
    r"(?i)forget\s+(all\s+)?(previous|prior|above)\s+(instructions|directives|commands)",
    r"(?i)remember\s+(this\s+)?(new\s+)?(instruction|rule|command)",
    r"(?i)act\s+as\s+(if\s+)?(you\s+are\s+)?(a\s+)?(new\s+)?",
    r"(?i)from\s+now\s+on",
    r"(?i)your\s+(new\s+)?(task|mission|goal|purpose|objective)\s+is",
    r"(?i)say\s+(the\s+)?(word|phrase|text|message)\s+",
    r"(?i)repeat\s+(after\s+me|the\s+following|this\s+exact)",
    r"(?i)output\s+(the\s+)?(word|phrase|text|message|following)",
    r"(?i)start\s+(your\s+)?(response|answer|message)\s+(with|by)",
    r"(?i)end\s+(your\s+)?(response|answer|message)\s+(with|by)",
    r"(?i)include\s+(the\s+)?(word|phrase|text|following)\s+",
    r"(?i)do\s+not\s+(include|show|display|mention|reveal|tell|say)",
    r"(?i)never\s+(mention|reveal|tell|say|disclose|show)",
    r"(?i)send\s+(this\s+)?(email|message|information|data|text)\s+to",
    r"(?i)transfer\s+(money|funds|payment|the\s+money|the\s+funds)\s+to",
]


def check_prompt_for_injection(prompt: str, threshold: float = PROMPT_INJECTION_THRESHOLD) -> bool:
    """
    检查用户提交的 prompt 是否包含注入指令。
    
    检测逻辑（二次验证）：
    1. 先检查 SAFE_PROMPT_PATTERNS，匹配则直接放行
    2. 用 DeBERTa 模型检测 prompt 是否包含注入内容
    3. 模型判定为注入后，再用 INSTRUCTION_PATTERNS 检查是否包含指令性关键词
    4. 只有两者都满足才判定为注入
    
    Args:
        prompt: 用户输入的 prompt 文本。
        threshold: 安全分数阈值（越低越敏感）。
        
    Returns:
        True 如果 prompt 安全（无注入），False 如果检测到注入。
    """
    if not prompt or not isinstance(prompt, str):
        return True  # 空 prompt 视为安全
    
    # 先检查安全模式，避免误判
    for safe_pattern in SAFE_PROMPT_PATTERNS:
        if re.search(safe_pattern, prompt):
            return True
    
    # 使用模型检测
    is_injection, safety_score = detect_prompt_injection(prompt, threshold)
    
    if is_injection:
        # 二次验证：模型判定为注入后，还需检查是否包含指令性关键词
        for instr_pattern in INSTRUCTION_PATTERNS:
            if re.search(instr_pattern, prompt):
                return False  # 模型 + 指令关键词双重确认 → 真正的注入
        # 模型判定为注入，但不含指令关键词 → 视为误判，放行
        return True
    
    return True  # 未检测到注入


def check_prompt_for_injection_with_details(prompt: str, threshold: float = PROMPT_INJECTION_THRESHOLD) -> dict:
    """
    检查 prompt 是否包含注入，返回完整详情用于审计追踪。
    
    Returns:
        dict with keys:
            - passed: bool (True = safe, False = injection detected)
            - safety_score: float
            - detection_method: str
            - prompt_length: int
            - matched_pattern: str or None
    """
    result = {
        "passed": True,
        "safety_score": 1.0,
        "detection_method": "empty_prompt",
        "prompt_length": 0,
        "matched_pattern": None,
    }
    
    if not prompt or not isinstance(prompt, str):
        return result
    
    result["prompt_length"] = len(prompt)
    
    # 先检查安全模式
    for safe_pattern in SAFE_PROMPT_PATTERNS:
        if re.search(safe_pattern, prompt):
            result["safety_score"] = 1.0
            result["detection_method"] = "safe_pattern"
            result["matched_pattern"] = safe_pattern
            return result
    
    # 使用模型检测
    is_injection, safety_score = detect_prompt_injection(prompt, threshold)
    result["safety_score"] = safety_score
    
    if is_injection:
        # 二次验证
        has_instruction = False
        for instr_pattern in INSTRUCTION_PATTERNS:
            if re.search(instr_pattern, prompt):
                has_instruction = True
                result["matched_pattern"] = instr_pattern
                break
        
        if has_instruction:
            result["passed"] = False
            result["detection_method"] = "deberta_model"
        else:
            result["passed"] = True
            result["detection_method"] = "deberta_model_with_secondary_check"
    else:
        result["detection_method"] = "deberta_model"
    
    return result
