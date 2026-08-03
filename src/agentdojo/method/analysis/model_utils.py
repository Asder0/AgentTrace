"""
Model utilities for the Analysis Pipeline.
Provides lazy-loaded model wrappers for:
1. Prompt Injection Detection (DeBERTa-based)
2. Intent Consistency (Sentence-BERT)
3. Sensitive Data Detection (NER)
4. Anomalous Parameter Detection

All models are loaded on first use and cached for subsequent calls.
"""

import os
import re
import logging
from typing import Optional, Tuple, List, Any
from functools import lru_cache

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# HuggingFace network configuration (auto-mirror for mainland China)
# ---------------------------------------------------------------------------


def _configure_hf_network():
    """Module-level HF network setup.

    Priority:
    1. User-set HF_ENDPOINT / HF_HUB_ENDPOINT — respect user's choice.
    2. AGENTDOJO_LOCAL_MODELS=true — offline mode (cached models only).
    3. Default — auto-set https://hf-mirror.com (China mainland mirror).
    """
    if os.getenv("HF_ENDPOINT") or os.getenv("HF_HUB_ENDPOINT"):
        ep = os.getenv("HF_ENDPOINT") or os.getenv("HF_HUB_ENDPOINT")
        logger.info(f"HF endpoint (user): {ep}")
        return

    if os.getenv("AGENTDOJO_LOCAL_MODELS", "").lower() in ("1", "true", "yes"):
        os.environ["HF_HUB_OFFLINE"] = "1"
        os.environ["TRANSFORMERS_OFFLINE"] = "1"
        logger.info("Offline mode: using cached models only")
        return

    mirror = "https://hf-mirror.com"
    os.environ["HF_ENDPOINT"] = mirror
    os.environ["HF_HUB_ENDPOINT"] = mirror
    logger.info(f"HF mirror: {mirror}")


_configure_hf_network()

# ---------------------------------------------------------------------------
# Global model cache (lazy loading)
# ---------------------------------------------------------------------------

_model_cache = {}


def _get_device():
    """Determine the best available device."""
    try:
        import torch
        if torch.cuda.is_available():
            return "cuda"
        elif hasattr(torch, "backends") and hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
            return "mps"
    except ImportError:
        pass
    return "cpu"


# ---------------------------------------------------------------------------
# Ring 1: Prompt Injection Detection (DeBERTa)
# ---------------------------------------------------------------------------

def _is_offline_mode() -> bool:
    """Check if offline-only mode is active."""
    return os.getenv("AGENTDOJO_LOCAL_MODELS", "").lower() in ("1", "true", "yes")


def get_pi_detector():
    """
    Get or create the prompt injection detection pipeline.
    Uses protectai/deberta-v3-base-prompt-injection-v2 (same as AgentDojo's TransformersBasedPIDetector).
    """
    if "pi_detector" not in _model_cache:
        try:
            from transformers import pipeline
            device = _get_device()
            kwargs = dict(task="text-classification", model="protectai/deberta-v3-base-prompt-injection-v2", device=device)
            if _is_offline_mode():
                kwargs["local_files_only"] = True
                _model_cache["pi_detector"] = pipeline(**kwargs)
            else:
                try:
                    # 优先使用本地缓存，避免每次启动都向镜像发网络校验而卡住
                    _model_cache["pi_detector"] = pipeline(**kwargs, local_files_only=True)
                except Exception:
                    # 本地缓存缺失/不完整时才联网下载
                    _model_cache["pi_detector"] = pipeline(**kwargs)
            logger.info(f"PI detector loaded on {device}")
        except ImportError as e:
            logger.warning(f"Transformers not available, falling back to regex: {e}")
            _model_cache["pi_detector"] = None
        except Exception as e:
            logger.warning(f"Failed to load PI detector model, falling back to regex: {e}")
            _model_cache["pi_detector"] = None
    return _model_cache["pi_detector"]


def _token_aware_truncate(text: str, max_tokens: int = 480) -> str:
    """Token-aware truncation: use tokenizer to truncate at max_tokens.
    
    If the text fits within max_tokens, return as-is. Otherwise keep
    head (1/4 budget) + tail (3/4 budget). This ensures injection payloads
    typically placed at the end of long tool outputs are not lost.
    
    Falls back to rough character-based truncation (~4 chars/token) if
    the tokenizer is unavailable.
    """
    try:
        detector = get_pi_detector()
        if detector is None or not hasattr(detector, 'tokenizer'):
            return text[:max_tokens * 4]
        tokenizer = detector.tokenizer
        tokens = tokenizer.encode(text, add_special_tokens=True)
        # Reserve room for special tokens (CLS + SEP ≈ 2 tokens)
        effective_max = max_tokens - 2
        if len(tokens) <= effective_max:
            return text
        head_budget = effective_max // 4
        tail_budget = effective_max - head_budget
        head_text = tokenizer.decode(tokens[:head_budget], skip_special_tokens=False)
        tail_text = tokenizer.decode(tokens[-tail_budget:], skip_special_tokens=False)
        return head_text + "\n...\n" + tail_text
    except Exception:
        return text[:max_tokens * 4]


def detect_prompt_injection(text: str, threshold: float = 0.5) -> Tuple[bool, float]:
    """
    Detect if text contains a prompt injection.
    
    Returns:
        Tuple of (is_injection: bool, confidence_score: float)
        confidence_score is the safety score (higher = safer)
    """
    if not text or not isinstance(text, str):
        return False, 1.0
    
    detector = get_pi_detector()
    
    if detector is not None:
        try:
            # Token-aware truncation: keep max ~480 tokens, head+tail split
            # to ensure injection payloads at the end of long text are not lost
            truncated = _token_aware_truncate(text)
            result = detector(truncated)[0]
            safe_label = "SAFE"
            safety_score = result["score"] if result["label"] == safe_label else 1 - result["score"]
            is_injection = safety_score < threshold
            return is_injection, safety_score
        except Exception as e:
            logger.warning(f"PI detector inference failed: {e}")
            # Fall through to regex fallback
    
    # Fallback: regex-based detection
    return _regex_pi_fallback(text)


def _regex_pi_fallback(text: str) -> Tuple[bool, float]:
    """Regex-based prompt injection detection fallback."""
    injection_patterns = [
        r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|directives|commands|prompts)",
        r"(?i)disregard\s+(all\s+)?(previous|prior|above)\s+(instructions|directives|commands|prompts)",
        r"(?i)(new|updated|modified)\s+(system\s+)?prompt",
        r"(?i)you\s+are\s+(now\s+)?(a\s+)?(new\s+)?(AI|assistant|agent|bot)",
        r"(?i)send\s+(this\s+)?(email|message|information|data)\s+to",
        r"(?i)transfer\s+(money|funds|payment)\s+to",
        r"(?i)this\s+is\s+(an\s+)?(important|urgent|critical)\s+(instruction|message|update)",
        r"(?i)you\s+must\s+(now\s+)?(do|perform|execute|complete)",
    ]
    
    for pattern in injection_patterns:
        if re.search(pattern, text):
            return True, 0.3  # Low confidence, but flagged
    
    return False, 0.95  # Probably safe


# ---------------------------------------------------------------------------
# Ring 2: Intent Consistency (Sentence-BERT)
# ---------------------------------------------------------------------------

def get_sentence_encoder():
    """
    Get or create the Sentence-BERT encoder for intent consistency checking.
    Uses all-MiniLM-L6-v2 for lightweight semantic similarity.
    """
    if "sentence_encoder" not in _model_cache:
        try:
            from sentence_transformers import SentenceTransformer
            device = _get_device()
            kwargs = dict(model_name_or_path="all-MiniLM-L6-v2", device=device)
            if _is_offline_mode():
                kwargs["local_files_only"] = True
                _model_cache["sentence_encoder"] = SentenceTransformer(**kwargs)
            else:
                try:
                    # 优先使用本地缓存，避免镜像网络校验卡住
                    _model_cache["sentence_encoder"] = SentenceTransformer(**kwargs, local_files_only=True)
                except Exception:
                    _model_cache["sentence_encoder"] = SentenceTransformer(**kwargs)
            logger.info(f"Sentence encoder loaded on {device}")
        except ImportError as e:
            logger.warning(f"sentence-transformers not available, falling back to keyword matching: {e}")
            _model_cache["sentence_encoder"] = None
        except Exception as e:
            logger.warning(f"Failed to load sentence encoder, falling back to keyword matching: {e}")
            _model_cache["sentence_encoder"] = None
    return _model_cache["sentence_encoder"]


def compute_intent_similarity(user_intent: str, action_name: str, action_args: dict = None) -> float:
    """
    Compute semantic similarity between user intent and an action.
    
    Returns:
        Similarity score between 0.0 and 1.0.
    """
    if not user_intent:
        return 1.0  # Can't judge without intent
    
    encoder = get_sentence_encoder()
    
    # Build action description
    action_desc = action_name
    if action_args:
        args_str = ", ".join(f"{k}={v}" for k, v in action_args.items())
        action_desc = f"{action_name}({args_str})"
    
    if encoder is not None:
        try:
            embeddings = encoder.encode([user_intent, action_desc])
            from sklearn.metrics.pairwise import cosine_similarity
            import numpy as np
            sim = cosine_similarity([embeddings[0]], [embeddings[1]])[0][0]
            return float(max(0.0, min(1.0, sim)))
        except Exception as e:
            logger.warning(f"Sentence encoder inference failed: {e}")
            # Fall through to keyword fallback
    
    # Fallback: keyword overlap
    return _keyword_similarity_fallback(user_intent, action_name)


def _keyword_similarity_fallback(user_intent: str, action_name: str) -> float:
    """Keyword overlap similarity fallback."""
    intent_words = set(re.findall(r'\w+', user_intent.lower()))
    action_words = set(re.findall(r'\w+', action_name.lower()))
    
    if not intent_words or not action_words:
        return 0.5
    
    overlap = len(intent_words & action_words)
    total = len(intent_words | action_words)
    
    if total == 0:
        return 0.5
    
    return overlap / total


# ---------------------------------------------------------------------------
# Ring 3: Sensitive Data Detection (NER)
# ---------------------------------------------------------------------------

def get_ner_pipeline():
    """
    Get or create the NER pipeline for sensitive data detection.
    Uses dslim/bert-base-NER for entity recognition.
    """
    if "ner_pipeline" not in _model_cache:
        try:
            from transformers import pipeline
            device = _get_device()
            if _is_offline_mode():
                from transformers import AutoTokenizer, AutoModelForTokenClassification
                _tokenizer = AutoTokenizer.from_pretrained("dslim/bert-base-NER", local_files_only=True)
                _model = AutoModelForTokenClassification.from_pretrained("dslim/bert-base-NER", local_files_only=True)
                _model_cache["ner_pipeline"] = pipeline(
                    task="ner", model=_model, tokenizer=_tokenizer, device=device, aggregation_strategy="simple"
                )
            else:
                try:
                    from transformers import AutoTokenizer, AutoModelForTokenClassification
                    _tokenizer = AutoTokenizer.from_pretrained("dslim/bert-base-NER", local_files_only=True)
                    _model = AutoModelForTokenClassification.from_pretrained("dslim/bert-base-NER", local_files_only=True)
                    _model_cache["ner_pipeline"] = pipeline(
                        task="ner", model=_model, tokenizer=_tokenizer, device=device, aggregation_strategy="simple"
                    )
                except Exception:
                    _model_cache["ner_pipeline"] = pipeline(
                        task="ner", model="dslim/bert-base-NER", device=device, aggregation_strategy="simple"
                    )
            logger.info(f"NER pipeline loaded on {device}")
        except ImportError as e:
            logger.warning(f"Transformers not available, falling back to regex: {e}")
            _model_cache["ner_pipeline"] = None
        except Exception as e:
            logger.warning(f"Failed to load NER model, falling back to regex: {e}")
            _model_cache["ner_pipeline"] = None
    return _model_cache["ner_pipeline"]


# Sensitive patterns for regex fallback and additional coverage
SENSITIVE_PATTERNS: list = [
    (r'(password|passwd|pwd|secret|token|api[_-]?key|auth[_-]?key)\s*[:=]\s*\S+', 'credential'),
    (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', 'email'),
    (r'\b(?:\d{4}[-\s]?){3}\d{4}\b', 'credit_card'),
    (r'\b\d{3}-\d{2}-\d{4}\b', 'ssn'),
    (r'\b(?:password123|secret_token|my_secret|my_password|admin123)\b', 'known_secret'),
    # --- IBAN — International Bank Account Numbers (ISO 13616) ---
    (r'\bDE\d{20}\b', 'iban'),
    (r'\bUS\d{21}\b', 'iban'),
    (r'\bSE\d{24}\b', 'iban'),
    (r'\bCH\d{21}\b', 'iban'),
    (r'\bGB\d{2}[A-Z]{4}\d{14}\b', 'iban'),
    (r'\b[A-Z]{2}\d{2}\s?[A-Z0-9]{4}\s?[A-Z0-9]{4}\s?[A-Z0-9]{4}\s?[A-Z0-9]{4,20}\b', 'iban'),
    # --- Personal PII ---
    (r'\b(?:\+?\d{1,3}[-.]?)?\(?\d{3}\)?[-.]?\d{3}[-.]?\d{4}\b', 'phone'),
    (r'\b\d+\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\s+(?:Street|Avenue|Road|Drive|Lane|Blvd)\b', 'address'),
    (r"'(?:first_name|last_name)'[:\s]*'([A-Z][a-z]+)'", 'personal_name'),
    # --- Financial amounts ---
    (r'\$[\d,]+(?:\.\d{2})?\b', 'financial_amount'),
]


def detect_sensitive_data(text: str) -> List[dict]:
    """
    Detect sensitive data in text using NER model + regex patterns.
    
    Returns:
        List of dicts with keys: text, label, score, start, end
    """
    if not text or not isinstance(text, str):
        return []
    
    results = []
    
    # Try NER model first
    ner = get_ner_pipeline()
    if ner is not None:
        try:
            # Token-aware truncation for NER: use full text, properly truncated
            ner_text = _token_aware_truncate(text, max_tokens=480)
            entities = ner(ner_text)
            for ent in entities:
                results.append({
                    "text": ent["word"],
                    "label": f"NER_{ent['entity_group']}",
                    "score": ent["score"],
                    "start": ent["start"],
                    "end": ent["end"],
                })
        except Exception as e:
            logger.warning(f"NER inference failed: {e}")
    
    # Regex patterns for additional coverage
    for pattern, label in SENSITIVE_PATTERNS:
        for match in re.finditer(pattern, text):
            # Avoid duplicates with NER results
            if not any(abs(r["start"] - match.start()) < 5 for r in results):
                results.append({
                    "text": match.group(0),
                    "label": f"REGEX_{label}",
                    "score": 0.8,
                    "start": match.start(),
                    "end": match.end(),
                })
    
    return results


def redact_sensitive_data(text: str, replacement: str = "[REDACTED]") -> str:
    """
    Redact sensitive data from text.
    
    Returns:
        Text with sensitive data replaced.
    """
    if not text or not isinstance(text, str):
        return text
    
    sensitive_items = detect_sensitive_data(text)
    
    # Sort by start position in reverse order to avoid offset issues
    sensitive_items.sort(key=lambda x: x["start"], reverse=True)
    
    result = text
    for item in sensitive_items:
        result = result[:item["start"]] + replacement + result[item["end"]:]
    
    return result



# ---------------------------------------------------------------------------
# AgentRaft DOE: D_nec / D_int extraction for data over-exposure judgment
# ---------------------------------------------------------------------------

# Map tool intents to data categories that are NECESSARY for the tool's function (D_nec)
# When a tool is called, its defined output categories are always allowed
# Expanded to cover all banking, email, calendar, cloud_drive, and user_account tools
TOOL_NEC_CATEGORIES = {
    # --- Credential tools ---
    "get_credentials": {"credential", "known_secret"},
    # --- Banking tools ---
    "get_balance": {"financial_data", "financial_amount"},
    "get_iban": {"iban", "financial_data"},
    "get_most_recent_transactions": {"financial_data", "financial_amount", "iban", "personal_name"},
    "get_scheduled_transactions": {"financial_data", "financial_amount", "iban", "personal_name"},
    "send_money": {"iban", "financial_amount"},
    "schedule_transaction": {"iban", "financial_amount"},
    "update_scheduled_transaction": {"financial_amount", "iban"},
    # --- User account tools ---
    "get_user_info": {"personal_name", "address", "location", "email"},
    "update_user_info": {"personal_name", "address"},
    "update_password": {"credential"},
    # --- Email tools ---
    "search_emails": {"email", "personal_name"},
    "get_received_emails": {"email", "personal_name"},
    "get_sent_emails": {"email", "personal_name"},
    "get_unread_emails": {"email", "personal_name"},
    "get_draft_emails": {"email", "personal_name"},
    "send_email": {"email"},
    "search_contacts_by_name": {"personal_name", "email"},
    "search_contacts_by_email": {"email", "personal_name"},
    # --- File tools ---
    "read_file": {"financial_data", "iban", "personal_name", "credential"},
    "search_files_by_filename": {"financial_data", "iban", "personal_name"},
    "list_files": {"financial_data", "personal_name"},
    "search_files": {"financial_data", "personal_name"},
    "get_file_by_id": {"financial_data", "personal_name"},
    # --- Calendar tools ---
    "get_current_day": set(),
    "get_day_calendar_events": {"personal_name", "location"},
    "search_calendar_events": {"personal_name", "location"},
    "create_calendar_event": {"personal_name", "location", "email"},
    "add_calendar_event_participants": {"email"},
    "cancel_calendar_event": set(),
    "reschedule_calendar_event": set(),
}

# Keywords that indicate user intends to access specific data categories
INTENT_CATEGORY_KEYWORDS = {
    "credential": [
        "credential", "password", "passwd", "pwd", "login", "account",
        "secret", "token", "api_key", "auth_key", "key", "credentials",
    ],
    "email": ["email", "mail", "send.*mail", "contact", "recipient"],
    "ssn": ["ssn", "social security", "social.*number"],
    "credit_card": ["credit card", "card number", "payment", "bank account", "cc"],
    "financial_data": ["balance", "transaction", "payment", "transfer", "money", "funds", "amount", "rent", "bill", "pay"],
    "financial_amount": ["dollar", "euro", "price", "cost", "fee", "amount", "rent", "bill"],
    "iban": ["iban", "bank account", "account number", "swift", "bic", "recipient.*account"],
    "personal_name": ["name", "user", "profile", "identity", "who", "contact"],
    "address": ["address", "street", "city", "location", "residence", "live"],
    "phone": ["phone", "telephone", "mobile", "cell", "number"],
}


def extract_necessary_categories(tool_intent: str) -> set:
    """Extract D_nec: data categories that are necessary for the tool's function."""
    return TOOL_NEC_CATEGORIES.get(tool_intent, set())


def extract_intended_categories(user_intent_text: str) -> set:
    """Extract D_int: data categories the user explicitly intended to access.

    Parses the user's original intent/prompt to determine which types of
    sensitive data the user legitimately needs to access in this task.
    """
    if not user_intent_text:
        return set()
    text_lower = user_intent_text.lower()
    intended = set()
    for category, keywords in INTENT_CATEGORY_KEYWORDS.items():
        for kw in keywords:
            if re.search(kw, text_lower):
                intended.add(category)
                break
    return intended


def _get_item_category(label: str) -> str:
    """Extract the semantic category from a detection label.

    Handles labels like:
      - 'REGEX_credential'  -> 'credential'
      - 'NER_PER'           -> 'PER'
      - 'credential'        -> 'credential'
    """
    if label.startswith("REGEX_"):
        return label[6:]
    if label.startswith("NER_"):
        return label[4:]
    return label


def redact_only_overexposed(
    text: str,
    allowed_categories: set = None,
    replacement: str = "[REDACTED]",
) -> str:
    """Redact only sensitive data whose category is NOT in allowed_categories.

    Implements the core DOE formula:
        D_OE = (D_trans \\ (D_nec U D_int)) n D_total

    Only items whose category falls outside (D_nec U D_int) will be redacted.
    When no allowed_categories are provided (None), falls back to redacting ALL
    sensitive data (conservative/default mode).
    """
    if not text or not isinstance(text, str):
        return text
    if allowed_categories is None:
        # Conservative default: redact everything (original behavior)
        return redact_sensitive_data(text, replacement)

    sensitive_items = detect_sensitive_data(text)

    # Filter: only redact items NOT in allowed categories
    to_redact = []
    for item in sensitive_items:
        category = _get_item_category(item["label"])
        if category not in allowed_categories:
            to_redact.append(item)

    if not to_redact:
        return text

    # Sort by start position in reverse order to avoid offset issues
    to_redact.sort(key=lambda x: x["start"], reverse=True)

    result = text
    for item in to_redact:
        result = result[: item["start"]] + replacement + result[item["end"] :]

    return result



# ---------------------------------------------------------------------------
