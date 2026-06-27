import json
import re
import httpx
import redis.asyncio as redis
from typing import Optional, Dict, Any
from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)
redis_client = redis.from_url(settings.REDIS_URL, decode_responses=True)

SUSPICIOUS_PATTERNS = [
    re.compile(r"(?i)ignore (all )?(previous|past)( instructions| messages| prompts| commands)?"),
    re.compile(r"(?i)forget (all )?(previous|past)( instructions| messages| prompts| commands)?"),
    re.compile(r"(?i)override (the )?(system|security|policy|filters)"),
    re.compile(r"(?i)disable (the )?(filters|safety|moderation)"),
    re.compile(r"(?i)jailbreak"),
    re.compile(r"(?i)break out of"),
    re.compile(r"(?i)do anything now"),
    re.compile(r"(?i)act as if"),
    re.compile(r"(?i)execute the following command"),
]

SENSITIVE_PATTERNS = {
    re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"): "[REDACTED_IP]",
    re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"): "[REDACTED_EMAIL]",
    re.compile(r"(?i)(password|passwd)\s*[:=]\s*[^\s,;]+"): "[REDACTED]",
    re.compile(r"(?i)(api[_-]?key|token|secret)\s*[:=]\s*[^\s,;]+"): "[REDACTED_TOKEN]",
    re.compile(r"\b[a-f0-9]{32,}\b", re.IGNORECASE): "[REDACTED_HEX]",
}

class PromptInjectionError(Exception):
    pass

def _stub_ml_classifier(prompt: str) -> float:
    # Stub for a real ML model inference
    lower_prompt = prompt.lower()
    if "ignore" in lower_prompt and "instructions" in lower_prompt:
        return 0.95
    return 0.1

def is_prompt_suspicious(prompt: str) -> bool:
    # Evaluate with ML model (stubbed)
    ml_score = _stub_ml_classifier(prompt)
    if ml_score > 0.85:
        logger.warning(f"Prompt classified as malicious with ML score: {ml_score}")
        return True

    # Fallback to Regex heuristics
    for patt in SUSPICIOUS_PATTERNS:
        if patt.search(prompt):
            logger.warning(f"Prompt suspicious pattern matched: {patt.pattern}")
            return True
    return False

def anonymize_prompt(prompt: str) -> str:
    redacted = prompt
    for patt, placeholder in SENSITIVE_PATTERNS.items():
        try:
            redacted = patt.sub(placeholder, redacted)
        except re.error:
            continue
    return redacted

RATE_LIMIT_LUA = """
local current = redis.call("INCR", KEYS[1])
if tonumber(current) == 1 then
    redis.call("EXPIRE", KEYS[1], ARGV[1])
end
return current
"""

async def check_rate_limit(user_id: int | str, limit: Optional[int] = None) -> bool:
    limit = limit or settings.AI_RATE_LIMIT_PER_MIN
    key = f"rl:ai:{user_id}"
    try:
        new = await redis_client.eval(RATE_LIMIT_LUA, 1, key, 60)
        return int(new) <= int(limit)
    except Exception:
        logger.exception("Rate limiter redis exception")
        return True

async def call_llm(prompt: str, model: Optional[str] = None) -> Dict[str, Any]:
    dev_fallback = settings.AI_DEV_FALLBACK
    model = model or settings.OLLAMA_DEFAULT_MODEL or "llama3"

    if not settings.OLLAMA_URL:
        if dev_fallback:
            return {"answer": "[AI fallback] Ollama not configured. Development stub.", "raw": "", "model": model}
        return {"error": "ollama_url_not_configured"}

    # Use num_ctx=2048 for tinyllama compatibility (supports max 2048)
    payload = {"model": model, "prompt": prompt, "stream": False, "options": {"num_ctx": 2048}}
    # Increased timeout to 300s to allow for model loading/swapping
    async with httpx.AsyncClient(timeout=300.0) as client:
        try:
            r = await client.post(settings.OLLAMA_URL, json=payload)
            r.raise_for_status()
            data = r.json()
            raw_text = data.get("response") or data.get("message") or data.get("result") or data.get("text") or ""
            return {"answer": raw_text.strip(), "raw": raw_text, "model": model}
        except Exception as exc:
            logger.exception("LLM request failed")
            if dev_fallback:
                return {"answer": f"[AI fallback] LLM error: {str(exc)}", "raw": str(exc), "model": model}
            return {"error": "request_exception", "message": str(exc)}

async def generate_ai_response(prompt: str, model: Optional[str] = None) -> Dict[str, Any]:
    if is_prompt_suspicious(prompt):
        raise PromptInjectionError("Malicious prompt detected")
    anonymized = anonymize_prompt(prompt)
    return await call_llm(anonymized, model=model)


async def generate_threat_report(alert: Any, osint_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    context = f"""
Alert: {alert.description}
Process: {alert.process_name} (PID: {alert.pid})
Path: {alert.process_path or 'N/A'}
Severity: {alert.severity}

OSINT Data:
{json.dumps(osint_data, indent=2) if osint_data else 'No OSINT data available'}
"""
    prompt = f"""You are an AegisXDR security analyst. Analyze this alert and OSINT data.
Provide:
1. Summary of the threat (1-2 sentences)
2. Confidence level (low/medium/high)
3. Recommended actions (list)

Alert context:
{context}

Respond in JSON format: {{"summary": "...", "confidence": "...", "recommended_actions": [...], "detailed_analysis": "..."}}
"""
    try:
        response = await call_llm(prompt, model="tinyllama")
        text = response.get("answer", "")
        try:
            import json
            start = text.find("{")
            end = text.rfind("}") + 1
            if start >= 0 and end > start:
                return json.loads(text[start:end])
        except Exception:
            pass
        return {
            "summary": f"Alert: {alert.description[:100]}",
            "confidence": "medium",
            "recommended_actions": [f"Investigate process {alert.process_name} on host"],
            "detailed_analysis": text[:500] if text else None,
        }
    except Exception:
        return None
