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


# ---------------------------------------------------------------- Provider
# Il provider e' pluggabile: locale (ollama) o cloud via API key. La chiave
# si legge env -> dashboard (integration_settings, cifrata col KEK), stesso
# meccanismo dei provider OSINT: nessun .env obbligatorio.
PROVIDERS = ("ollama", "gemini", "openai")

_LOCAL_PROVIDERS = {"ollama"}


async def _provider_key(name: str) -> str:
    """Chiave del provider: env vince, poi override DB della dashboard."""
    env_name = {"gemini": "GEMINI_API_KEY", "openai": "OPENAI_API_KEY"}.get(name)
    if not env_name:
        return ""
    env_val = (getattr(settings, env_name, "") or "").strip()
    if env_val and not env_val.startswith("your_") and env_val != "replace-with":
        return env_val
    try:
        from app.database.connection import AsyncSessionLocal
        from app.services.integration_settings import get_key

        async with AsyncSessionLocal() as db:
            return await get_key(db, name)
    except Exception:
        logger.debug("Lettura chiave %s da dashboard fallita", name)
        return ""


async def _ollama_reachable() -> bool:
    """Probe breve: l'URL configurato non basta, il server deve rispondere.

    Senza questo, `auto` sceglieva ollama solo perche' OLLAMA_URL esiste nel
    compose: a container spento ogni arricchimento falliva con connection
    refused invece di degradare a 'AI disattivata' o a un altro provider.
    """
    url = (settings.OLLAMA_URL or "").strip()
    if not url:
        return False
    probe = url.replace("/api/generate", "/api/tags").replace("/v1/chat/completions", "/api/tags")
    try:
        async with httpx.AsyncClient(timeout=1.5) as client:
            r = await client.get(probe)
            return r.status_code < 500
    except Exception:
        return False


async def _ai_config() -> Dict[str, Any]:
    """Configurazione AI effettiva: dashboard (`app_settings`) + env.

    La precedenza è dichiarata in `app_settings.resolve_ai`: l'env vince dove
    esprime una scelta esplicita, la dashboard dove l'env è solo un default
    (AI_PROVIDER=auto). Mai eccezioni: se il DB non risponde si ricade sui
    valori d'ambiente, cioè il comportamento precedente alla UI.
    """
    try:
        from app.database.connection import AsyncSessionLocal
        from app.services.app_settings import resolve_ai

        async with AsyncSessionLocal() as db:
            return await resolve_ai(db)
    except Exception:
        logger.debug("Lettura impostazioni AI da dashboard fallita, uso env")
        return {
            "provider": (settings.AI_PROVIDER or "auto").strip().lower(),
            "model": (settings.AI_MODEL or "").strip(),
            "automatic_enrich": bool(settings.AI_AUTOMATIC_ENRICH),
            "provider_source": "env", "model_source": "env",
            "automatic_source": "env", "cloud": False, "local": False,
        }


async def resolve_provider() -> Dict[str, Any]:
    """Provider effettivo + modello + chiave. Mai eccezioni.

    `auto` sceglie in ordine: ollama che risponde davvero, gemini con chiave,
    openai con chiave, altrimenti disabled — cosi' chi non configura nulla non
    paga nulla e non vede errori a raffica: vede 'AI disattivata'.
    """
    cfg = await _ai_config()
    requested = cfg["provider"] or "auto"
    model_override = cfg["model"]
    automatic = bool(cfg["automatic_enrich"])

    if requested == "disabled":
        return {"provider": "disabled", "model": "", "key": "", "reason": "disabled by configuration"}

    if requested in PROVIDERS and requested != "auto":
        chosen = requested
    elif requested in ("auto", ""):
        # auto = usa cio' che FUNZIONA: ollama solo se risponde davvero.
        chosen = ""
        if settings.OLLAMA_URL and await _ollama_reachable():
            chosen = "ollama"
        else:
            for cand in ("gemini", "openai"):
                if await _provider_key(cand):
                    chosen = cand
                    break
        if not chosen:
            return {"provider": "disabled", "model": "", "key": "",
                    "reason": "no AI provider available (ollama not reachable, no cloud key)"}
    else:
        return {"provider": "disabled", "model": "", "key": "",
                "reason": f"unknown AI_PROVIDER '{requested}'"}

    if chosen == "ollama":
        model = model_override or (settings.OLLAMA_DEFAULT_MODEL or "llama3")
        # Una scelta esplicita si rispetta (l'operatore ha selezionato ollama),
        # ma se il server non risponde lo stato lo DICE: senza questo la
        # dashboard mostrerebbe "ollama · qwen2.5" mentre ogni chat fallisce.
        reachable = await _ollama_reachable()
        reason = ("local" if reachable else
                  f"ollama selected but not reachable at {settings.OLLAMA_URL or 'OLLAMA_URL unset'}")
        # Locale = nessun dato esce dalla rete: l'arricchimento automatico non
        # richiede consenso (il consenso vale per i provider cloud).
        return {"provider": "ollama", "model": model, "key": "",
                "reason": reason, "reachable": reachable, "automatic": True}

    key = await _provider_key(chosen)
    if not key:
        return {"provider": "disabled", "model": "", "key": "",
                "reason": f"{chosen} selected but no API key configured"}
    default_model = settings.GEMINI_MODEL if chosen == "gemini" else settings.OPENAI_MODEL
    return {"provider": chosen, "model": model_override or default_model, "key": key,
            "reason": "cloud", "automatic": automatic}


async def provider_summary() -> Dict[str, Any]:
    """Stato per la UI: provider, modello, se i dati escono dalla rete."""
    info = await resolve_provider()
    return {
        "provider": info["provider"],
        "model": info.get("model") or "",
        "local": info["provider"] in _LOCAL_PROVIDERS,
        # `automatic` è già la decisione risolta (dashboard > env): non si
        # ricalcola qui, altrimenti due fonti di verità che divergono.
        "automatic_enrichment": bool(info.get("automatic")),
        "reason": info.get("reason", ""),
        # None quando non ha senso (provider cloud o disattivata): la UI
        # distingue "non applicabile" da "raggiungibile/non raggiungibile".
        "reachable": info.get("reachable"),
    }


async def _call_ollama(prompt: str, model: str) -> Dict[str, Any]:
    # num_ctx 2048 = compatibilita' con i modelli piccoli; timeout lungo per
    # il caricamento del modello.
    payload = {"model": model, "prompt": prompt, "stream": False, "options": {"num_ctx": 2048}}
    async with httpx.AsyncClient(timeout=300.0) as client:
        r = await client.post(settings.OLLAMA_URL, json=payload)
        r.raise_for_status()
        data = r.json()
        raw_text = data.get("response") or data.get("message") or data.get("result") or data.get("text") or ""
        return {"answer": raw_text.strip(), "raw": raw_text, "model": model, "provider": "ollama"}


async def _call_gemini(prompt: str, model: str, key: str) -> Dict[str, Any]:
    url = (f"https://generativelanguage.googleapis.com/v1beta/models/{model}"
           f":generateContent?key={key}")
    payload = {"contents": [{"parts": [{"text": prompt}]}]}
    async with httpx.AsyncClient(timeout=60.0) as client:
        r = await client.post(url, json=payload)
        r.raise_for_status()
        data = r.json()
        try:
            raw_text = data["candidates"][0]["content"]["parts"][0]["text"]
        except (KeyError, IndexError):
            raw_text = json.dumps(data)[:1000]
        return {"answer": raw_text.strip(), "raw": raw_text, "model": model, "provider": "gemini"}


async def _call_openai(prompt: str, model: str, key: str) -> Dict[str, Any]:
    base = (settings.OPENAI_BASE_URL or "https://api.openai.com/v1").rstrip("/")
    payload = {"model": model, "messages": [{"role": "user", "content": prompt}]}
    headers = {"Authorization": f"Bearer {key}"}
    async with httpx.AsyncClient(timeout=60.0) as client:
        r = await client.post(f"{base}/chat/completions", json=payload, headers=headers)
        r.raise_for_status()
        data = r.json()
        try:
            raw_text = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError):
            raw_text = json.dumps(data)[:1000]
        return {"answer": raw_text.strip(), "raw": raw_text, "model": model, "provider": "openai"}


def _heuristic_suspicion_score(prompt: str) -> float:
    # Euristica dichiarata ( NON un modello ML): conta pattern noti.
    # Storicamente si chiamava _stub_ml_classifier con soglia 0.85 —
    # rinominato perché il nome mentiva sul metodo.
    lower_prompt = prompt.lower()
    hits = sum(1 for p in SUSPICIOUS_PATTERNS if p.search(prompt))
    if "ignore" in lower_prompt and "instructions" in lower_prompt:
        hits += 2
    return min(0.99, hits * 0.45)


def is_prompt_suspicious(prompt: str) -> bool:
    # Soglia 0.85 invariata per compatibilità di comportamento.
    score = _heuristic_suspicion_score(prompt)
    if score > 0.85:
        logger.warning(f"Prompt classified as malicious with heuristic score: {score}")
        return True

    # Fallback ridondante tenuto per difesa in profondità
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
        # Audit: fail-CLOSED (prima True = LLM illimitato con Redis giu').
        logger.exception("Rate limiter redis exception")
        return False


def allowed_model(model: Optional[str]) -> str:
    """Modello effettivo: default se assente; solo allowlist (audit)."""
    default = settings.OLLAMA_DEFAULT_MODEL or "llama3"
    if not model:
        return default
    allowed = {default, "tinyllama"}
    extra = {m.strip() for m in (settings.OLLAMA_ALLOWED_MODELS or "").split(",") if m.strip()}
    allowed |= extra
    if model not in allowed:
        raise ValueError(f"model not allowed: {model}")
    return model

async def call_llm(prompt: str, model: Optional[str] = None,
                   respect_automatic: bool = False) -> Dict[str, Any]:
    """Chiama il provider AI configurato. Mai eccezioni verso il chiamante.

    `respect_automatic=True` (usato dall'arricchimento automatico degli
    alert): se il provider e' CLOUD e l'arricchimento automatico e' spento,
    non manda nulla fuori — ritorna uno stato esplicito. Con AI_AUTOMATIC_
    ENRICH=false i dati sensibili escono solo su richiesta dell'utente.
    """
    dev_fallback = settings.AI_DEV_FALLBACK
    info = await resolve_provider()

    if info["provider"] == "disabled":
        msg = info.get("reason") or "AI disabled"
        if dev_fallback:
            return {"answer": f"[AI fallback] {msg}", "raw": "", "model": ""}
        return {"error": "ai_disabled", "message": msg}

    if respect_automatic and info["provider"] not in _LOCAL_PROVIDERS and not info.get("automatic", False):
        return {"error": "ai_cloud_requires_optin",
                "message": "cloud provider in use: automatic enrichment disabled, ask on-demand"}

    effective = info["model"]
    if model:
        if info["provider"] == "ollama":
            # Allowlist solo per ollama: i modelli cloud sono fissati dal provider.
            try:
                effective = allowed_model(model)
            except ValueError as exc:
                return {"error": "model_not_allowed", "message": str(exc)}
        else:
            effective = model

    try:
        if info["provider"] == "ollama":
            return await _call_ollama(prompt, effective)
        if info["provider"] == "gemini":
            return await _call_gemini(prompt, effective, info["key"])
        return await _call_openai(prompt, effective, info["key"])
    except Exception as exc:
        logger.exception("LLM request failed (%s)", info["provider"])
        if dev_fallback:
            return {"answer": f"[AI fallback] LLM error: {str(exc)}", "raw": str(exc), "model": effective}
        return {"error": "request_exception", "message": str(exc),
                "provider": info["provider"]}

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
        # Nessun modello hardcoded: si usa quello del provider configurato
        # (ollama/gemini/openai). respect_automatic evita che un provider
        # cloud riceva gli alert senza consenso esplicito.
        response = await call_llm(prompt, respect_automatic=True)
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
