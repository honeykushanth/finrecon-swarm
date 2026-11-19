# llm_factory.py
import os
from pathlib import Path
from typing import List, Tuple
from dotenv import load_dotenv
from langchain_core.messages import BaseMessage
from langchain_groq import ChatGroq
from langchain_ollama import ChatOllama

BASE_DIR = Path(__file__).resolve().parent
# utf-8-sig safely strips Windows PowerShell UTF-8 BOM if present in .env
load_dotenv(dotenv_path=BASE_DIR / ".env", override=True, encoding="utf-8-sig")

GROQ_FAST_MODEL = os.getenv("GROQ_FAST_MODEL", "openai/gpt-oss-20b")
GROQ_REASONING_MODEL = os.getenv("GROQ_REASONING_MODEL", "openai/gpt-oss-120b")
OLLAMA_FALLBACK_MODEL = os.getenv("OLLAMA_FALLBACK_MODEL", "llama3.1")
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")


def _has_valid_groq_key() -> bool:
    key = (os.getenv("GROQ_API_KEY") or "").strip()
    return bool(key) and key.startswith("gsk_") and key != "gsk_my_key"


def invoke_llm_with_failover(
    messages: List[BaseMessage],
    tier: str = "fast",
    temperature: float = 0.1
) -> Tuple[str, str, List[str]]:
    """
    Invokes the assigned Groq open-weight LLM with automatic fallback to local Ollama.

    Args:
        messages: List of LangChain SystemMessage/HumanMessage objects.
        tier: 'fast' (routing/extraction) or 'reasoning' (compliance & executive synthesis).
        temperature: Sampling temperature.

    Returns:
        Tuple of (response_text, provider_used_label, failover_warnings)
    """
    warnings: List[str] = []

    groq_candidates = (
        [GROQ_FAST_MODEL]
        if tier == "fast"
        else [GROQ_REASONING_MODEL, GROQ_FAST_MODEL]
    )

    # 1. Primary: Groq Free-Tier Open-Weight Models
    if _has_valid_groq_key():
        for model_name in groq_candidates:
            try:
                llm = ChatGroq(
                    model=model_name,
                    temperature=temperature,
                    max_retries=1,
                    timeout=45,
                )
                resp = llm.invoke(messages)
                content = resp.content if isinstance(resp.content, str) else str(resp.content)
                return content, f"Groq ({model_name})", warnings
            except Exception as e:
                err_msg = str(e)
                reason = "HTTP 429 Rate Limit" if "429" in err_msg else type(e).__name__
                warnings.append(f"Groq [{model_name}] failed ({reason}): {err_msg[:140]}")
    else:
        warnings.append("GROQ_API_KEY missing or still set to placeholder 'gsk_my_key' — routing directly to Ollama.")

    # 2. Automatic Failover: Local Ollama Instance
    try:
        ollama_llm = ChatOllama(
            model=OLLAMA_FALLBACK_MODEL,
            base_url=OLLAMA_BASE_URL,
            temperature=temperature,
        )
        resp = ollama_llm.invoke(messages)
        content = resp.content if isinstance(resp.content, str) else str(resp.content)
        return content, f"Ollama Local Failover ({OLLAMA_FALLBACK_MODEL})", warnings
    except Exception as e:
        raise RuntimeError(
            f"All LLM providers failed. Warnings: {warnings}. Ollama error: {str(e)}"
        ) from e
