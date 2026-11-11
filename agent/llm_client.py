"""Thin wrapper around a chat endpoint - Ollama's native /api/chat locally,
or OpenRouter's OpenAI-style chat completions in the cloud, switched via
config.PROVIDER - plus a small tool-calling loop. Both are handled as
OpenAI-style messages inside the loop.

Stateless between calls - there is no server-side memory of a previous
request. Every call resends the full conversation so far.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Callable

import requests

from . import config

# Free-tier OpenRouter models occasionally return a transient 5xx/429 under
# load, or cut a reply off mid-answer (see _call_once) - retry a few times
# before giving up. A local Ollama model rarely hits any of these, but the
# same retry path costs nothing when it isn't needed.
MAX_RETRIES = 3
RETRY_BACKOFF_SEC = 5.0
RATE_LIMIT_BACKOFF_SEC = 20.0  # 429s need much longer than a transient 5xx to clear


# Largest prompt (tokens) Ollama reported in the current run_agent call.
# Ollama silently drops the START of a prompt that overflows num_ctx, so
# assess.py flags a case whose prompt came close to it.
max_prompt_tokens = 0


class DailyQuotaExceeded(RuntimeError):
    """OpenRouter's free-tier daily request cap is used up. Retrying will not
    help - the whole batch should stop, not burn through remaining cases.
    Never raised when config.PROVIDER == "ollama"."""


class OutOfCredit(DailyQuotaExceeded):
    """OpenRouter has no credit left (HTTP 402) or the key's spending limit
    is reached. Like the daily quota, it stops the whole batch."""


# Token use since the last reset_usage() (assess.py resets it per case).
# Ollama reports prompt_eval_count / eval_count; OpenRouter a `usage` block,
# with the actual cost when usage accounting is on.
usage = {"calls": 0, "prompt_tokens": 0, "completion_tokens": 0, "cached_tokens": 0, "cost_usd": 0.0}


def reset_usage() -> None:
    for key in usage:
        usage[key] = 0.0 if key == "cost_usd" else 0


def usage_snapshot() -> dict:
    return {**usage, "cost_usd": round(usage["cost_usd"], 6)}


def estimate_cost(prompt_tokens: int, completion_tokens: int) -> float:
    """USD from the per-million-token prices in config (0 for a local model)."""
    return (prompt_tokens * config.PRICE_INPUT_PER_MTOK + completion_tokens * config.PRICE_OUTPUT_PER_MTOK) / 1e6


def _add_usage(prompt_tokens: int, completion_tokens: int, cached_tokens: int = 0, cost: float | None = None) -> None:
    usage["calls"] += 1
    usage["prompt_tokens"] += int(prompt_tokens or 0)
    usage["completion_tokens"] += int(completion_tokens or 0)
    usage["cached_tokens"] += int(cached_tokens or 0)
    usage["cost_usd"] += float(cost) if cost is not None else estimate_cost(prompt_tokens or 0, completion_tokens or 0)


def _record_openrouter_usage(data: dict) -> None:
    block = data.get("usage") or {}
    details = block.get("prompt_tokens_details") or {}
    _add_usage(block.get("prompt_tokens") or 0, block.get("completion_tokens") or 0,
               details.get("cached_tokens") or 0, block.get("cost"))


CREDIT_WORDS = ("credit", "insufficient", "limit exceeded", "key limit", "spend limit")


def _out_of_credit(response) -> bool:
    """HTTP 402, or 403 saying the key's limit is reached."""
    if response.status_code == 402:
        return True
    return response.status_code == 403 and any(w in response.text.lower() for w in CREDIT_WORDS)


def _cached(messages: list[dict]) -> list[dict]:
    """Anthropic prompt caching through OpenRouter: mark the system prompt and
    the case file (the first user message), which stay the same across one
    case's tool rounds, with cache_control."""
    out, marked_user = [], False
    for message in messages:
        mark = message.get("role") == "system" or (message.get("role") == "user" and not marked_user)
        if mark and isinstance(message.get("content"), str):
            marked_user = marked_user or message["role"] == "user"
            message = {**message, "content": [{"type": "text", "text": message["content"],
                                               "cache_control": {"type": "ephemeral"}}]}
        out.append(message)
    return out


def _use_cache(model: str) -> bool:
    return config.PROMPT_CACHE and model.startswith("anthropic/")


def _to_ollama_messages(messages: list[dict]) -> list[dict]:
    """Ollama's native API wants tool-call arguments as objects, not JSON strings."""
    converted = []
    for message in messages:
        if not message.get("tool_calls"):
            converted.append(message)
            continue
        calls = []
        for call in message["tool_calls"]:
            fn = call.get("function", {})
            arguments = fn.get("arguments") or {}
            if isinstance(arguments, str):
                arguments = json.loads(arguments or "{}")
            calls.append({"function": {"name": fn.get("name", ""), "arguments": arguments}})
        converted.append({**message, "tool_calls": calls})
    return converted


def _call_ollama(messages: list[dict], tools: list[dict] | None, model: str | None,
                 temperature: float | None, max_tokens: int) -> dict:
    """One request to Ollama's native /api/chat. The OpenAI-compatible endpoint
    ignores the context size, and Ollama's 4096-token default silently drops
    the start of a long prompt (the system prompt and reply template), so the
    native endpoint is used to set num_ctx. Returns an OpenAI-style message."""
    payload = {
        "model": model or config.model(),
        "messages": _to_ollama_messages(messages),
        "stream": False,
        "options": {
            "temperature": config.TEMPERATURE if temperature is None else temperature,
            "num_predict": max_tokens,
            "num_ctx": config.OLLAMA_NUM_CTX,
            "seed": config.SEED,
        },
    }
    if tools:
        payload["tools"] = tools
    if config.OLLAMA_THINK is not None:
        payload["think"] = config.OLLAMA_THINK  # hidden reasoning, if any, comes back in message.thinking
    headers = {}
    if config.OLLAMA_API_KEY:
        headers["Authorization"] = f"Bearer {config.OLLAMA_API_KEY}"
    response = requests.post(config.OLLAMA_API_URL, headers=headers, json=payload, timeout=config.LLM_TIMEOUT_SEC)
    response.raise_for_status()
    data = response.json()
    if "error" in data:
        raise RuntimeError(f"ollama error: {data['error']}")

    global max_prompt_tokens
    max_prompt_tokens = max(max_prompt_tokens, int(data.get("prompt_eval_count") or 0))
    _add_usage(data.get("prompt_eval_count") or 0, data.get("eval_count") or 0)
    raw = data.get("message", {})
    message = {"role": "assistant", "content": raw.get("content", "")}
    if raw.get("tool_calls"):
        message["tool_calls"] = [
            {
                "id": call.get("id", f"call_{i}"),
                "type": "function",
                "function": {
                    "name": call.get("function", {}).get("name", ""),
                    "arguments": json.dumps(call.get("function", {}).get("arguments", {})),
                },
            }
            for i, call in enumerate(raw["tool_calls"])
        ]
    if data.get("done_reason") == "length" or (not message["content"] and not message.get("tool_calls")):
        raise RuntimeError(f"truncated reply (done_reason={data.get('done_reason')}) - "
                           f"ran out of num_predict={max_tokens} before finishing")
    return message


def _call_once(messages: list[dict], tools: list[dict] | None, model: str | None,
               temperature: float | None, max_tokens: int) -> dict:
    """One HTTP request. Returns the raw assistant message dict."""
    if config.PROVIDER == "ollama":
        return _call_ollama(messages, tools, model, temperature, max_tokens)

    model = model or config.model()
    payload = {
        "model": model,
        "temperature": config.TEMPERATURE if temperature is None else temperature,
        "max_tokens": max_tokens,
        "seed": config.SEED,
        "messages": _cached(messages) if _use_cache(model) else messages,
        "usage": {"include": True},  # OpenRouter usage accounting: the actual cost of each call
    }
    if tools:
        payload["tools"] = tools

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {config.api_key()}",
        "HTTP-Referer": config.SITE_URL,
        "X-Title": config.SITE_NAME,
    }
    response = requests.post(config.api_url(), headers=headers, json=payload, timeout=config.LLM_TIMEOUT_SEC)

    if response.status_code == 429 and "free-models-per-day" in response.text:
        reset_ms = response.headers.get("X-RateLimit-Reset")
        reset_note = ""
        if reset_ms:
            reset_time = datetime.fromtimestamp(int(reset_ms) / 1000, tz=timezone.utc)
            reset_note = f" Resets at {reset_time.isoformat()}."
        raise DailyQuotaExceeded(
            "OpenRouter free-tier daily request quota is exhausted." + reset_note +
            " Wait for the reset, add credits at openrouter.ai to raise the daily cap, "
            "or set LLM_PROVIDER=ollama to use a local model instead."
        )
    if _out_of_credit(response):
        raise OutOfCredit(
            f"OpenRouter refused the request for lack of credit (HTTP {response.status_code}). Add credit or raise "
            "the key's limit at openrouter.ai, or set LLM_PROVIDER=ollama to use a local model instead."
        )
    response.raise_for_status()
    data = response.json()
    if "error" in data:
        raise RuntimeError(f"{config.PROVIDER} error: {data['error']}")
    _record_openrouter_usage(data)

    choice = data["choices"][0]
    message = choice["message"]
    finish_reason = choice.get("finish_reason")
    has_tool_calls = bool(message.get("tool_calls"))

    # Reasoning models can burn the whole max_tokens budget on hidden "thinking"
    # before finishing the visible answer, cutting it off mid-reply. A tool-call
    # reply legitimately has empty content, so only flag truncation when there's
    # neither real content nor a tool call, or the API itself says "length".
    if finish_reason == "length" or (not message.get("content") and not has_tool_calls):
        raise RuntimeError(
            f"truncated reply (finish_reason={finish_reason}) - ran out of "
            f"max_tokens={max_tokens} before finishing"
        )
    return message


def _call_with_retry(messages: list[dict], tools: list[dict] | None, model: str | None,
                     temperature: float | None, max_tokens: int) -> dict:
    budget = max_tokens
    last_error: Exception | None = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            return _call_once(messages, tools, model, temperature, budget)
        except DailyQuotaExceeded:
            raise  # not transient - retrying within this call cannot fix it
        except requests.exceptions.HTTPError as exc:
            last_error = exc
            if attempt < MAX_RETRIES:
                # Free-tier rate limit: back off much longer than a generic retry,
                # and honour Retry-After if the server sent one.
                status = exc.response.status_code if exc.response is not None else None
                if status == 429:
                    retry_after = exc.response.headers.get("Retry-After") if exc.response is not None else None
                    wait = float(retry_after) if retry_after else RATE_LIMIT_BACKOFF_SEC * attempt
                else:
                    wait = RETRY_BACKOFF_SEC * attempt
                time.sleep(wait)
        except requests.exceptions.RequestException as exc:
            last_error = exc
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_BACKOFF_SEC * attempt)
        except RuntimeError as exc:
            # Our own truncation signal (see _call_once) - give the next attempt
            # a bigger token budget, since a bigger budget is exactly the fix.
            last_error = exc
            budget = int(budget * 1.6)
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_BACKOFF_SEC * attempt)
    raise RuntimeError(f"{config.PROVIDER} request failed after {MAX_RETRIES} attempts: {last_error}")


def chat(messages: list[dict], max_tokens: int | None = None) -> str:
    """One plain reply (no tools), e.g. for the self-check pass."""
    message = _call_with_retry(messages, None, None, None, max_tokens or config.MAX_TOKENS)
    return message.get("content") or ""


def run_agent(messages: list[dict], tools: list[dict] | None = None,
              tool_executor: Callable[[str, dict], dict] | None = None,
              model: str | None = None, temperature: float | None = None,
              max_tokens: int | None = None, max_rounds: int | None = None,
              reset_prompt_count: bool = True) -> tuple[str, list[dict], list[dict]]:
    """Run a tool-calling loop. Returns (final reply text, tool-call trace,
    the whole conversation including tool results and the final reply).

    Capped at max_rounds (default config.MAX_TOOL_ROUNDS) round-trips; the
    final round drops the `tools` param so the model has to answer in text.
    """
    global max_prompt_tokens
    if reset_prompt_count:
        max_prompt_tokens = 0
    budget = max_tokens or config.MAX_TOKENS
    rounds = config.MAX_TOOL_ROUNDS if max_rounds is None else max_rounds
    working_messages = list(messages)
    trace: list[dict] = []

    for round_i in range(rounds + 1):
        is_final_round = round_i == rounds
        offer_tools = tools if (tools and tool_executor and not is_final_round) else None

        message = _call_with_retry(working_messages, offer_tools, model, temperature, budget)
        tool_calls = message.get("tool_calls") if offer_tools else None

        if tool_calls:
            working_messages.append(message)
            for call in tool_calls:
                fn = call.get("function", {})
                name = fn.get("name", "")
                try:
                    arguments = json.loads(fn.get("arguments") or "{}")
                except json.JSONDecodeError:
                    arguments = {}
                result = tool_executor(name, arguments)
                trace.append({"tool": name, "arguments": arguments, "result": result})
                working_messages.append({
                    "role": "tool",
                    "tool_call_id": call.get("id", ""),
                    "content": json.dumps(result, default=str),
                })
            continue  # let the model see the tool result and respond again

        content = message.get("content")
        if content:
            working_messages.append({"role": "assistant", "content": content})
            return content, trace, working_messages

    raise RuntimeError("model never produced a final text answer within the tool-call round limit")
