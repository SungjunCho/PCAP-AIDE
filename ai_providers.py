"""
ai_providers.py
===============
다중 AI 공급자 어댑터 모듈.

지원 공급자
-----------
  claude    : Anthropic Claude (claude-sonnet-4-20250514)
  openai    : OpenAI ChatGPT   (gpt-4o-mini / gpt-4o)
  deepseek  : DeepSeek         (deepseek-chat)  ← OpenAI 호환 API
  grok      : xAI Grok         (grok-3-mini)    ← OpenAI 호환 API
  copilot   : GitHub Copilot   (gpt-4o / Azure OpenAI 호환)

공통 인터페이스
---------------
  call(provider_id, system_prompt, user_msg, api_key) -> str (JSON 문자열)

각 공급자는 아래 공통 JSON 을 반환하도록 system_prompt 를 통일:
  {"is_attack":bool, "confidence":int, "category_name":str,
   "severity":str, "reason":str, "keywords":[str,...], "nocase":bool}
"""

from __future__ import annotations

import json
import re
import urllib.request
import urllib.error
from typing import Any


# ══════════════════════════════════════════════════════════════════════════════
# 공급자 메타 정보 (표시용)
# ══════════════════════════════════════════════════════════════════════════════

PROVIDER_META: dict[str, dict] = {
    "claude": {
        "label":        "Claude (Anthropic)",
        "url":          "https://api.anthropic.com/v1/messages",
        "default_model":"claude-sonnet-4-20250514",
        "key_env":      "ANTHROPIC_API_KEY",
        "key_help":     "https://console.anthropic.com/settings/keys",
        "free_tier":    False,
        "note":         "가장 정확한 보안 분석. 월 사용량 제한 있음.",
    },
    "openai": {
        "label":        "ChatGPT (OpenAI)",
        "url":          "https://api.openai.com/v1/chat/completions",
        "default_model":"gpt-4o-mini",
        "key_env":      "OPENAI_API_KEY",
        "key_help":     "https://platform.openai.com/api-keys",
        "free_tier":    False,
        "note":         "gpt-4o-mini: 저비용 고속. gpt-4o: 고정밀.",
    },
    "deepseek": {
        "label":        "DeepSeek",
        "url":          "https://api.deepseek.com/chat/completions",
        "default_model":"deepseek-chat",
        "key_env":      "DEEPSEEK_API_KEY",
        "key_help":     "https://platform.deepseek.com/api_keys",
        "free_tier":    True,
        "note":         "OpenAI 호환 API. 무료 크레딧 제공. 비용 매우 저렴.",
    },
    "grok": {
        "label":        "Grok (xAI)",
        "url":          "https://api.x.ai/v1/chat/completions",
        "default_model":"grok-3-mini",
        "key_env":      "GROK_API_KEY",
        "key_help":     "https://console.x.ai/",
        "free_tier":    True,
        "note":         "OpenAI 호환 API. 무료 크레딧 제공.",
    },
    "copilot": {
        "label":        "GitHub Copilot",
        "url":          "https://api.githubcopilot.com/chat/completions",
        "default_model":"gpt-4o",
        "key_env":      "GITHUB_TOKEN",
        "key_help":     "https://github.com/settings/tokens",
        "free_tier":    True,
        "note":         "GitHub Copilot 구독 필요. OpenAI 호환 API.",
    },
}


# ══════════════════════════════════════════════════════════════════════════════
# 내부 HTTP 유틸
# ══════════════════════════════════════════════════════════════════════════════

def _http_post(url: str, headers: dict, body: dict, timeout: int = 40) -> dict:
    """순수 표준 라이브러리 JSON POST. 실패 시 예외를 그대로 전파."""
    data = json.dumps(body, ensure_ascii=False).encode("utf-8")
    req  = urllib.request.Request(url, data=data,
                                  headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def _strip_fence(text: str) -> str:
    """마크다운 코드 펜스 제거."""
    text = re.sub(r"^```[a-z]*\s*", "", text.strip())
    text = re.sub(r"\s*```$",        "", text)
    return text.strip()


# ══════════════════════════════════════════════════════════════════════════════
# 공급자별 어댑터
# ══════════════════════════════════════════════════════════════════════════════

def _call_claude(system: str, user_msg: str, api_key: str, model: str) -> str:
    """Anthropic Messages API."""
    resp = _http_post(
        url     = PROVIDER_META["claude"]["url"],
        headers = {"Content-Type": "application/json",
                   "x-api-key":    api_key,
                   "anthropic-version": "2023-06-01"},
        body    = {"model": model, "max_tokens": 1000,
                   "system": system,
                   "messages": [{"role": "user", "content": user_msg}]},
    )
    return resp["content"][0]["text"]


def _call_openai_compat(url: str, system: str, user_msg: str,
                         api_key: str, model: str,
                         extra_headers: dict | None = None) -> str:
    """OpenAI 호환 /chat/completions API (OpenAI·DeepSeek·Grok·Copilot 공통)."""
    headers = {"Content-Type": "application/json",
               "Authorization": f"Bearer {api_key}"}
    if extra_headers:
        headers.update(extra_headers)
    resp = _http_post(
        url     = url,
        headers = headers,
        body    = {"model": model, "max_tokens": 1000,
                   "messages": [
                       {"role": "system",  "content": system},
                       {"role": "user",    "content": user_msg},
                   ]},
    )
    return resp["choices"][0]["message"]["content"]


# ── 공개 단일 진입점 ──────────────────────────────────────────────────────────

def call(provider_id: str, system: str, user_msg: str,
         api_key: str, model: str | None = None) -> str:
    """
    지정한 공급자로 API 를 호출하고 응답 텍스트를 반환한다.

    Parameters
    ----------
    provider_id : "claude" | "openai" | "deepseek" | "grok" | "copilot"
    system      : 시스템 프롬프트
    user_msg    : 사용자 메시지
    api_key     : 해당 공급자의 API 키
    model       : 모델명 (None 이면 기본값 사용)

    Returns
    -------
    str  — AI 응답 원문 (JSON 파싱 전 raw text)

    Raises
    ------
    ValueError  — 알 수 없는 provider_id
    Exception   — API 호출 실패 (상위에서 폴백 처리)
    """
    meta  = PROVIDER_META.get(provider_id)
    if meta is None:
        raise ValueError(f"Unknown provider: {provider_id}")

    m = model or meta["default_model"]

    if provider_id == "claude":
        return _call_claude(system, user_msg, api_key, m)

    elif provider_id == "openai":
        return _call_openai_compat(meta["url"], system, user_msg, api_key, m)

    elif provider_id == "deepseek":
        return _call_openai_compat(meta["url"], system, user_msg, api_key, m)

    elif provider_id == "grok":
        return _call_openai_compat(meta["url"], system, user_msg, api_key, m)

    elif provider_id == "copilot":
        # GitHub Copilot 은 추가 헤더 필요
        return _call_openai_compat(
            meta["url"], system, user_msg, api_key, m,
            extra_headers={"Editor-Version": "vscode/1.85.0",
                           "Copilot-Integration-Id": "vscode-chat"},
        )

    else:
        raise ValueError(f"Unhandled provider: {provider_id}")


def parse_response(raw_text: str) -> dict:
    """
    AI 응답에서 JSON 객체를 추출·파싱한다.
    마크다운 펜스, 앞뒤 공백 등을 제거 후 json.loads().
    """
    cleaned = _strip_fence(raw_text)
    # { ... } 블록만 추출 시도 (앞뒤 잡문 제거)
    m = re.search(r"\{[\s\S]*\}", cleaned)
    if m:
        cleaned = m.group(0)
    return json.loads(cleaned)
