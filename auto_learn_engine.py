"""
auto_learn_engine.py  (Multi-AI Edition)
=========================================
PCAP 분석 후 '미탐지 패킷' payload 를 여러 AI 공급자에 순서대로 질의하여
keywords.yaml 에 새 키워드·카테고리를 자동 추가하는 자동학습 엔진.

지원 AI 공급자 (ai_config.yaml 에서 설정)
------------------------------------------
  claude   — Anthropic Claude     (최우선 기본값)
  openai   — OpenAI ChatGPT
  deepseek — DeepSeek             (무료 크레딧)
  grok     — xAI Grok             (무료 크레딧)
  copilot  — GitHub Copilot       (Copilot 구독 필요)

폴백 체인
---------
ai_config.yaml 의 priority 순서대로 시도.
fallback_on_error=true 이면 현재 공급자 실패 시 다음 공급자로 자동 전환.
모든 공급자 실패 시 해당 payload 는 건너뜀.

처리 흐름
---------
1. collect_candidates()    — 미탐지 payload 선별
2. run_auto_learn()        — 후보를 순회하며 AI 폴백 체인 실행
   └── _analyze_one()      — 단일 payload: 공급자 순서대로 시도
3. merge_into_yaml()       — 결과를 keywords.yaml 에 안전 병합
4. 관리 유틸               — get_learn_log / get_auto_categories / delete_keyword
"""

from __future__ import annotations

import json, re, shutil, threading, time
from pathlib import Path

try:
    import yaml
    YAML_OK = True
except ImportError:
    YAML_OK = False

import ai_providers as _prov   # 공급자별 API 어댑터

# ── 경로 ──────────────────────────────────────────────────────────────────────
_BASE          = Path(__file__).parent
KEYWORDS_FILE  = _BASE / "keywords" / "keywords.yaml"
LOG_FILE       = _BASE / "keywords" / "auto_learn_log.yaml"
AI_CONFIG_FILE = _BASE / "keywords" / "ai_config.yaml"

# ── 기본값 (ai_config.yaml 로드 실패 시 사용) ─────────────────────────────────
_DEFAULT_CFG = {
    "confidence_threshold":     60,
    "max_payloads_per_session": 15,
    "fallback_on_error":        True,
    "providers": [
        {"id":"claude","label":"Claude (Anthropic)","priority":1,
         "enabled":True,"api_key":"","model":""},
    ],
}

# ── 스레드 락 ──────────────────────────────────────────────────────────────────
_lock     = threading.Lock()
_cfg_lock = threading.Lock()

# ── 설정 캐시 ──────────────────────────────────────────────────────────────────
_cfg: dict        = {}
_cfg_mtime: float = 0.0


# ── 기존 카테고리 ID 매핑 ──────────────────────────────────────────────────────
_KNOWN_IDS: dict[str, int] = {
    "Command Injection / RCE":              1,
    "Directory Traversal":                  2,
    "SQL Injection":                        3,
    "XSS (Cross-Site Scripting)":           4,
    "WebShell Upload":                      5,
    "Malicious Scanner / Reconnaissance":   6,
    "Reverse Shell":                        7,
    "Log4Shell / JNDI Injection":           8,
    "Exploit Shellcode / Buffer Overflow":  9,
    "Exploit Overflow Pattern (Plaintext)": 91,
    "Malware / C2 Communication":           10,
    "PowerShell Attack":                    11,
    "Vulnerability Scanner Tools":          12,
}
_PROTO_MAP: dict[int, list[str]] = {
    1:["HTTP","FTP","TELNET","ANY"], 2:["HTTP","FTP","ANY"],
    3:["HTTP","ANY"], 4:["HTTP","ANY"], 5:["HTTP","ANY"],
    6:["HTTP","ANY"], 7:["HTTP","TELNET","ANY"], 8:["HTTP","ANY"],
    9:["ANY"], 91:["ANY"], 10:["ANY"], 11:["HTTP","ANY"], 12:["HTTP","ANY"],
}

# ── 보안 분석 시스템 프롬프트 (모든 공급자 공통) ──────────────────────────────
_SYSTEM_PROMPT = """당신은 네트워크 패킷 보안 분석 전문가입니다.
주어진 패킷 payload 를 분석하여 공격 여부와 탐지 키워드를 판별합니다.

반드시 아래 JSON 형식만 반환하세요. 마크다운이나 추가 설명 없이 순수 JSON 만 반환하세요.

{
  "is_attack": true 또는 false,
  "confidence": 0~100,
  "category_name": "카테고리명(영어)",
  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
  "reason": "한국어 판단 근거 1~2문장",
  "keywords": ["키워드1", "키워드2"],
  "nocase": true 또는 false
}

규칙:
- is_attack=false 이면 keywords 는 반드시 []
- keywords 는 payload 에 실제로 포함된 문자열만, 길이 3~40 bytes
- category_name 은 가능하면 아래 기존 카테고리 중 선택:
  Command Injection / RCE, Directory Traversal, SQL Injection,
  XSS (Cross-Site Scripting), WebShell Upload,
  Malicious Scanner / Reconnaissance, Reverse Shell,
  Log4Shell / JNDI Injection, Exploit Shellcode / Buffer Overflow,
  Malware / C2 Communication, PowerShell Attack, Vulnerability Scanner Tools
- confidence < 60 이면 is_attack=false 권장
- 정상 HTTP 요청, DNS 표준 쿼리 등은 is_attack=false"""


# ══════════════════════════════════════════════════════════════════════════════
# 1. 설정 로더
# ══════════════════════════════════════════════════════════════════════════════

def _load_cfg() -> dict:
    """ai_config.yaml 을 로드한다. 실패 시 기본값 반환."""
    global _cfg, _cfg_mtime
    with _cfg_lock:
        if not YAML_OK:
            return _DEFAULT_CFG
        try:
            mtime = AI_CONFIG_FILE.stat().st_mtime
        except OSError:
            return _DEFAULT_CFG
        if mtime == _cfg_mtime and _cfg:
            return _cfg
        try:
            with open(AI_CONFIG_FILE, "r", encoding="utf-8") as f:
                loaded = yaml.safe_load(f) or {}
            _cfg       = {**_DEFAULT_CFG, **loaded}
            _cfg_mtime = mtime
            return _cfg
        except Exception as e:
            print(f"[AutoLearn] ai_config.yaml 로드 실패: {e}")
            return _DEFAULT_CFG


def reload_ai_config() -> dict:
    """설정 파일을 강제 재로드하고 요약 반환."""
    global _cfg_mtime
    _cfg_mtime = 0.0   # 캐시 무효화
    cfg = _load_cfg()
    enabled = [p for p in cfg.get("providers", []) if p.get("enabled") and p.get("api_key")]
    return {
        "status":           "ok",
        "providers_active": len(enabled),
        "providers":        [p["label"] for p in enabled],
    }


def save_ai_config(new_cfg: dict) -> bool:
    """
    관리 페이지에서 전송된 설정을 ai_config.yaml 에 저장한다.
    API 키는 빈 문자열로 전송된 경우 기존 값을 유지.
    """
    if not YAML_OK:
        return False
    global _cfg_mtime
    with _cfg_lock:
        try:
            # 기존 파일 로드 (키 보존 목적)
            old: dict = {}
            if AI_CONFIG_FILE.exists():
                with open(AI_CONFIG_FILE, "r", encoding="utf-8") as f:
                    old = yaml.safe_load(f) or {}

            old_keys = {p["id"]: p.get("api_key", "")
                        for p in old.get("providers", [])}

            # 새 설정 병합
            merged = {**old, **new_cfg}
            for p in merged.get("providers", []):
                # 빈 키 전송 시 기존 값 유지
                if not p.get("api_key", "").strip():
                    p["api_key"] = old_keys.get(p["id"], "")

            bak = AI_CONFIG_FILE.with_suffix(".yaml.bak")
            if AI_CONFIG_FILE.exists():
                shutil.copy2(AI_CONFIG_FILE, bak)

            with open(AI_CONFIG_FILE, "w", encoding="utf-8") as f:
                yaml.dump(merged, f, allow_unicode=True,
                          default_flow_style=False, sort_keys=False, indent=2)
            _cfg_mtime = 0.0  # 캐시 무효화
            return True
        except Exception as e:
            print(f"[AutoLearn] 설정 저장 실패: {e}")
            return False


def get_providers_status() -> list[dict]:
    """현재 설정된 공급자 목록 + 상태 반환 (관리 페이지용)."""
    cfg       = _load_cfg()
    providers = sorted(cfg.get("providers", []),
                       key=lambda p: p.get("priority", 99))
    result    = []
    for p in providers:
        pid   = p.get("id", "")
        meta  = _prov.PROVIDER_META.get(pid, {})
        has_key = bool(str(p.get("api_key", "")).strip())
        result.append({
            "id":           pid,
            "label":        p.get("label") or meta.get("label", pid),
            "priority":     p.get("priority", 99),
            "enabled":      p.get("enabled", False),
            "has_key":      has_key,
            "model":        p.get("model", "") or meta.get("default_model", ""),
            "key_help":     meta.get("key_help", ""),
            "free_tier":    meta.get("free_tier", False),
            "note":         meta.get("note", ""),
            "ready":        p.get("enabled", False) and has_key,
        })
    return result


# ══════════════════════════════════════════════════════════════════════════════
# 2. 학습 대상 수집
# ══════════════════════════════════════════════════════════════════════════════

def collect_candidates(payload_info_list: list[dict],
                       max_count: int = 15) -> list[dict]:
    """
    분석된 payload_info 목록에서 자동학습 대상을 선별.
    조건: kw_detected=False, wl_matched=False, skipped_reason=None,
          payload >= 8 bytes, 앞 64 bytes 중복 제거.
    """
    result:    list[dict] = []
    seen_keys: set[bytes] = set()

    for pkt in payload_info_list:
        if pkt.get("kw_detected"):    continue
        if pkt.get("wl_matched"):     continue
        if pkt.get("skipped_reason"): continue

        raw: bytes = b""
        fh = pkt.get("full_hex", "")
        if fh:
            try: raw = bytes.fromhex(fh.replace(" ", ""))
            except: pass
        if len(raw) < 8: continue

        key = raw[:64]
        if key in seen_keys: continue
        seen_keys.add(key)

        result.append({
            "payload_bytes": raw,
            "protocol":      pkt.get("protocol", "OTHER"),
            "frame_no":      pkt.get("frame_no", 0),
            "length":        len(raw),
        })
        if len(result) >= max_count:
            break

    return result


# ══════════════════════════════════════════════════════════════════════════════
# 3. AI 폴백 체인 분석
# ══════════════════════════════════════════════════════════════════════════════

def _build_user_msg(raw: bytes, protocol: str, frame_no: int,
                    max_preview: int = 400) -> str:
    """AI 에 전달할 사용자 메시지 구성."""
    try:    printable = raw.decode("utf-8", errors="replace")[:max_preview]
    except: printable = ""
    hex_prev = " ".join(f"{b:02x}" for b in raw[:64])
    return (f"프로토콜: {protocol}\nFrame: {frame_no}\n"
            f"Payload 길이: {len(raw)} bytes\n\n"
            f"[ASCII/UTF-8 미리보기]\n{printable}\n\n"
            f"[HEX (앞 64 bytes)]\n{hex_prev}")


def _analyze_one(raw: bytes, protocol: str, frame_no: int,
                 providers: list[dict], cfg: dict) -> dict | None:
    """
    단일 payload 를 공급자 우선순위에 따라 순차 시도.
    성공하면 파싱된 dict 반환, 모두 실패하면 None.
    """
    threshold = cfg.get("confidence_threshold", 60)
    fallback  = cfg.get("fallback_on_error", True)
    user_msg  = _build_user_msg(raw, protocol, frame_no)

    for p in providers:
        pid     = p.get("id", "")
        api_key = str(p.get("api_key", "")).strip()
        model   = str(p.get("model", "")).strip() or None

        if not api_key:
            continue

        label = p.get("label", pid)
        print(f"[AutoLearn] Frame {frame_no} → {label} ({pid})")
        try:
            raw_text = _prov.call(pid, _SYSTEM_PROMPT, user_msg, api_key, model)
            result   = _prov.parse_response(raw_text)

            # confidence 필터
            if result.get("confidence", 0) < threshold:
                result["is_attack"] = False

            result["frame_no"]    = frame_no
            result["protocol"]    = protocol
            result["_provider"]   = pid
            result["_provider_label"] = label
            print(f"[AutoLearn] Frame {frame_no} — {label}: "
                  f"is_attack={result.get('is_attack')}, "
                  f"confidence={result.get('confidence')}")
            return result

        except json.JSONDecodeError as e:
            print(f"[AutoLearn] {label} JSON 파싱 실패: {e}")
            if not fallback: return None

        except Exception as e:
            print(f"[AutoLearn] {label} 호출 실패: {e}")
            if not fallback: return None

    print(f"[AutoLearn] Frame {frame_no} — 모든 공급자 실패")
    return None


# ══════════════════════════════════════════════════════════════════════════════
# 4. keywords.yaml 병합
# ══════════════════════════════════════════════════════════════════════════════

def _next_auto_id(cats: list[dict]) -> int:
    used = [c.get("category_id", 0) for c in cats
            if c.get("category_id", 0) >= 100]
    return max(used, default=99) + 1


def merge_into_yaml(ai_results: list[dict]) -> dict:
    """AI 분석 결과를 keywords.yaml 에 안전하게 병합."""
    attacks = [r for r in ai_results if r and r.get("is_attack") and r.get("keywords")]
    if not attacks:
        return {"added": 0, "skipped": 0, "new_cats": 0, "details": ["공격 패턴 없음"]}
    if not YAML_OK:
        return {"added": 0, "skipped": 0, "new_cats": 0, "details": ["PyYAML 미설치"]}
    if not KEYWORDS_FILE.exists():
        return {"added": 0, "skipped": 0, "new_cats": 0, "details": ["keywords.yaml 없음"]}

    with _lock:
        with open(KEYWORDS_FILE, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        cats: list[dict] = data.get("categories", [])
        existing: set[str] = {str(kw).strip().lower()
                               for cat in cats for kw in cat.get("keywords", [])}
        added = skipped = new_cats = 0
        details: list[str] = []
        log_rows: list[dict] = []

        for res in attacks:
            cat_name = res.get("category_name", "Unknown Threat")
            severity = res.get("severity", "MEDIUM")
            nocase   = res.get("nocase",   False)
            proto    = res.get("protocol", "OTHER")
            frame    = res.get("frame_no", 0)
            reason   = res.get("reason",   "")
            provider = res.get("_provider_label", "?")
            kws = [str(k).strip() for k in res.get("keywords", [])
                   if 3 <= len(str(k).strip()) <= 40]
            if not kws:
                continue

            # 대상 카테고리 탐색 또는 신규 생성
            target = next((c for c in cats
                           if c.get("name", "").strip() == cat_name), None)
            if target is None:
                cid    = _KNOWN_IDS.get(cat_name) or _next_auto_id(cats)
                protos = _PROTO_MAP.get(cid,
                    ([proto.upper()] if proto.upper() not in ("OTHER","ANY") else []) + ["ANY"])
                target = {
                    "category_id": cid, "name": cat_name, "severity": severity,
                    "protocols": protos, "nocase": nocase, "is_hex": False,
                    "keywords": [], "_source": "auto_learn",
                    "_added_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                }
                cats.append(target)
                new_cats += 1
                details.append(f"[신규 카테고리] {cat_name} (ID:{cid})")

            for kw in kws:
                kw_low = kw.lower()
                if kw_low in existing:
                    skipped += 1
                    details.append(f"  - 중복: {kw}")
                    continue
                target["keywords"].append(kw)
                existing.add(kw_low)
                added += 1
                details.append(f"  ✅ [{cat_name}] {kw}  "
                                f"(Frame {frame}, {severity}, via {provider})")
                log_rows.append({
                    "keyword":   kw,     "category": cat_name,
                    "severity":  severity, "frame_no": frame,
                    "protocol":  proto,  "reason":   reason,
                    "provider":  provider,
                    "added_at":  time.strftime("%Y-%m-%d %H:%M:%S"),
                })

        if added == 0:
            return {"added": 0, "skipped": skipped,
                    "new_cats": 0, "details": details or ["신규 키워드 없음"]}

        data["categories"] = cats
        bak = KEYWORDS_FILE.with_suffix(".yaml.bak")
        try: shutil.copy2(KEYWORDS_FILE, bak)
        except: pass
        with open(KEYWORDS_FILE, "w", encoding="utf-8") as f:
            yaml.dump(data, f, allow_unicode=True,
                      default_flow_style=False, sort_keys=False, indent=2)
        _append_log(log_rows)

    return {"added": added, "skipped": skipped,
            "new_cats": new_cats, "details": details}


def _append_log(rows: list[dict]) -> None:
    try:
        ex: list = []
        if LOG_FILE.exists():
            with open(LOG_FILE, "r", encoding="utf-8") as f:
                ex = yaml.safe_load(f) or []
        ex.extend(rows)
        ex = ex[-500:]
        with open(LOG_FILE, "w", encoding="utf-8") as f:
            yaml.dump(ex, f, allow_unicode=True,
                      default_flow_style=False, sort_keys=False)
    except Exception as e:
        print(f"[AutoLearn] 로그 저장 실패: {e}")


# ══════════════════════════════════════════════════════════════════════════════
# 5. 메인 진입점
# ══════════════════════════════════════════════════════════════════════════════

def run_auto_learn(payload_info_list: list[dict]) -> dict:
    """
    PCAP 분석 결과를 받아 자동학습 파이프라인 전체를 실행한다.

    Returns
    -------
    {"analyzed":int, "added":int, "skipped":int,
     "new_cats":int, "details":[str], "error":str,
     "providers_used":[str]}
    """
    base = {"analyzed": 0, "added": 0, "skipped": 0,
            "new_cats": 0, "details": [], "error": "",
            "providers_used": []}

    if not YAML_OK:
        base["error"] = "PyYAML 미설치"; return base

    # 설정 로드
    cfg = _load_cfg()
    providers_all = sorted(cfg.get("providers", []),
                           key=lambda p: p.get("priority", 99))
    # 활성화 + 키 있는 공급자만
    providers_ready = [p for p in providers_all
                       if p.get("enabled") and str(p.get("api_key","")).strip()]

    if not providers_ready:
        # API 키가 없는 경우 — error 가 아닌 조용한 건너뜀으로 처리
        # 상위(app_single/multi)에서 learn_result.get('no_provider') 로 판별 가능
        base["no_provider"] = True
        base["details"] = ["AI 공급자 미설정 — 자동학습 건너뜀 (API 키 없음)"]
        return base

    # 1. 후보 수집
    max_pkt = cfg.get("max_payloads_per_session", 15)
    candidates = collect_candidates(payload_info_list, max_count=max_pkt)
    if not candidates:
        base["details"] = ["학습 대상 없음 (모두 기탐지 또는 화이트리스트)"]
        return base

    base["analyzed"] = len(candidates)

    # 2. AI 폴백 체인 분석
    ai_results:    list[dict] = []
    providers_used: set[str]  = set()

    for c in candidates:
        result = _analyze_one(
            c["payload_bytes"], c["protocol"], c["frame_no"],
            providers_ready, cfg,
        )
        if result:
            ai_results.append(result)
            providers_used.add(result.get("_provider_label", "?"))
        time.sleep(0.2)

    base["providers_used"] = sorted(providers_used)

    # 3. yaml 병합
    merge = merge_into_yaml(ai_results)
    base.update({
        "added":    merge["added"],
        "skipped":  merge["skipped"],
        "new_cats": merge["new_cats"],
        "details":  merge["details"],
    })

    # 4. KeywordLoader 핫 리로드
    if merge["added"] > 0:
        try:
            from keyword_rule_engine import reload_keywords
            reload_keywords()
            print(f"[AutoLearn] 재로드 완료 (+{merge['added']} 키워드)")
        except Exception as e:
            print(f"[AutoLearn] 재로드 실패: {e}")

    return base


# ══════════════════════════════════════════════════════════════════════════════
# 6. 관리 유틸
# ══════════════════════════════════════════════════════════════════════════════

def get_learn_log(limit: int = 100) -> list[dict]:
    if not YAML_OK or not LOG_FILE.exists(): return []
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            rows = yaml.safe_load(f) or []
        return list(reversed(rows))[:limit]
    except: return []


def get_auto_categories() -> list[dict]:
    if not YAML_OK or not KEYWORDS_FILE.exists(): return []
    try:
        with open(KEYWORDS_FILE, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return [
            {"category_id": c.get("category_id"), "name": c.get("name"),
             "severity": c.get("severity"),
             "keyword_count": len(c.get("keywords", [])),
             "added_at": c.get("_added_at", ""),
             "keywords": c.get("keywords", [])}
            for c in data.get("categories", [])
            if c.get("_source") == "auto_learn"
        ]
    except: return []


def delete_keyword(category_name: str, keyword: str) -> bool:
    if not YAML_OK or not KEYWORDS_FILE.exists(): return False
    with _lock:
        try:
            with open(KEYWORDS_FILE, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            changed = False
            for cat in data.get("categories", []):
                if cat.get("name") == category_name:
                    kws = cat.get("keywords", [])
                    if keyword in kws:
                        kws.remove(keyword)
                        cat["keywords"] = kws
                        changed = True; break
            if changed:
                bak = KEYWORDS_FILE.with_suffix(".yaml.bak")
                try: shutil.copy2(KEYWORDS_FILE, bak)
                except: pass
                with open(KEYWORDS_FILE, "w", encoding="utf-8") as f:
                    yaml.dump(data, f, allow_unicode=True,
                              default_flow_style=False, sort_keys=False, indent=2)
            return changed
        except Exception as e:
            print(f"[AutoLearn] 삭제 실패: {e}"); return False


def get_stats() -> dict:
    log  = get_learn_log(500)
    cats = get_auto_categories()
    # 공급자별 기여 통계
    provider_counts: dict[str, int] = {}
    for row in log:
        pv = row.get("provider", "unknown")
        provider_counts[pv] = provider_counts.get(pv, 0) + 1
    return {
        "total_learned":    len(log),
        "total_auto_cats":  len(cats),
        "total_auto_kws":   sum(c["keyword_count"] for c in cats),
        "last_learned_at":  log[0]["added_at"] if log else "없음",
        "provider_counts":  provider_counts,
    }
