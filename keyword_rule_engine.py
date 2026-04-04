"""
keyword_rule_engine.py
=======================
keywords/keywords.yaml 을 읽어 패킷 payload 에서 키워드를 탐지하고
Snort 룰을 자동 생성하는 엔진.

주요 기능
---------
- YAML 키워드 파일 로드 (파일 변경 시 자동 재로드)
- 카테고리·프로토콜·심각도별 분류
- hex/plaintext 혼용 content 지원
- nocase 옵션 지원
- 매칭된 키워드마다 개별 Snort rule 생성 (Frame N 주석 포함)
- 탐지 결과 요약(matched_keywords, categories) 반환
"""

from __future__ import annotations

import os
import re
import time
from pathlib import Path
from typing import Any

# PyYAML 은 requirements.txt 에 추가 필요
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

# ── 상수 ──────────────────────────────────────────────────────────────────────
KEYWORDS_FILE = Path(__file__).parent / "keywords" / "keywords.yaml"

# SID 범위: 카테고리 ID × 10_000 + 순번
#   예) category_id=1 → SID 10001 ~ 10999
SID_BASE       = 10_000
SID_MULTIPLIER = 10_000

# 프로토콜 → Snort proto 문자열 매핑
PROTO_MAP = {
    "HTTP":   "tcp",
    "FTP":    "tcp",
    "TELNET": "tcp",
    "SMTP":   "tcp",
    "DNS":    "udp",
    "ANY":    "tcp",   # 범용
}

# 프로토콜 기본 목적지 포트 (실제 포트를 알 수 없을 때 fallback)
DEFAULT_PORTS = {
    "HTTP":   "[80,8080,8000,8443]",
    "FTP":    "21",
    "TELNET": "23",
    "SMTP":   "[25,465,587]",
    "DNS":    "53",
    "ANY":    "any",
}


# ══════════════════════════════════════════════════════════════════════════════
# 1. YAML 로더 (파일 변경 감지 포함)
# ══════════════════════════════════════════════════════════════════════════════

class KeywordLoader:
    """keywords.yaml 을 로드하고 변경 시 자동으로 재로드한다."""

    def __init__(self, path: Path = KEYWORDS_FILE):
        self.path       = path
        self._categories: list[dict] = []
        self._mtime: float = 0.0
        self._load()

    # ── 내부 로드 ──────────────────────────────────────────────────────────
    def _load(self) -> None:
        if not YAML_AVAILABLE:
            print("[KeywordLoader] PyYAML not installed — keyword detection disabled.")
            self._categories = []
            return

        if not self.path.exists():
            print(f"[KeywordLoader] File not found: {self.path}")
            self._categories = []
            return

        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            self._categories = data.get("categories", [])
            self._mtime      = self.path.stat().st_mtime
            print(f"[KeywordLoader] Loaded {len(self._categories)} categories from {self.path.name}")
        except Exception as e:
            print(f"[KeywordLoader] Load error: {e}")
            self._categories = []

    def _needs_reload(self) -> bool:
        try:
            return self.path.stat().st_mtime > self._mtime
        except OSError:
            return False

    # ── 공개 API ───────────────────────────────────────────────────────────
    @property
    def categories(self) -> list[dict]:
        """카테고리 목록 반환 (변경 감지 시 자동 재로드)."""
        if self._needs_reload():
            print("[KeywordLoader] File changed — reloading…")
            self._load()
        return self._categories

    def reload(self) -> None:
        """수동 재로드."""
        self._load()


# 모듈 수준 싱글톤 (앱 전체에서 공유)
_loader = KeywordLoader()


def get_loader() -> KeywordLoader:
    return _loader


def reload_keywords() -> None:
    """외부에서 강제 재로드할 때 호출."""
    _loader.reload()


# ══════════════════════════════════════════════════════════════════════════════
# 2. 키워드 → Snort content 변환
# ══════════════════════════════════════════════════════════════════════════════

def _keyword_to_content(keyword: str, is_hex: bool) -> str:
    """
    키워드를 Snort content 필드 문자열로 변환.

    is_hex=True  : \\xNN 이스케이프 → |NN| hex 바이트 표기
                   평문 hex 문자열(예: '4141414141') → |41 41 41 41 41| 변환
    is_hex=False : 특수문자 이스케이프만 처리
    """
    if is_hex:
        # \\xNN 패턴 → |NN| 변환
        def replace_xnn(m: re.Match) -> str:
            byte_val = int(m.group(1), 16)
            return f"|{byte_val:02x}|"

        converted = re.sub(r"\\x([0-9a-fA-F]{2})", replace_xnn, keyword)

        # 순수 hex 문자열(짝수 자리, 0-9a-fA-F만) → |xx xx xx| 변환
        stripped = converted.replace(" ", "")
        if re.fullmatch(r"[0-9a-fA-F]+", stripped) and len(stripped) % 2 == 0:
            pairs = [stripped[i:i+2] for i in range(0, len(stripped), 2)]
            return "|" + " ".join(pairs) + "|"

        return converted

    # 평문: Snort content 내 큰따옴표·개행 이스케이프
    return keyword.replace('"', '\\"').replace("\n", " ").replace("\r", " ")


# ══════════════════════════════════════════════════════════════════════════════
# 3. 단일 패킷 payload 키워드 탐지
# ══════════════════════════════════════════════════════════════════════════════

def scan_payload(payload: bytes, protocol: str) -> list[dict]:
    """
    payload 에서 keywords.yaml 의 모든 카테고리를 순회하며 키워드를 탐지한다.

    Returns
    -------
    list of {
        "category_id"  : int,
        "category_name": str,
        "severity"     : str,
        "keyword"      : str,
        "keyword_index": int,   # 카테고리 내 키워드 순번 (SID 계산용)
        "nocase"       : bool,
        "is_hex"       : bool,
        "protocols"    : list[str],
    }
    """
    matches: list[dict] = []

    # payload 를 대소문자 무시 검색용으로도 준비
    try:
        payload_text       = payload.decode("utf-8", errors="ignore")
        payload_text_lower = payload_text.lower()
    except Exception:
        payload_text       = ""
        payload_text_lower = ""

    for cat in _loader.categories:
        cat_id    = cat.get("category_id", 0)
        cat_name  = cat.get("name", "Unknown")
        severity  = cat.get("severity", "MEDIUM")
        protocols = [p.upper() for p in cat.get("protocols", ["ANY"])]
        nocase    = cat.get("nocase", False)
        is_hex    = cat.get("is_hex", False)
        keywords  = cat.get("keywords", [])

        # 프로토콜 필터: ANY は全プロトコル対象
        if "ANY" not in protocols and protocol.upper() not in protocols:
            continue

        for idx, kw in enumerate(keywords):
            kw_str = str(kw)

            if is_hex:
                # hex 키워드: bytes 레벨에서 검색
                try:
                    # \\xNN 패턴을 실제 바이트로 변환하여 검색
                    pattern_bytes = re.sub(
                        r"\\x([0-9a-fA-F]{2})",
                        lambda m: bytes([int(m.group(1), 16)]).decode("latin-1"),
                        kw_str
                    ).encode("latin-1")
                    if pattern_bytes in payload:
                        matches.append(_make_match(cat_id, cat_name, severity, protocols, nocase, is_hex, kw_str, idx))
                    continue
                except Exception:
                    pass

                # 순수 hex 문자열 (예: 4141414141)
                stripped = kw_str.replace(" ", "")
                if re.fullmatch(r"[0-9a-fA-F]+", stripped) and len(stripped) % 2 == 0:
                    try:
                        search_bytes = bytes.fromhex(stripped)
                        if search_bytes in payload:
                            matches.append(_make_match(cat_id, cat_name, severity, protocols, nocase, is_hex, kw_str, idx))
                    except ValueError:
                        pass
                    continue

            # 평문 키워드
            if nocase:
                if kw_str.lower() in payload_text_lower:
                    matches.append(_make_match(cat_id, cat_name, severity, protocols, nocase, is_hex, kw_str, idx))
            else:
                if kw_str in payload_text:
                    matches.append(_make_match(cat_id, cat_name, severity, protocols, nocase, is_hex, kw_str, idx))

    return matches


def _make_match(cat_id, cat_name, severity, protocols, nocase, is_hex, kw, idx) -> dict:
    return {
        "category_id":   cat_id,
        "category_name": cat_name,
        "severity":      severity,
        "keyword":       kw,
        "keyword_index": idx,
        "nocase":        nocase,
        "is_hex":        is_hex,
        "protocols":     protocols,
    }


# ══════════════════════════════════════════════════════════════════════════════
# 4. Snort 룰 생성
# ══════════════════════════════════════════════════════════════════════════════

def build_keyword_rules(
    matches:   list[dict],
    protocol:  str,
    dst_port:  str,
    frame_no:  int,
) -> list[str]:
    """
    scan_payload() 결과를 받아 Snort 룰 목록을 반환한다.

    SID 계산:  SID_BASE + category_id × SID_MULTIPLIER + keyword_index
      예) category_id=1, keyword_index=3  →  SID = 10000 + 1×10000 + 3 = 20003
    """
    rules: list[str] = []
    seen_sids: set[int] = set()

    for m in matches:
        sid = SID_BASE + m["category_id"] * SID_MULTIPLIER + m["keyword_index"]

        # 동일 SID 중복 방지
        if sid in seen_sids:
            continue
        seen_sids.add(sid)

        snort_proto = PROTO_MAP.get(protocol.upper(), "tcp")
        port        = dst_port if dst_port not in ("any", "0", "") else DEFAULT_PORTS.get(protocol.upper(), "any")

        content_val = _keyword_to_content(m["keyword"], m["is_hex"])
        nocase_opt  = " nocase;" if m["nocase"] else ""
        severity    = m["severity"]
        cat_name    = m["category_name"]
        kw_display  = m["keyword"][:50].replace('"', "'")

        rule = (
            f'# Frame {frame_no}\n'
            f'alert {snort_proto} any any -> any {port} '
            f'(msg:"{severity} {cat_name} - {kw_display}"; '
            f'content:"{content_val}";{nocase_opt} '
            f'sid:{sid}; rev:1;)'
        )
        rules.append(rule)

    return rules


# ══════════════════════════════════════════════════════════════════════════════
# 5. 공개 진입점
# ══════════════════════════════════════════════════════════════════════════════

def detect_and_build_rules(
    payload:  bytes,
    protocol: str,
    dst_port: str,
    frame_no: int,
) -> dict:
    """
    payload 를 스캔하고 키워드 매칭 룰을 반환하는 메인 함수.

    Returns
    -------
    {
        "matched_keywords": [str, ...],       # 탐지된 키워드 목록
        "matched_categories": [str, ...],     # 탐지된 카테고리 이름 목록 (중복 제거)
        "severity_max": str,                  # 가장 높은 심각도
        "rules": [str, ...],                  # 생성된 Snort 룰 목록
        "matches": [dict, ...],               # 상세 매치 정보
    }
    """
    matches = scan_payload(payload, protocol)

    rules = build_keyword_rules(matches, protocol, dst_port, frame_no)

    matched_keywords   = [m["keyword"]       for m in matches]
    matched_categories = list(dict.fromkeys(m["category_name"] for m in matches))  # 순서 유지 중복 제거

    severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    severity_max  = max(
        (m["severity"] for m in matches),
        key=lambda s: severity_rank.get(s, 0),
        default="LOW"
    ) if matches else "LOW"

    return {
        "matched_keywords":   matched_keywords,
        "matched_categories": matched_categories,
        "severity_max":       severity_max,
        "rules":              rules,
        "matches":            matches,
    }


# ══════════════════════════════════════════════════════════════════════════════
# 6. 키워드 파일 관리 유틸 (Flask 라우트에서 호출)
# ══════════════════════════════════════════════════════════════════════════════

def get_keywords_summary() -> list[dict]:
    """
    현재 로드된 키워드 목록의 요약 반환.
    [{ category_id, name, severity, protocols, keyword_count, keywords }, ...]
    """
    return [
        {
            "category_id":   c.get("category_id"),
            "name":          c.get("name"),
            "severity":      c.get("severity"),
            "protocols":     c.get("protocols"),
            "keyword_count": len(c.get("keywords", [])),
            "keywords":      c.get("keywords", []),
        }
        for c in _loader.categories
    ]


def get_keywords_file_path() -> str:
    return str(KEYWORDS_FILE)


def get_keywords_file_mtime() -> str:
    try:
        ts = KEYWORDS_FILE.stat().st_mtime
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
    except OSError:
        return "N/A"
