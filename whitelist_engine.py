"""
whitelist_engine.py
===================
전체 프로토콜 공통 화이트리스트 엔진.

global_whitelist.yaml 에 등록된 패턴과 일치하는 패킷은
프로토콜 종류에 관계없이 "정상 패킷"으로 판정되어
Snort 룰 생성에서 제외됩니다.

처리 흐름
---------
1. GlobalWhitelistLoader — global_whitelist.yaml 로드 (변경 시 자동 재로드)
2. check_global_whitelist(payload, protocol, icmp_info) — 화이트리스트 대조
3. 결과: {"matched": bool, "reason": str, "entry": dict|None}

지원 match_type
---------------
- payload_exact  : payload 전체 hex 완전 일치
- payload_hex    : payload 앞부분 hex starts-with 매칭
- payload_text   : payload 내 문자열 포함 여부 (부분 매칭)
- type_code      : ICMP type/code 조합만으로 정상 판정

화이트리스트 파일: keywords/global_whitelist.yaml
"""

from __future__ import annotations

import datetime
from pathlib import Path

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


# ── 경로 상수 ──────────────────────────────────────────────────────────────────
WHITELIST_FILE = Path(__file__).parent / "keywords" / "global_whitelist.yaml"


# ══════════════════════════════════════════════════════════════════════════════
# 1. YAML 로더 (파일 변경 자동 감지)
# ══════════════════════════════════════════════════════════════════════════════

class GlobalWhitelistLoader:
    """
    global_whitelist.yaml 을 로드하고 파일이 변경될 때 자동 재로드한다.
    싱글턴으로 모듈 레벨에서 한 번만 인스턴스화된다.
    """

    def __init__(self, path: Path = WHITELIST_FILE):
        self.path      = path
        self._entries: list[dict] = []
        self._mtime:   float      = 0.0
        self._load()

    # ── 내부 로드 ──────────────────────────────────────────────────────────────
    def _load(self) -> None:
        if not YAML_AVAILABLE:
            print("[GlobalWhitelist] PyYAML 미설치 — 화이트리스트 비활성화.")
            self._entries = []
            return

        if not self.path.exists():
            print(f"[GlobalWhitelist] 파일 없음: {self.path}")
            self._entries = []
            return

        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            self._entries = data.get("whitelist", []) if data else []
            self._mtime   = self.path.stat().st_mtime
            print(f"[GlobalWhitelist] 로드 완료 — {len(self._entries)}개 엔트리 "
                  f"({self.path.name})")
        except Exception as e:
            print(f"[GlobalWhitelist] 로드 실패: {e}")
            self._entries = []

    def _check_reload(self) -> None:
        """파일 수정 시각이 바뀌었으면 자동 재로드"""
        try:
            if self.path.exists() and self.path.stat().st_mtime != self._mtime:
                print("[GlobalWhitelist] 파일 변경 감지 — 재로드 중...")
                self._load()
        except Exception:
            pass

    @property
    def entries(self) -> list[dict]:
        self._check_reload()
        return self._entries

    def reload(self) -> int:
        self._load()
        return len(self._entries)

    # ── 관리 페이지용 요약 ───────────────────────────────────────────────────
    def get_summary(self) -> list[dict]:
        return [
            {
                "description": e.get("description", ""),
                "source":      e.get("source", ""),
                "protocols":   e.get("protocols") or ["ALL"],
                "match_type":  e.get("match_type", ""),
                "value":       e.get("value", ""),
                "icmp_type":   e.get("icmp_type"),
                "icmp_code":   e.get("icmp_code"),
            }
            for e in self.entries
        ]

    def get_file_path(self) -> str:
        return str(self.path)

    def get_file_mtime(self) -> str:
        try:
            ts = self.path.stat().st_mtime
            return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return "unknown"


# 모듈 레벨 싱글턴
_loader = GlobalWhitelistLoader()


# ══════════════════════════════════════════════════════════════════════════════
# 2. 화이트리스트 대조 (메인 함수)
# ══════════════════════════════════════════════════════════════════════════════

def check_global_whitelist(
    payload: bytes,
    protocol: str,
    icmp_type: int = -1,
    icmp_code: int = -1,
) -> dict:
    """
    payload 와 프로토콜 정보를 글로벌 화이트리스트와 대조한다.

    Parameters
    ----------
    payload   : 패킷 payload bytes
    protocol  : 감지된 프로토콜 문자열 ("HTTP", "DNS", "ICMP", ...)
    icmp_type : ICMP type 번호 (-1 = ICMP 아님)
    icmp_code : ICMP code 번호 (-1 = ICMP 아님)

    Returns
    -------
    {
      "matched" : bool,        # True = 화이트리스트 일치 (정상 패킷)
      "reason"  : str,         # 매칭 사유 설명
      "entry"   : dict | None, # 매칭된 엔트리
    }
    """
    payload_hex_str = payload.hex() if payload else ""

    for entry in _loader.entries:
        # ── 프로토콜 필터 ──────────────────────────────────────────────────
        wl_protocols = entry.get("protocols")  # None 또는 리스트
        if wl_protocols:
            # 대소문자 무관 비교
            wl_protos_upper = [str(p).upper() for p in wl_protocols]
            if protocol.upper() not in wl_protos_upper:
                continue  # 이 엔트리는 해당 프로토콜에 적용 안 됨

        # ── ICMP type/code 필터 ────────────────────────────────────────────
        wl_icmp_type = entry.get("icmp_type")  # None = 모든 type
        wl_icmp_code = entry.get("icmp_code")  # None = 모든 code
        if wl_icmp_type is not None and wl_icmp_type != icmp_type:
            continue
        if wl_icmp_code is not None and wl_icmp_code != icmp_code:
            continue

        match_type = entry.get("match_type", "")
        value      = str(entry.get("value", "") or "")
        desc       = entry.get("description", "")
        src        = entry.get("source", "unknown")
        reason_prefix = f"{desc} [source: {src}]"

        # ── match_type 별 대조 ─────────────────────────────────────────────

        # 1) payload_exact — 전체 hex 완전 일치
        if match_type == "payload_exact":
            wl_hex = value.replace(" ", "").lower()
            # 길이 일치 또는 starts-with 로 비교
            if payload_hex_str == wl_hex or payload_hex_str.startswith(wl_hex):
                return {
                    "matched": True,
                    "reason":  f"exact hex match: {reason_prefix}",
                    "entry":   entry,
                }
            continue

        # 2) payload_hex — 앞부분 hex starts-with 매칭
        if match_type == "payload_hex":
            wl_hex = value.replace(" ", "").lower()
            if wl_hex and payload_hex_str.startswith(wl_hex):
                return {
                    "matched": True,
                    "reason":  f"hex prefix match: {reason_prefix}",
                    "entry":   entry,
                }
            continue

        # 3) payload_text — 문자열 포함 여부
        if match_type == "payload_text":
            if value == "":
                # 빈 문자열 = type/code 조합만으로 판정 (ICMP 제어 메시지 등)
                if wl_icmp_type is not None:
                    return {
                        "matched": True,
                        "reason":  f"type/code match (any payload): {reason_prefix}",
                        "entry":   entry,
                    }
                continue
            try:
                payload_str = payload.decode("utf-8", errors="ignore")
                if value in payload_str:
                    return {
                        "matched": True,
                        "reason":  f"text contains '{value}': {reason_prefix}",
                        "entry":   entry,
                    }
            except Exception:
                pass
            continue

        # 4) type_code — ICMP type/code 조합만으로 정상 판정
        if match_type == "type_code":
            # type/code 조건은 이미 위에서 필터링됨 → 여기까지 오면 일치
            return {
                "matched": True,
                "reason":  f"ICMP type/code match: {reason_prefix}",
                "entry":   entry,
            }

    return {"matched": False, "reason": "no whitelist match", "entry": None}


# ══════════════════════════════════════════════════════════════════════════════
# 3. 관리 유틸
# ══════════════════════════════════════════════════════════════════════════════

def get_whitelist_summary() -> list[dict]:
    return _loader.get_summary()

def get_whitelist_file_path() -> str:
    return _loader.get_file_path()

def get_whitelist_file_mtime() -> str:
    return _loader.get_file_mtime()

def get_whitelist_total() -> int:
    return len(_loader.entries)

def reload_whitelist() -> int:
    return _loader.reload()


def add_whitelist_entry(entry: dict) -> dict:
    """
    global_whitelist.yaml 에 새 엔트리를 추가한다 (페이로드 카드 화이트리스트 버튼).

    entry 예시
    ----------
    {
      "description": "Frame 12 — HTTP GET /healthz (수동 등록)",
      "source":      "user_manual",
      "protocols":   ["HTTP"],
      "match_type":  "payload_text",
      "value":       "GET /healthz",
    }

    Returns
    -------
    {"status": "ok", "total": int} 또는 {"status": "error", "message": str}
    """
    if not YAML_AVAILABLE:
        return {"status": "error", "message": "PyYAML 미설치"}
    if not WHITELIST_FILE.exists():
        return {"status": "error", "message": "global_whitelist.yaml 없음"}

    # 필수 필드 검증
    required = ["description", "match_type"]
    for f in required:
        if not entry.get(f):
            return {"status": "error", "message": f"필수 필드 누락: {f}"}

    match_type = entry.get("match_type", "payload_text")
    if match_type not in ("payload_exact", "payload_hex", "payload_text", "type_code"):
        return {"status": "error", "message": f"알 수 없는 match_type: {match_type}"}

    try:
        with open(WHITELIST_FILE, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        whitelist: list = data.get("whitelist", [])

        # 중복 체크 (value + match_type 기준)
        new_val = str(entry.get("value", "")).strip()
        for existing in whitelist:
            if (existing.get("match_type") == match_type and
                    str(existing.get("value", "")).strip() == new_val):
                return {"status": "duplicate", "message": "이미 동일한 항목이 등록되어 있습니다",
                        "total": len(whitelist)}

        # 엔트리 정규화
        clean: dict = {
            "description": str(entry.get("description", ""))[:120],
            "source":      str(entry.get("source", "user_manual"))[:60],
            "protocols":   entry.get("protocols") or ["ANY"],
            "match_type":  match_type,
        }
        if new_val:
            clean["value"] = new_val
        # ICMP 전용 필드
        if entry.get("icmp_type") is not None:
            clean["icmp_type"] = int(entry["icmp_type"])
        if entry.get("icmp_code") is not None:
            clean["icmp_code"] = int(entry["icmp_code"])

        whitelist.append(clean)
        data["whitelist"] = whitelist

        # 백업 후 저장
        import shutil
        bak = WHITELIST_FILE.with_suffix(".yaml.bak")
        try:
            shutil.copy2(WHITELIST_FILE, bak)
        except Exception:
            pass
        with open(WHITELIST_FILE, "w", encoding="utf-8") as f:
            yaml.dump(data, f, allow_unicode=True,
                      default_flow_style=False, sort_keys=False, indent=2)

        # 로더 재로드
        _loader.reload()
        return {"status": "ok", "total": len(whitelist)}

    except Exception as e:
        return {"status": "error", "message": str(e)}
