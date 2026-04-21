"""
noise_filter_engine.py
======================
의미 없는 payload(노이즈/패딩/제어문자)를 조기에 제외하는 필터 엔진.

noise_filter.yaml 에 정의된 규칙을 순서대로 평가한다.
하나라도 일치하면 즉시 제외 판정을 반환한다.

처리 순서 (protocol_rule_engine.py)
  0a단계: dst_port 443 차단
  0a-2단계: ★ 이 엔진  ←── 여기서 제외
  0b단계: global_whitelist.yaml 대조
  1단계: keyword_rule_engine.py 탐지
  2단계: protocol_rule_engine.py 룰 생성

check_type 목록
---------------
  min_length          : len(payload) <= value
  null_ratio          : NULL 바이트 비율 >= value
  repeat_byte         : 단일 바이트 반복 비율 >= value
  pkcs_padding        : PKCS#5/7 패딩 자동 감지
  seq_pattern         : 연속 증가·감소 시퀀스 >= value bytes
  non_printable_ratio : 비인쇄 문자 비율 >= value (길이 <= min_length_threshold 에서만)
  text_exact_nocase   : ASCII 변환 후 완전 일치 (대소문자 무시)
  hex_exact           : 전체 hex 완전 일치
  hex_prefix          : hex 앞부분 starts-with 매칭
"""

from __future__ import annotations

import datetime
import threading
from pathlib import Path

try:
    import yaml
    YAML_OK = True
except ImportError:
    YAML_OK = False

NOISE_FILE = Path(__file__).parent / "keywords" / "noise_filter.yaml"

_lock = threading.Lock()


# ══════════════════════════════════════════════════════════════════════════════
# 1. YAML 로더 (파일 변경 자동 감지)
# ══════════════════════════════════════════════════════════════════════════════

class NoiseFilterLoader:
    def __init__(self, path: Path = NOISE_FILE):
        self.path    = path
        self._rules: list[dict] = []
        self._mtime: float      = 0.0
        self._load()

    def _load(self) -> None:
        if not YAML_OK:
            self._rules = []; return
        if not self.path.exists():
            print(f"[NoiseFilter] 파일 없음: {self.path}"); self._rules = []; return
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            self._rules = [r for r in (data or {}).get("noise_rules", [])
                           if r.get("enabled", True)]
            self._mtime = self.path.stat().st_mtime
            print(f"[NoiseFilter] 로드 완료 — {len(self._rules)}개 규칙")
        except Exception as e:
            print(f"[NoiseFilter] 로드 실패: {e}"); self._rules = []

    def _check_reload(self) -> None:
        try:
            if self.path.exists() and self.path.stat().st_mtime != self._mtime:
                print("[NoiseFilter] 파일 변경 감지 — 재로드 중...")
                self._load()
        except Exception:
            pass

    @property
    def rules(self) -> list[dict]:
        self._check_reload()
        return self._rules

    def reload(self) -> int:
        self._load()
        return len(self._rules)

    def get_summary(self) -> list[dict]:
        return [
            {
                "description": r.get("description", ""),
                "check_type":  r.get("check_type", ""),
                "value":       r.get("value"),
                "enabled":     r.get("enabled", True),
            }
            for r in self._rules
        ]

    def get_file_path(self) -> str:
        return str(self.path)

    def get_file_mtime(self) -> str:
        try:
            ts = self.path.stat().st_mtime
            return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return "unknown"


_loader = NoiseFilterLoader()


# ══════════════════════════════════════════════════════════════════════════════
# 2. 개별 check_type 판별 함수
# ══════════════════════════════════════════════════════════════════════════════

def _check_min_length(payload: bytes, value) -> bool:
    """payload 길이가 value 이하"""
    try:
        return len(payload) <= int(value)
    except Exception:
        return False


def _check_null_ratio(payload: bytes, value) -> bool:
    """NULL(0x00) 바이트 비율 >= value"""
    if not payload:
        return True
    try:
        ratio = payload.count(0) / len(payload)
        return ratio >= float(value)
    except Exception:
        return False


def _check_repeat_byte(payload: bytes, value) -> bool:
    """
    가장 많이 등장하는 단일 바이트의 비율 >= value.
    예: FF FF FF FF FF FF FF FF → 1.0
    """
    if not payload:
        return True
    try:
        most_common_count = max(payload.count(b) for b in set(payload))
        ratio = most_common_count / len(payload)
        return ratio >= float(value)
    except Exception:
        return False


def _check_pkcs_padding(payload: bytes, _value) -> bool:
    """
    PKCS#5 / PKCS#7 패딩 패턴 감지.
    마지막 N 바이트가 모두 값 N (1 <= N <= 16) 이면 패딩으로 판정.
    payload 전체가 패딩인 경우만 제외 (일반 패킷 오탐 방지).
    """
    if not payload or len(payload) > 32:
        return False
    try:
        pad_val = payload[-1]
        if pad_val < 1 or pad_val > 16:
            return False
        # 전체 payload 가 모두 같은 패딩 바이트인지 확인
        return all(b == pad_val for b in payload)
    except Exception:
        return False


def _check_seq_pattern(payload: bytes, value) -> bool:
    """
    연속 증가 또는 감소 바이트 시퀀스의 길이 >= value.
    예: 00 01 02 03 04 05 06 07 → 증가 시퀀스 길이 8
    """
    if not payload:
        return False
    try:
        min_len = int(value)
        n = len(payload)
        # 증가 방향
        run = 1
        for i in range(1, n):
            if (payload[i] - payload[i-1]) % 256 == 1:
                run += 1
                if run >= min_len:
                    return True
            else:
                run = 1
        # 감소 방향
        run = 1
        for i in range(1, n):
            if (payload[i-1] - payload[i]) % 256 == 1:
                run += 1
                if run >= min_len:
                    return True
            else:
                run = 1
        return False
    except Exception:
        return False


def _check_non_printable_ratio(payload: bytes, value, min_length_threshold) -> bool:
    """
    비인쇄 문자 비율 >= value  AND  len(payload) <= min_length_threshold.
    긴 바이너리 페이로드(실제 공격 패킷)에서 오탐하지 않도록 길이 제한.
    """
    if not payload:
        return True
    try:
        threshold = int(min_length_threshold) if min_length_threshold else 16
        if len(payload) > threshold:
            return False
        non_print = sum(1 for b in payload if not (32 <= b <= 126))
        ratio = non_print / len(payload)
        return ratio >= float(value)
    except Exception:
        return False


def _check_text_exact_nocase(payload: bytes, value: str) -> bool:
    """ASCII 변환 후 대소문자 무시 완전 일치 (공백·\r\n trim)"""
    try:
        text = payload.decode("utf-8", errors="ignore").strip()
        return text.lower() == str(value).lower()
    except Exception:
        return False


def _check_hex_exact(payload: bytes, value: str) -> bool:
    """전체 hex 완전 일치"""
    try:
        wl_hex = value.replace(" ", "").lower()
        return payload.hex() == wl_hex
    except Exception:
        return False


def _check_hex_prefix(payload: bytes, value: str) -> bool:
    """hex 앞부분 starts-with 매칭"""
    try:
        wl_hex = value.replace(" ", "").lower()
        return payload.hex().startswith(wl_hex)
    except Exception:
        return False


# ══════════════════════════════════════════════════════════════════════════════
# 3. 메인 판별 함수
# ══════════════════════════════════════════════════════════════════════════════


def _compute_shannon_entropy(payload: bytes) -> float:
    """
    Shannon Entropy 계산.
    H = -Σ p_i * log2(p_i)  (0 ≤ H ≤ 8)
    - 완전 랜덤/암호화 트래픽: H ≈ 7.5~8.0
    - 일반 텍스트/ASCII:       H ≈ 3.5~5.0
    - 반복 패턴:               H ≈ 0~2.0
    논문 3.2절 기준: H ≥ 4.5 → High-Entropy Noise 판정
    """
    if not payload:
        return 0.0
    counts = [0] * 256
    for b in payload:
        counts[b] += 1
    n = len(payload)
    entropy = 0.0
    for c in counts:
        if c > 0:
            p = c / n
            import math
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def _check_shannon_entropy(payload: bytes, threshold: float = 4.5) -> tuple[bool, float]:
    """
    Shannon Entropy 기반 High-Entropy Noise 탐지.
    threshold: 4.5 (논문 3.2절 기준값)
    암호화·랜덤 트래픽은 H ≥ 4.5 이상을 보임.
    단, DNS/HTTP 프로토콜은 호출하지 말 것 (wire format 특성상 오탐).
    """
    entropy = _compute_shannon_entropy(payload)
    return entropy >= float(threshold), entropy


def _check_irregularity_score(payload: bytes, threshold) -> tuple[bool, float]:
    """
    payload 의 불규칙성 점수를 계산하여 임계값 이상이면 True 반환.

    불규칙성 점수 구성 (0~100 범위):
      A. 특수문자 비율         × 30  (알파벳/숫자/공백 외 문자)
      B. 제어문자(0x00~0x1F) 비율 × 25
      C. 유니코드 카테고리 수  × 20  (정규화: /15)
      D. 비알파벳/숫자 비율    × 15
      E. 대소문자 전환 비율    × 10

    임계값(threshold) 기본값 20 권장:
      - 불규칙 payload (암호화·랜덤·바이너리): 평균 38.8, 최솟값 20.5
      - 정상 문자열 (DNS도메인·명령어 등):  최댓값 12.3
    """
    try:
        import unicodedata as _ud

        threshold = float(threshold)
        text = payload.decode("utf-8", errors="replace")
        n = len(text)
        if n == 0:
            return False, 0.0

        # A. 특수문자 비율
        special  = sum(1 for c in text if not c.isalnum() and not c.isspace())
        spec_r   = special / n

        # B. 제어문자 비율 (0x00~0x1F, DEL 제외 공백 제외)
        ctrl     = sum(1 for c in text if ord(c) < 32 and c not in ('\n', '\r', '\t'))
        ctrl_r   = ctrl / n

        # C. 유니코드 카테고리 수 (정규화)
        cats     = len(set(_ud.category(c) for c in text))
        cat_s    = min(cats / 15.0, 1.0)

        # D. 비알파벳/숫자 비율
        alnum    = sum(1 for c in text if c.isalnum())
        non_al_r = 1.0 - (alnum / n)

        # E. 대소문자 전환 비율
        alphas   = [c for c in text if c.isalpha()]
        if len(alphas) > 1:
            sw   = sum(1 for i in range(len(alphas) - 1)
                       if alphas[i].isupper() != alphas[i+1].isupper())
            case_r = sw / (len(alphas) - 1)
        else:
            case_r = 0.0

        score = (spec_r   * 30 +
                 ctrl_r   * 25 +
                 cat_s    * 20 +
                 non_al_r * 15 +
                 case_r   * 10)

        return score >= threshold, round(score, 1)
    except Exception:
        return False, 0.0


def is_noise(payload: bytes, protocol: str = "") -> dict:
    """
    payload 가 노이즈/패딩인지 판별한다.

    Parameters
    ----------
    payload  : 분석할 payload bytes
    protocol : 상위에서 판별된 프로토콜 문자열 (예: "DNS", "HTTP", "OTHER")
               irregularity_score 체크는 "OTHER" 또는 미지정일 때만 실행됩니다.
               DNS·HTTP·FTP·TELNET·SMTP·ICMP 는 wire format 특성상 제외합니다.

    Returns
    -------
    {
      "noise"  : bool,   # True = 노이즈 → 분석 제외
      "reason" : str,    # 제외 사유 (UI 표시용)
    }
    """
    if not payload:
        return {"noise": True, "reason": "빈 payload"}

    # irregularity_score 를 적용하면 안 되는 프로토콜
    _SKIP_IRREGULARITY = {"DNS", "HTTP", "FTP", "TELNET", "SMTP", "ICMP"}
    proto_upper = (protocol or "").upper()

    for rule in _loader.rules:
        ct    = rule.get("check_type", "")
        val   = rule.get("value")
        desc  = rule.get("description", ct)
        matched = False

        # irregularity_score: OTHER 또는 미지정 프로토콜에만 적용
        if ct == "irregularity_score":
            if proto_upper in _SKIP_IRREGULARITY:
                continue   # DNS·HTTP 등은 건너뜀
            matched, _score = _check_irregularity_score(payload, val if val is not None else 19)
        elif ct == "min_length":
            matched = _check_min_length(payload, val)
        elif ct == "null_ratio":
            matched = _check_null_ratio(payload, val)
        elif ct == "repeat_byte":
            matched = _check_repeat_byte(payload, val)
        elif ct == "pkcs_padding":
            matched = _check_pkcs_padding(payload, val)
        elif ct == "seq_pattern":
            matched = _check_seq_pattern(payload, val)
        elif ct == "non_printable_ratio":
            mlt = rule.get("min_length_threshold", 16)
            matched = _check_non_printable_ratio(payload, val, mlt)
        elif ct == "text_exact_nocase":
            matched = _check_text_exact_nocase(payload, str(val))
        elif ct == "hex_exact":
            matched = _check_hex_exact(payload, str(val))
        elif ct == "hex_prefix":
            matched = _check_hex_prefix(payload, str(val))

        if matched:
            return {"noise": True, "reason": f"노이즈 필터: {desc}"}

    return {"noise": False, "reason": ""}


# ══════════════════════════════════════════════════════════════════════════════
# 4. 관리 유틸
# ══════════════════════════════════════════════════════════════════════════════

def reload_noise_filter() -> int:
    return _loader.reload()

def get_noise_filter_summary() -> list[dict]:
    return _loader.get_summary()

def get_noise_filter_file_path() -> str:
    return _loader.get_file_path()

def get_noise_filter_mtime() -> str:
    return _loader.get_file_mtime()

def get_noise_filter_total() -> int:
    return len(_loader.rules)
