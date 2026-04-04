"""
dns_reputation_engine.py
========================
DNS 쿼리 도메인의 악성 여부를 판별하는 엔진.

처리 흐름
---------
1. dns_whitelist.yaml 대조 → 정상 도메인이면 즉시 SAFE 반환
2. 메모리 캐시 확인 (TTL: 1시간)
3. 영구 캐시 확인 (dns_reputation_cache.yaml)
4. Google Safe Browsing API 조회 (무료, 우선 실행 / MALICIOUS·SUSPICIOUS 탐지 시 VT 생략)
5. VirusTotal API v3 조회 (SB 미탐지 또는 SB 키 없을 때만 실행)
6. 결과 캐시 저장

결과 구조
---------
{
  "verdict"    : "SAFE" | "MALICIOUS" | "SUSPICIOUS" | "UNKNOWN",
  "score"      : int,      # 0 ~ 100 (악성 점수)
  "malicious"  : int,      # VT 악성 판정 엔진 수
  "suspicious" : int,      # VT 의심 판정 엔진 수
  "total"      : int,      # VT 검사 엔진 수
  "source"     : str,      # "whitelist" | "cache" | "virustotal" | "safebrowsing" | "unknown"
  "wl_category": str,      # 화이트리스트 카테고리 (SAFE 시)
  "categories" : [str],    # VT 카테고리 태그
  "reason"     : str,      # 판정 사유 (사람이 읽기용)
}

VirusTotal 판정 기준
---------------------
  malicious >= 3  → MALICIOUS  (Snort 룰 생성)
  malicious >= 1  → SUSPICIOUS (Snort 룰 생성, 낮은 심각도)
  malicious == 0  → SAFE

API 호출 제한 (무료 플랜: 4 req/분, 500 req/일)
  → 캐시 우선, API 호출 최소화
"""

from __future__ import annotations

import json
import threading
import time
import urllib.request
import urllib.error
from pathlib import Path

try:
    import yaml
    YAML_OK = True
except ImportError:
    YAML_OK = False

# ── 경로 ──────────────────────────────────────────────────────────────────────
_BASE         = Path(__file__).parent / "keywords"
WL_FILE       = _BASE / "dns_whitelist.yaml"
CACHE_FILE    = _BASE / "dns_reputation_cache.yaml"
VT_CFG_FILE   = _BASE / "ai_config.yaml"       # VT API 키를 ai_config.yaml 에 함께 관리

# ── 설정 ──────────────────────────────────────────────────────────────────────
VT_API_URL       = "https://www.virustotal.com/api/v3/domains/{domain}"
SB_API_URL       = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
SB_CLIENT_ID     = "pcap-analyzer"
SB_CLIENT_VER    = "1.0"
CACHE_TTL        = 3600          # 메모리 캐시 TTL (초)  — 1시간
DISK_CACHE_MAX   = 5000          # 영구 캐시 최대 항목 수
MALICIOUS_THRESH = 3             # 이 수 이상 → MALICIOUS
SUSPICIOUS_THRESH= 1             # 이 수 이상 → SUSPICIOUS
REQUEST_TIMEOUT  = 8             # VT API 타임아웃 (초)

_lock       = threading.Lock()
_mem_cache: dict[str, dict] = {}   # domain → {result, ts}
_wl_data:   dict            = {}
_wl_mtime:  float           = 0.0


# ══════════════════════════════════════════════════════════════════════════════
# 1. VT API 키 로드
# ══════════════════════════════════════════════════════════════════════════════

def _get_vt_api_key() -> str:
    """ai_config.yaml 의 virustotal.api_key 또는 최상위 virustotal_api_key 를 읽는다."""
    if not YAML_OK:
        return ""
    try:
        if not VT_CFG_FILE.exists():
            return ""
        with open(VT_CFG_FILE, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
        # virustotal 섹션 우선
        vt = cfg.get("virustotal", {})
        if isinstance(vt, dict):
            key = str(vt.get("api_key", "")).strip()
            if key:
                return key
        # 최상위 키 fallback
        return str(cfg.get("virustotal_api_key", "")).strip()
    except Exception:
        return ""


def save_vt_api_key(api_key: str) -> bool:
    """ai_config.yaml 의 virustotal.api_key 를 저장한다."""
    if not YAML_OK:
        return False
    try:
        cfg: dict = {}
        if VT_CFG_FILE.exists():
            with open(VT_CFG_FILE, "r", encoding="utf-8") as f:
                cfg = yaml.safe_load(f) or {}
        if "virustotal" not in cfg or not isinstance(cfg["virustotal"], dict):
            cfg["virustotal"] = {}
        cfg["virustotal"]["api_key"] = api_key.strip()
        with open(VT_CFG_FILE, "w", encoding="utf-8") as f:
            yaml.dump(cfg, f, allow_unicode=True,
                      default_flow_style=False, sort_keys=False, indent=2)
        return True
    except Exception as e:
        print(f"[DNS Rep] VT 키 저장 실패: {e}")
        return False


def _get_sb_api_key() -> str:
    """ai_config.yaml 의 google_safe_browsing.api_key 를 읽는다."""
    try:
        if not YAML_OK or not VT_CFG_FILE.exists():
            return ""
        with open(VT_CFG_FILE, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
        sb = cfg.get("google_safe_browsing", {})
        if isinstance(sb, dict):
            key = str(sb.get("api_key", "")).strip()
            if key and key not in ("null", "None", '""', "''"):
                return key
        return ""
    except Exception:
        return ""


def save_sb_api_key(api_key: str) -> bool:
    """ai_config.yaml 의 google_safe_browsing.api_key 를 저장한다."""
    if not YAML_OK or not VT_CFG_FILE.exists():
        return False
    try:
        with open(VT_CFG_FILE, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
        if "google_safe_browsing" not in cfg or not isinstance(cfg["google_safe_browsing"], dict):
            cfg["google_safe_browsing"] = {}
        cfg["google_safe_browsing"]["api_key"] = api_key.strip()
        with open(VT_CFG_FILE, "w", encoding="utf-8") as f:
            yaml.dump(cfg, f, allow_unicode=True,
                      default_flow_style=False, sort_keys=False, indent=2)
        return True
    except Exception:
        return False


def get_sb_key_status() -> dict:
    """Safe Browsing API 키 설정 상태를 반환한다."""
    key = _get_sb_api_key()
    return {
        "configured": bool(key),
        "masked":     (key[:4] + "****" + key[-4:]) if len(key) >= 8 else ("****" if key else ""),
    }


# ══════════════════════════════════════════════════════════════════════════════
# 2. DNS 화이트리스트 로더
# ══════════════════════════════════════════════════════════════════════════════

def _load_whitelist() -> None:
    global _wl_data, _wl_mtime
    if not YAML_OK or not WL_FILE.exists():
        _wl_data = {}; return
    try:
        mtime = WL_FILE.stat().st_mtime
        if mtime == _wl_mtime and _wl_data:
            return
        with open(WL_FILE, "r", encoding="utf-8") as f:
            _wl_data = yaml.safe_load(f) or {}
        _wl_mtime = mtime
        cnt = len(_wl_data.get("domains", []))
        print(f"[DNS Rep] 화이트리스트 로드 — {cnt}개 도메인")
    except Exception as e:
        print(f"[DNS Rep] 화이트리스트 로드 실패: {e}")
        _wl_data = {}


def _check_whitelist(domain: str) -> dict | None:
    """
    도메인이 화이트리스트에 있으면 엔트리 반환, 없으면 None.
    서브도메인 suffix 매칭 적용 (exact=True 이면 완전 일치만).
    """
    _load_whitelist()
    domain_low = domain.lower().rstrip(".")
    for entry in _wl_data.get("domains", []):
        wl_domain = str(entry.get("domain", "")).lower().rstrip(".")
        if not wl_domain:
            continue
        exact = entry.get("exact", False)
        if exact:
            if domain_low == wl_domain:
                return entry
        else:
            # suffix 매칭: domain이 wl_domain 으로 끝나는지
            if domain_low == wl_domain or domain_low.endswith("." + wl_domain):
                return entry
    return None


# ══════════════════════════════════════════════════════════════════════════════
# 3. 영구 캐시 (YAML)
# ══════════════════════════════════════════════════════════════════════════════

def _load_disk_cache() -> dict:
    if not YAML_OK or not CACHE_FILE.exists():
        return {}
    try:
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}


def _save_disk_cache(domain: str, result: dict) -> None:
    if not YAML_OK:
        return
    try:
        cache = _load_disk_cache()
        cache[domain] = {
            "verdict":    result["verdict"],
            "score":      result["score"],
            "malicious":  result["malicious"],
            "suspicious": result["suspicious"],
            "total":      result["total"],
            "categories": result.get("categories", []),
            "reason":     result["reason"],
            "orig_source": result.get("source", "unknown"),  # ← 원본 출처 보존
            "cached_at":  time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        # 최대 항목 수 제한
        if len(cache) > DISK_CACHE_MAX:
            keys = list(cache.keys())
            for k in keys[:len(cache) - DISK_CACHE_MAX]:
                del cache[k]
        with open(CACHE_FILE, "w", encoding="utf-8") as f:
            yaml.dump(cache, f, allow_unicode=True,
                      default_flow_style=False, sort_keys=False, indent=2)
    except Exception as e:
        print(f"[DNS Rep] 캐시 저장 실패: {e}")


def _get_disk_cache(domain: str) -> dict | None:
    cache = _load_disk_cache()
    return cache.get(domain)


# ══════════════════════════════════════════════════════════════════════════════
# 4. VirusTotal API 호출
# ══════════════════════════════════════════════════════════════════════════════

def _query_virustotal(domain: str, api_key: str) -> dict:
    """
    VirusTotal v3 /domains/{domain} 를 조회하고 결과 dict 를 반환한다.
    API 오류 시 UNKNOWN 결과 반환.
    """
    url = VT_API_URL.format(domain=domain)
    try:
        req = urllib.request.Request(
            url,
            headers={"x-apikey": api_key, "Accept": "application/json"},
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as r:
            raw = json.loads(r.read().decode("utf-8"))

        stats = (raw.get("data", {})
                    .get("attributes", {})
                    .get("last_analysis_stats", {}))

        malicious  = int(stats.get("malicious",  0))
        suspicious = int(stats.get("suspicious", 0))
        harmless   = int(stats.get("harmless",   0))
        undetected = int(stats.get("undetected", 0))
        total      = malicious + suspicious + harmless + undetected

        # VT 카테고리 태그 ({"engine": "category"} 형태)
        cats_raw = (raw.get("data", {})
                       .get("attributes", {})
                       .get("categories", {}))
        categories = list(set(cats_raw.values())) if cats_raw else []

        # 점수 계산: malicious 가중치 3, suspicious 가중치 1
        score = 0
        if total > 0:
            score = min(100, int((malicious * 3 + suspicious) / total * 100))

        # 판정
        if malicious >= MALICIOUS_THRESH:
            verdict = "MALICIOUS"
            reason  = (f"VirusTotal: {malicious}/{total} 엔진 악성 판정"
                       + (f", 의심 {suspicious}개" if suspicious else ""))
        elif malicious >= SUSPICIOUS_THRESH or suspicious >= MALICIOUS_THRESH:
            verdict = "SUSPICIOUS"
            reason  = (f"VirusTotal: {malicious} 악성/{suspicious} 의심 "
                       f"({total}개 엔진 검사)")
        else:
            verdict = "SAFE"
            reason  = f"VirusTotal: 악성 판정 없음 ({total}개 엔진 검사)"

        return {
            "verdict":    verdict,
            "score":      score,
            "malicious":  malicious,
            "suspicious": suspicious,
            "total":      total,
            "source":     "virustotal",
            "wl_category": "",
            "categories": categories,
            "reason":     reason,
        }

    except urllib.error.HTTPError as e:
        if e.code == 404:
            # VT 데이터 없음 → 알 수 없음
            return _unknown(domain, "VirusTotal: 도메인 정보 없음 (신규 또는 희귀 도메인)")
        if e.code == 401:
            return _unknown(domain, "VirusTotal API 키가 유효하지 않습니다")
        if e.code == 429:
            return _unknown(domain, "VirusTotal API 호출 한도 초과")
        return _unknown(domain, f"VirusTotal HTTP 오류: {e.code}")
    except Exception as e:
        return _unknown(domain, f"VirusTotal 조회 실패: {str(e)[:60]}")


def _query_safebrowsing(domain: str, api_key: str) -> dict:
    """
    Google Safe Browsing API v4 threatMatches:find 를 조회하고 결과 dict 를 반환한다.
    - MALWARE, SOCIAL_ENGINEERING, POTENTIALLY_HARMFUL_APPLICATION → MALICIOUS
    - UNWANTED_SOFTWARE                                            → SUSPICIOUS
    - 위협 없음                                                    → SAFE
    - API 오류                                                     → UNKNOWN

    무료 한도: 10,000 req/일
    발급: https://console.cloud.google.com/ → Safe Browsing API 활성화
    """
    url  = f"{SB_API_URL}?key={api_key}"
    uri  = f"http://{domain}/"
    body = json.dumps({
        "client": {
            "clientId":      SB_CLIENT_ID,
            "clientVersion": SB_CLIENT_VER,
        },
        "threatInfo": {
            "threatTypes":      ["MALWARE", "SOCIAL_ENGINEERING",
                                 "UNWANTED_SOFTWARE",
                                 "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes":    ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries":    [{"url": uri}],
        },
    }).encode("utf-8")

    try:
        req = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as r:
            raw = json.loads(r.read().decode("utf-8"))

        matches = raw.get("matches", [])

        if not matches:
            return {
                "verdict":    "SAFE",
                "score":      0,
                "malicious":  0,
                "suspicious": 0,
                "total":      1,
                "source":     "safebrowsing",
                "wl_category": "",
                "categories": [],
                "reason":     "Google Safe Browsing: 위협 없음",
            }

        # 위협 유형 추출 및 판정
        malicious_types  = {"MALWARE", "SOCIAL_ENGINEERING",
                            "POTENTIALLY_HARMFUL_APPLICATION"}
        suspicious_types = {"UNWANTED_SOFTWARE"}

        threat_types = list({m.get("threatType", "") for m in matches})
        matched_mal  = [t for t in threat_types if t in malicious_types]
        matched_sus  = [t for t in threat_types if t in suspicious_types]

        type_names = {
            "MALWARE":                       "악성코드",
            "SOCIAL_ENGINEERING":            "피싱/사기",
            "UNWANTED_SOFTWARE":             "유해 소프트웨어",
            "POTENTIALLY_HARMFUL_APPLICATION": "잠재적 유해 앱",
        }
        labels = [type_names.get(t, t) for t in threat_types]

        if matched_mal:
            verdict = "MALICIOUS"
            score   = 90
        else:
            verdict = "SUSPICIOUS"
            score   = 40

        reason = f"Google Safe Browsing: {', '.join(labels)} 탐지"

        return {
            "verdict":    verdict,
            "score":      score,
            "malicious":  len(matched_mal),
            "suspicious": len(matched_sus),
            "total":      1,
            "source":     "safebrowsing",
            "wl_category": "",
            "categories": labels,
            "reason":     reason,
        }

    except urllib.error.HTTPError as e:
        if e.code == 400:
            return _unknown(domain, "Google Safe Browsing: 잘못된 요청 (URI 형식 오류)")
        if e.code == 403:
            return _unknown(domain, "Google Safe Browsing API 키가 유효하지 않거나 권한 없음")
        if e.code == 429:
            return _unknown(domain, "Google Safe Browsing API 호출 한도 초과")
        return _unknown(domain, f"Google Safe Browsing HTTP 오류: {e.code}")
    except Exception as e:
        return _unknown(domain, f"Google Safe Browsing 조회 실패: {str(e)[:60]}")


def _unknown(domain: str, reason: str) -> dict:
    """UNKNOWN 결과 반환."""
    return {
        "verdict":    "UNKNOWN",
        "score":      0,
        "malicious":  0,
        "suspicious": 0,
        "total":      0,
        "source":     "unknown",
        "wl_category": "",
        "categories": [],
        "reason":     reason,
    }


# ══════════════════════════════════════════════════════════════════════════════
# 5. 메인 판별 함수
# ══════════════════════════════════════════════════════════════════════════════

def check_domain(domain: str) -> dict:
    """
    도메인의 악성 여부를 판별한다.

    Parameters
    ----------
    domain : 조회할 도메인명 (예: "evil.example.com")

    Returns
    -------
    결과 dict (상단 모듈 docstring 참조)
    """
    if not domain:
        return _unknown("", "빈 도메인")

    domain = domain.lower().rstrip(".")

    # ── 1단계: 화이트리스트 ────────────────────────────────────────────────
    wl_entry = _check_whitelist(domain)
    if wl_entry:
        return {
            "verdict":    "SAFE",
            "score":      0,
            "malicious":  0,
            "suspicious": 0,
            "total":      0,
            "source":     "whitelist",
            "wl_category": wl_entry.get("category", ""),
            "categories": [],
            "reason":     f"화이트리스트 일치: {wl_entry.get('category','')} — {wl_entry.get('note','')}",
        }

    # ── 2단계: 메모리 캐시 ────────────────────────────────────────────────
    with _lock:
        cached = _mem_cache.get(domain)
        if cached and (time.time() - cached["ts"]) < CACHE_TTL:
            result = dict(cached["result"])
            result["source"] = "cache"
            return result

    # ── 3단계: 영구 캐시 ──────────────────────────────────────────────────
    disk = _get_disk_cache(domain)
    if disk:
        # orig_source: 이전 버전 캐시 호환 (없으면 reason으로 유추)
        orig_source = disk.get("orig_source", "")
        if not orig_source:
            reason_lower = disk.get("reason", "").lower()
            if "safe browsing" in reason_lower:
                orig_source = "safebrowsing"
            elif "virustotal" in reason_lower:
                orig_source = "virustotal"
            else:
                orig_source = "unknown"

        result = {
            "verdict":    disk.get("verdict",    "UNKNOWN"),
            "score":      disk.get("score",      0),
            "malicious":  disk.get("malicious",  0),
            "suspicious": disk.get("suspicious", 0),
            "total":      disk.get("total",      0),
            "source":     orig_source,   # ← 원본 출처 유지 (VT/SB 구분용)
            "wl_category": "",
            "categories": disk.get("categories", []),
            "reason":     disk.get("reason", "") + " (캐시)",
        }
        with _lock:
            _mem_cache[domain] = {"result": result, "ts": time.time()}
        return result

    # ── 4단계: Safe Browsing API 조회 (무료, 우선 실행) ─────────────────
    sb_key = _get_sb_api_key()
    result = None

    if sb_key:
        print(f"[DNS Rep] Safe Browsing 조회: {domain}")
        result = _query_safebrowsing(domain, sb_key)
        # SB가 위협 탐지 → VT 추가 조회 없이 바로 반환
        if result["verdict"] in ("MALICIOUS", "SUSPICIOUS"):
            print(f"[DNS Rep] Safe Browsing 탐지: {domain} → {result['verdict']}")
        else:
            # SB가 SAFE 또는 UNKNOWN → VT로 추가 확인
            sb_result = result   # SB 결과 보존 (reason 참조용)
            result = None        # VT 단계로 진입

    # ── 5단계: VirusTotal API 조회 (SB 미탐지 또는 SB 키 없을 때) ────────
    if result is None:
        vt_key = _get_vt_api_key()
        if vt_key:
            print(f"[DNS Rep] VirusTotal 조회: {domain}")
            result = _query_virustotal(domain, vt_key)
            # VT 429/401 → UNKNOWN 으로 남김
        else:
            # VT 키도 없음
            if sb_key:
                # SB는 조회했으나 SAFE/UNKNOWN → SB 결과를 최종 사용
                result = sb_result  # noqa: F821
                if result["verdict"] == "UNKNOWN":
                    result["reason"] += " | VirusTotal API 키 미설정"
            else:
                # SB도 VT도 없음
                result = _unknown(domain,
                    "Safe Browsing API 키 미설정 — /dns-reputation 에서 등록하세요 "
                    "| VirusTotal API 키 미설정")


    # 캐시 저장 (SAFE/MALICIOUS/SUSPICIOUS 만 — UNKNOWN 은 캐시 안 함)
    if result["verdict"] != "UNKNOWN":
        with _lock:
            _mem_cache[domain] = {"result": result, "ts": time.time()}
        _save_disk_cache(domain, result)
    else:
        # UNKNOWN도 메모리 캐시에 단기 저장 (반복 조회 방지, TTL 5분)
        with _lock:
            _mem_cache[domain] = {"result": result, "ts": time.time() - (CACHE_TTL - 300)}

    return result


# ══════════════════════════════════════════════════════════════════════════════
# 6. 캐시 관리 유틸
# ══════════════════════════════════════════════════════════════════════════════

def get_cache_stats() -> dict:
    disk = _load_disk_cache()
    malicious  = sum(1 for v in disk.values() if v.get("verdict") == "MALICIOUS")
    suspicious = sum(1 for v in disk.values() if v.get("verdict") == "SUSPICIOUS")
    safe       = sum(1 for v in disk.values() if v.get("verdict") == "SAFE")
    return {
        "total":      len(disk),
        "malicious":  malicious,
        "suspicious": suspicious,
        "safe":       safe,
        "mem_cache":  len(_mem_cache),
    }


def get_cache_entries(limit: int = 200) -> list[dict]:
    disk = _load_disk_cache()
    items = [{"domain": k, **v} for k, v in disk.items()]
    # 악성 → 의심 → 기타 순서로 정렬
    order = {"MALICIOUS": 0, "SUSPICIOUS": 1, "SAFE": 2, "UNKNOWN": 3}
    items.sort(key=lambda x: (order.get(x.get("verdict", "UNKNOWN"), 3),
                               x.get("domain", "")))
    return items[:limit]


def delete_cache_entry(domain: str) -> bool:
    if not YAML_OK or not CACHE_FILE.exists():
        return False
    try:
        cache = _load_disk_cache()
        if domain in cache:
            del cache[domain]
            with open(CACHE_FILE, "w", encoding="utf-8") as f:
                yaml.dump(cache, f, allow_unicode=True,
                          default_flow_style=False, sort_keys=False, indent=2)
            with _lock:
                _mem_cache.pop(domain, None)
            return True
        return False
    except Exception as e:
        print(f"[DNS Rep] 캐시 삭제 실패: {e}")
        return False


def clear_mem_cache() -> int:
    with _lock:
        count = len(_mem_cache)
        _mem_cache.clear()
    return count


def reload_whitelist() -> int:
    global _wl_mtime
    _wl_mtime = 0.0
    _load_whitelist()
    return len(_wl_data.get("domains", []))


def get_whitelist_domains() -> list[dict]:
    _load_whitelist()
    return _wl_data.get("domains", [])


def get_vt_key_status() -> dict:
    key = _get_vt_api_key()
    return {
        "configured": bool(key),
        "key_preview": (key[:8] + "..." + key[-4:]) if len(key) > 12 else ("설정됨" if key else "미설정"),
    }
