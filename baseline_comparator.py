"""
baseline_comparator.py  v2
==========================
PCAP-Analyzer 자동 생성 Snort 룰과 공개 Baseline 룰셋을 정량 비교하는 엔진.

SCIE 논문 Evaluation 섹션 직접 활용 지표
-----------------------------------------
  Alert Count        : PCAP 각 패킷에 룰 content 매칭 수행
  Unique Signatures  : 매칭에 기여한 고유 룰(SID) 수
  Precision          : TP / (TP + FP)
  Recall             : TP / (TP + FN)
  F1-Score           : 2·P·R / (P+R)
  False Positive Rate: FP / (FP + TN)
  Specificity Score  : content 길이·옵션 수·nocase 복합 지표 (0~100)
  Jaccard Similarity : |A∩B| / |A∪B|  (content fingerprint 기반)

출력 형식: JSON / 텍스트 리포트(논문 Table) / CSV(Excel 호환 UTF-8 BOM)

다운로드 지원 (HTTP, 무료, 설치 불필요)
  - Emerging Threats Open  (Snort 2.9 / Suricata 6.0)
  - 로컬 .rules 파일 직접 로드

Windows 호환: urllib 전용, 외부 바이너리 불필요
Python 의존: scapy (requirements.txt 포함)
"""

from __future__ import annotations

import csv
import gzip
import hashlib
import io
import json
import os
import re
import tarfile
import time
import urllib.error
import urllib.request
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# ──────────────────────────────────────────────────────────────────────────────
# 0. 경로
# ──────────────────────────────────────────────────────────────────────────────

_BASE_DIR      = Path(__file__).parent
_BASELINES_DIR = _BASE_DIR / "baselines"
_BASELINES_DIR.mkdir(exist_ok=True)

# ──────────────────────────────────────────────────────────────────────────────
# 1. 데이터 구조
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class ParsedRule:
    raw:           str
    action:        str        = "alert"
    proto:         str        = ""
    src_ip:        str        = "any"
    src_port:      str        = "any"
    direction:     str        = "->"
    dst_ip:        str        = "any"
    dst_port:      str        = "any"
    msg:           str        = ""
    sid:           int        = 0
    rev:           int        = 1
    contents:      List[str]  = field(default_factory=list)
    pcre_patterns: List[str]  = field(default_factory=list)
    options_raw:   str        = ""
    severity:      str        = "UNKNOWN"
    attack_cat:    str        = "UNKNOWN"
    has_nocase:    bool       = False
    has_pcre:      bool       = False
    option_count:  int        = 0
    content_len:   int        = 0
    source_label:  str        = ""
    fingerprint:   str        = ""


@dataclass
class AlertResult:
    label:             str   = ""
    rule_count:        int   = 0
    alert_count:       int   = 0
    unique_sids:       int   = 0
    tp:                int   = 0
    fp:                int   = 0
    fn:                int   = 0
    tn:                int   = 0
    precision:         float = 0.0
    recall:            float = 0.0
    f1:                float = 0.0
    fpr:               float = 0.0
    specificity:       float = 0.0   # TNR = TN/(TN+FP)
    specificity_score: float = 0.0   # content 패턴 복합 점수
    uniqueness_ratio:  float = 0.0
    jaccard:           float = 0.0
    overlap:           int   = 0
    only_in_target:    int   = 0
    only_in_pcap:      int   = 0
    proto_coverage:    Dict  = field(default_factory=dict)
    attack_coverage:   Dict  = field(default_factory=dict)
    severity_dist:     Dict  = field(default_factory=dict)
    avg_options:       float = 0.0
    avg_content_len:   float = 0.0


# ──────────────────────────────────────────────────────────────────────────────
# 2. 파서
# ──────────────────────────────────────────────────────────────────────────────

_SEV_MAP = {
    "CRITICAL":4, "HIGH":3, "MEDIUM":2, "LOW":1,
    "EXPLOIT":4, "MALWARE":4, "TROJAN":4, "PHISHING":3,
    "SCAN":2, "POLICY":1,
}

_ATTACK_CATS = [
    (r"\bDNS\b",                         "DNS"),
    (r"\bHTTP\b|\bWEB\b|\bURL\b",        "HTTP"),
    (r"\bFTP\b",                         "FTP"),
    (r"\bSMTP\b|\bEMAIL\b",             "SMTP"),
    (r"\bTELNET\b|\bSSH\b",             "TELNET"),
    (r"SQL.?INJECT|SQLi\b",              "SQL_INJECTION"),
    (r"\bXSS\b|CROSS.SITE",             "XSS"),
    (r"PATH.TRAV|DIR.TRAV",              "PATH_TRAVERSAL"),
    (r"\bLOG4\b|\bJNDI\b",             "LOG4SHELL"),
    (r"\bSCAN\b|\bNMAP\b",             "PORTSCAN"),
    (r"\bTYPO\b|\bPHISH\b|\bFAKE\b",   "PHISHING"),
    (r"\bMALWARE\b|\bTROJAN\b",        "MALWARE"),
    (r"\bBOTNET\b|\bC2\b",             "C2"),
    (r"\bBRUTE\b|\bCRED\b",            "BRUTEFORCE"),
    (r"\bRCE\b|\bEXECUT\b",            "RCE"),
]


def _infer_severity(msg: str) -> str:
    m = msg.upper()
    for kw, lvl in sorted(_SEV_MAP.items(), key=lambda x: -x[1]):
        if kw in m:
            if lvl >= 4: return "CRITICAL"
            if lvl == 3: return "HIGH"
            if lvl == 2: return "MEDIUM"
            if lvl == 1: return "LOW"
    return "INFO"


def _infer_attack_cat(msg: str, proto: str) -> str:
    m = msg.upper()
    for pat, cat in _ATTACK_CATS:
        if re.search(pat, m):
            return cat
    return {"udp":"DNS","tcp":"HTTP","icmp":"ICMP"}.get(proto.lower(), "GENERIC")


def parse_rule(raw: str, source_label: str = "") -> Optional[ParsedRule]:
    line = raw.strip()
    if not line or line.startswith("#"):
        return None
    m = re.match(
        r'^(alert|drop|pass|log|reject)\s+(\w+)\s+(\S+)\s+(\S+)\s+'
        r'(->|<>|<-)\s+(\S+)\s+(\S+)\s*\((.+)\)\s*$',
        line, re.DOTALL
    )
    if not m:
        return None
    action, proto, si, sp, direction, di, dp, opts = m.groups()
    r = ParsedRule(raw=raw, source_label=source_label,
                   action=action, proto=proto.lower(),
                   src_ip=si, src_port=sp, direction=direction,
                   dst_ip=di, dst_port=dp, options_raw=opts)

    msg_m  = re.search(r'msg\s*:\s*"([^"]*)"', opts)
    r.msg  = msg_m.group(1) if msg_m else ""
    sid_m  = re.search(r'\bsid\s*:\s*(\d+)', opts)
    r.sid  = int(sid_m.group(1)) if sid_m else 0
    rev_m  = re.search(r'\brev\s*:\s*(\d+)', opts)
    r.rev  = int(rev_m.group(1)) if rev_m else 1

    r.contents      = re.findall(r'content\s*:\s*"([^"]*)"', opts)
    r.pcre_patterns = re.findall(r'pcre\s*:\s*"([^"]*)"', opts)
    r.has_nocase    = bool(re.search(r'\bnocase\b', opts))
    r.has_pcre      = bool(r.pcre_patterns)

    kws = re.findall(
        r'\b(content|pcre|offset|depth|distance|within|nocase|'
        r'http_uri|http_header|http_client_body|dsize|flags|flow|'
        r'threshold|classtype|reference|metadata)\b', opts
    )
    r.option_count = len(kws)
    r.content_len  = sum(len(c) for c in r.contents)
    r.severity     = _infer_severity(r.msg)
    r.attack_cat   = _infer_attack_cat(r.msg, proto)

    fp_src      = "|".join(sorted(c.lower() for c in r.contents)) or r.msg.lower()
    r.fingerprint = hashlib.sha256(fp_src.encode()).hexdigest()[:16]
    return r


def parse_rules_from_text(text: str, source_label: str = "") -> List[ParsedRule]:
    return [r for line in text.splitlines()
            if (r := parse_rule(line.strip(), source_label))]


def parse_rules_from_file(path: str | Path, source_label: str = "") -> List[ParsedRule]:
    try:
        text = Path(path).read_text(encoding="utf-8", errors="ignore")
        return parse_rules_from_text(text, source_label or Path(path).stem)
    except Exception as e:
        print(f"[Baseline] 파일 읽기 실패 ({path}): {e}")
        return []


# ──────────────────────────────────────────────────────────────────────────────
# 3. 룰 다운로더
# ──────────────────────────────────────────────────────────────────────────────

_DL_TIMEOUT   = 30
_USER_AGENT   = "PCAP-Analyzer-BaselineComparator/2.0"

# ET Open 공식 URL (2024 이후 /rules/ 하위 디렉터리)
_ET_BASE = {
    "snort":    "https://rules.emergingthreats.net/open/snort-2.9.0/rules",
    "suricata": "https://rules.emergingthreats.net/open/suricata-6.0/rules",
}
# 번들 tar.gz (전체 룰셋)
_ET_BUNDLE = {
    "snort":    "https://rules.emergingthreats.net/open/snort-2.9.0/emerging.rules.tar.gz",
    "suricata": "https://rules.emergingthreats.net/open/suricata-6.0/emerging.rules.tar.gz",
}
# GitHub 미러 (ET 서버 장애 시 fallback)
_GITHUB_MIRROR = "https://raw.githubusercontent.com/EmergingThreats/et-open/master/rules"
# Snort Community Rules
_SNORT_COMMUNITY = "https://www.snort.org/downloads/community/community-rules.tar.gz"

# ET Open 카테고리 목록 (2024 현행 파일명 기준)
# emerging-phishing.rules 는 폐기 → emerging-phishing-new.rules 로 대체
ET_CATEGORIES = [
    "emerging-dns",
    "emerging-web_client",
    "emerging-web_server",
    "emerging-malware",
    "emerging-phishing-new",             # phishing (폐기된 emerging-phishing 대체)
    "emerging-phishing-new-with-fqdn",   # phishing FQDN 버전
    "emerging-trojan",
    "emerging-scan",
    "emerging-exploit",
    "emerging-ftp",
    "emerging-smtp",
    "emerging-sql",
    "emerging-shellcode",
    "emerging-dos",
    "emerging-mobile_malware",
]

# 폐기된 카테고리 → 대체 매핑 (사용자가 구 이름으로 요청할 때 자동 변환)
_DEPRECATED_CATS = {
    "emerging-phishing": "emerging-phishing-new",
}


def list_available_rulesets() -> List[Dict]:
    """
    다운로드 가능한 룰셋 목록.
    각 항목에 primary URL 과 fallback URL 포함.
    """
    items = []
    for engine in ("snort", "suricata"):
        for cat in ET_CATEGORIES:
            primary  = f"{_ET_BASE[engine]}/{cat}.rules"
            fallback = f"{_GITHUB_MIRROR}/{cat}.rules"
            items.append({
                "id":        f"et_{engine}_{cat}",
                "label":     f"ET Open ({engine.capitalize()}) — {cat}",
                "engine":    engine,
                "category":  cat,
                "url":       primary,
                "url_fallback": fallback,
                "type":      "single",
                "size_hint": "~50–500 KB",
            })
        items.append({
            "id":        f"et_bundle_{engine}",
            "label":     f"ET Open Bundle — {engine.capitalize()} 전체 (~10 MB)",
            "engine":    engine,
            "url":       _ET_BUNDLE[engine],
            "url_fallback": None,
            "type":      "bundle",
            "size_hint": "~10 MB",
        })
    # GitHub 미러 단독 항목 (ET 서버 접근 불가 시 대안)
    for cat in ET_CATEGORIES[:5]:   # 주요 5개만
        items.append({
            "id":        f"github_{cat}",
            "label":     f"GitHub Mirror — {cat}",
            "engine":    "suricata",
            "category":  cat,
            "url":       f"{_GITHUB_MIRROR}/{cat}.rules",
            "url_fallback": None,
            "type":      "single",
            "size_hint": "~50–500 KB",
            "source":    "github",
        })
    return items


def _resolve_deprecated_url(url: str) -> str:
    """폐기된 카테고리 URL을 현행 URL로 자동 변환"""
    for old, new in _DEPRECATED_CATS.items():
        url = url.replace(old + ".rules", new + ".rules")
    return url


def download_ruleset(
    url:         str,
    label:       str                    = "",
    save_to:     Optional[Path]         = None,
    progress_cb                         = None,
    fallback_url: Optional[str]         = None,
) -> Tuple[List[ParsedRule], str]:
    """
    URL에서 .rules 또는 .tar.gz 번들 다운로드 → 파싱.
    primary URL 실패 시 fallback_url 자동 시도.

    Returns (rules_list, status_message)
    Windows urllib 기반, 외부 도구 불필요.
    """
    url   = _resolve_deprecated_url(url)
    label = label or url.split("/")[-1]
    req   = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=_DL_TIMEOUT) as resp:
            total  = int(resp.headers.get("Content-Length", 0))
            chunks = []
            done   = 0
            while True:
                chunk = resp.read(65536)
                if not chunk: break
                chunks.append(chunk)
                done += len(chunk)
                if progress_cb:
                    progress_cb(done, total)
            raw_bytes = b"".join(chunks)
    except urllib.error.HTTPError as e:
        err_msg = f"HTTP {e.code}: {e.reason}"
        if fallback_url:
            print(f"[Baseline] {url} → {err_msg}, fallback 시도: {fallback_url}")
            return download_ruleset(fallback_url, label, save_to, progress_cb)
        return [], err_msg
    except Exception as e:
        err_msg = f"다운로드 실패: {str(e)[:80]}"
        if fallback_url:
            print(f"[Baseline] {url} → {err_msg}, fallback 시도: {fallback_url}")
            return download_ruleset(fallback_url, label, save_to, progress_cb)
        return [], err_msg

    if save_to:
        try:
            Path(save_to).parent.mkdir(parents=True, exist_ok=True)
            Path(save_to).write_bytes(raw_bytes)
        except Exception:
            pass

    fname = url.split("/")[-1].lower()
    rules: List[ParsedRule] = []

    if fname.endswith(".tar.gz") or fname.endswith(".tgz"):
        try:
            with tarfile.open(fileobj=io.BytesIO(raw_bytes), mode="r:gz") as tf:
                for member in tf.getmembers():
                    if member.name.endswith(".rules"):
                        f = tf.extractfile(member)
                        if f:
                            text = f.read().decode("utf-8", errors="ignore")
                            sub  = f"{label}/{member.name.split('/')[-1]}"
                            rules.extend(parse_rules_from_text(text, sub))
        except Exception as e:
            return [], f"tar.gz 파싱 실패: {e}"
    elif fname.endswith(".gz"):
        try:
            text  = gzip.decompress(raw_bytes).decode("utf-8", errors="ignore")
            rules = parse_rules_from_text(text, label)
        except Exception as e:
            return [], f"gzip 파싱 실패: {e}"
    else:
        text  = raw_bytes.decode("utf-8", errors="ignore")
        rules = parse_rules_from_text(text, label)

    return rules, f"완료: {len(rules)}개 룰  ({len(raw_bytes)//1024} KB)"


def load_or_download_et(
    category: str,
    engine:   str  = "snort",
    force:    bool = False,
) -> Tuple[List[ParsedRule], str]:
    """캐시 우선 로드, 없으면 ET Open 다운로드"""
    cache = _BASELINES_DIR / f"{category}_{engine}.rules"
    if cache.exists() and not force:
        rules = parse_rules_from_file(cache, f"{category}_{engine}")
        return rules, f"캐시 로드: {len(rules)}개 룰"
    url      = f"{_ET_BASE[engine]}/{category}.rules"
    fallback = f"{_GITHUB_MIRROR}/{category}.rules"
    return download_ruleset(url, f"{category}_{engine}", cache, fallback_url=fallback)


def get_cached_baselines() -> Dict[str, List[ParsedRule]]:
    """baselines/ 디렉터리의 모든 .rules 파일 로드"""
    result = {}
    for f in sorted(_BASELINES_DIR.glob("*.rules")):
        rules = parse_rules_from_file(f)
        if rules:
            result[f.stem] = rules
    return result


# ──────────────────────────────────────────────────────────────────────────────
# 4. PCAP 기반 Alert 시뮬레이터
# ──────────────────────────────────────────────────────────────────────────────

def _content_match(content: str, payload: bytes, nocase: bool) -> bool:
    """단일 content 패턴이 payload 바이트에 있는지 확인"""
    # |xx xx| hex 패턴
    hex_parts = re.findall(r'\|([0-9a-fA-F\s]+)\|', content)
    if hex_parts:
        try:
            needle = bytes.fromhex("".join(hex_parts[0].split()))
            return needle in payload
        except ValueError:
            pass
    needle_str = re.sub(r'\|[^|]+\|', '', content).strip()
    if not needle_str:
        return True
    try:
        needle_b = needle_str.encode("utf-8", errors="ignore")
        if nocase:
            return needle_b.lower() in payload.lower()
        return needle_b in payload
    except Exception:
        return False


def match_rule_on_payload(rule: ParsedRule, payload: bytes) -> bool:
    """
    룰의 모든 content 패턴이 payload에 매칭되는지 확인.
    (AND 매칭, distance/offset/depth는 논문 시뮬레이션 수준에서 무시)
    """
    if not rule.contents and not rule.pcre_patterns:
        return False
    for c in rule.contents:
        if not _content_match(c, payload, rule.has_nocase):
            return False
    for pat in rule.pcre_patterns:
        try:
            flags = re.IGNORECASE if "i" in pat.split("/")[-1] else 0
            body  = "/".join(pat.split("/")[1:-1])
            if not re.search(body, payload.decode("utf-8", errors="ignore"), flags):
                return False
        except Exception:
            pass
    return True


def _extract_pkt_payload(pkt) -> bytes:
    """scapy 패킷에서 payload 바이트 추출 (Raw → DNS → UDP → TCP 순)"""
    try:
        from scapy.all import Raw, DNS, UDP, TCP
        if Raw in pkt:   return bytes(pkt[Raw].load)
        if DNS in pkt:   return bytes(pkt[DNS])
        if UDP in pkt:   return bytes(pkt[UDP].payload) if pkt[UDP].payload else b""
        if TCP in pkt:   return bytes(pkt[TCP].payload) if pkt[TCP].payload else b""
    except Exception:
        pass
    return b""


def simulate_alerts(
    rules:         List[ParsedRule],
    pcap_packets:  list,
    malicious_idx: Set[int],
    label:         str = "ruleset",
) -> AlertResult:
    """
    룰 집합을 PCAP 패킷에 적용하여 AlertResult 산출.

    malicious_idx : 악성으로 레이블된 패킷 인덱스 집합 (ground-truth)
    """
    res = AlertResult(label=label, rule_count=len(rules))
    total  = len(pcap_packets)
    normal = set(range(total)) - malicious_idx

    alerted: Set[int] = set()
    sids:    Set[int] = set()

    for idx, pkt in enumerate(pcap_packets):
        payload = _extract_pkt_payload(pkt)
        if not payload:
            continue
        for rule in rules:
            if match_rule_on_payload(rule, payload):
                alerted.add(idx)
                sids.add(rule.sid)

    tp = len(alerted & malicious_idx)
    fp = len(alerted & normal)
    fn = len(malicious_idx - alerted)
    tn = len(normal - alerted)

    res.alert_count = len(alerted)
    res.unique_sids = len(sids)
    res.tp = tp; res.fp = fp; res.fn = fn; res.tn = tn

    res.precision   = round(tp/(tp+fp),   4) if (tp+fp) else 0.0
    res.recall      = round(tp/(tp+fn),   4) if (tp+fn) else 0.0
    res.f1          = round(2*res.precision*res.recall/(res.precision+res.recall), 4) \
                      if (res.precision+res.recall) else 0.0
    res.fpr         = round(fp/(fp+tn),   4) if (fp+tn) else 0.0
    res.specificity = round(tn/(tn+fp),   4) if (tn+fp) else 0.0
    return res


def build_malicious_idx(
    pcap_rules:   List[ParsedRule],
    pcap_packets: list,
) -> Set[int]:
    """
    PCAP-Analyzer 룰로 alert된 패킷 인덱스를 Pseudo Ground-Truth 악성 레이블로 사용.
    실제 레이블 파일이 없을 때 대안.
    """
    malicious: Set[int] = set()
    for idx, pkt in enumerate(pcap_packets):
        payload = _extract_pkt_payload(pkt)
        if not payload: continue
        for rule in pcap_rules:
            if match_rule_on_payload(rule, payload):
                malicious.add(idx)
                break
    return malicious


# ──────────────────────────────────────────────────────────────────────────────
# 5. 정적 비교 지표
# ──────────────────────────────────────────────────────────────────────────────

def _specificity_score(rules: List[ParsedRule]) -> float:
    if not rules: return 0.0
    avg_len  = sum(r.content_len  for r in rules) / len(rules)
    avg_opts = sum(r.option_count for r in rules) / len(rules)
    nc_ratio = sum(1 for r in rules if r.has_nocase or r.has_pcre) / len(rules)
    return round(min(avg_len/40,1)*40 + min(avg_opts/8,1)*40 + nc_ratio*20, 2)


def _uniqueness_ratio(rules: List[ParsedRule]) -> float:
    if not rules: return 0.0
    return round(len({r.fingerprint for r in rules}) / len(rules) * 100, 1)


def _overlap_stats(a: List[ParsedRule], b: List[ParsedRule]):
    fa = {r.fingerprint for r in a}
    fb = {r.fingerprint for r in b}
    inter = fa & fb; union = fa | fb
    jaccard = round(len(inter)/len(union), 4) if union else 0.0
    return len(inter), len(fa-fb), len(fb-fa), jaccard


def _severity_dist(rules: List[ParsedRule]) -> Dict:
    cnt   = Counter(r.severity for r in rules)
    total = len(rules) or 1
    return {k: round(v/total*100, 1) for k, v in cnt.items()}


def _safe_avg(lst, attr):
    return round(sum(getattr(r, attr) for r in lst) / len(lst), 2) if lst else 0.0


# ──────────────────────────────────────────────────────────────────────────────
# 6. 전체 비교 실행
# ──────────────────────────────────────────────────────────────────────────────

def run_evaluation(
    pcap_rules:    List[ParsedRule],
    baselines:     Dict[str, List[ParsedRule]],
    pcap_packets:  Optional[list] = None,
    malicious_idx: Optional[Set[int]] = None,
) -> Dict[str, AlertResult]:
    """
    PCAP-Analyzer 룰과 각 베이스라인을 비교.
    pcap_packets 가 None이면 정적 분석만 수행.
    """
    if pcap_packets is not None and malicious_idx is None:
        malicious_idx = build_malicious_idx(pcap_rules, pcap_packets)

    results: Dict[str, AlertResult] = {}

    # ── PCAP-Analyzer 자신 평가 ─────────────────────────────────────────────
    if pcap_packets is not None:
        pcap_res = simulate_alerts(pcap_rules, pcap_packets, malicious_idx, "PCAP-Analyzer")
    else:
        pcap_res = AlertResult(label="PCAP-Analyzer", rule_count=len(pcap_rules))
    pcap_res.specificity_score = _specificity_score(pcap_rules)
    pcap_res.uniqueness_ratio  = _uniqueness_ratio(pcap_rules)
    pcap_res.proto_coverage    = dict(Counter(r.proto for r in pcap_rules))
    pcap_res.attack_coverage   = dict(Counter(r.attack_cat for r in pcap_rules))
    pcap_res.severity_dist     = _severity_dist(pcap_rules)
    pcap_res.avg_options       = _safe_avg(pcap_rules, "option_count")
    pcap_res.avg_content_len   = _safe_avg(pcap_rules, "content_len")
    results["PCAP-Analyzer"]   = pcap_res

    # ── 베이스라인 평가 ─────────────────────────────────────────────────────
    for label, bl_rules in baselines.items():
        if pcap_packets is not None:
            res = simulate_alerts(bl_rules, pcap_packets, malicious_idx, label)
        else:
            res = AlertResult(label=label, rule_count=len(bl_rules))
            # 정적 Pseudo Precision/Recall (공격 유형 커버리지 기반)
            gt        = {r.attack_cat for r in pcap_rules} | {r.attack_cat for r in bl_rules}
            cov_bl    = {r.attack_cat for r in bl_rules} & gt
            rule_cats = {r.attack_cat for r in bl_rules}
            tp = len(cov_bl); fp = len(rule_cats-gt); fn = len(gt-rule_cats)
            res.precision = round(tp/(tp+fp),4) if (tp+fp) else 0.0
            res.recall    = round(tp/(tp+fn),4) if (tp+fn) else 0.0
            res.f1 = round(2*res.precision*res.recall/(res.precision+res.recall),4) \
                     if (res.precision+res.recall) else 0.0

        overlap, only_pcap, only_bl, jaccard = _overlap_stats(pcap_rules, bl_rules)
        res.specificity_score = _specificity_score(bl_rules)
        res.uniqueness_ratio  = _uniqueness_ratio(bl_rules)
        res.overlap           = overlap
        res.only_in_pcap      = only_pcap
        res.only_in_target    = only_bl
        res.jaccard           = jaccard
        res.proto_coverage    = dict(Counter(r.proto for r in bl_rules))
        res.attack_coverage   = dict(Counter(r.attack_cat for r in bl_rules))
        res.severity_dist     = _severity_dist(bl_rules)
        res.avg_options       = _safe_avg(bl_rules, "option_count")
        res.avg_content_len   = _safe_avg(bl_rules, "content_len")
        results[label]        = res

    return results


# ──────────────────────────────────────────────────────────────────────────────
# 7. 리포트 생성
# ──────────────────────────────────────────────────────────────────────────────

def _bar(v, w=20, mx=100.0):
    f = int(round(v/mx*w)); return "█"*f + "░"*(w-f)


def generate_text_report(results: Dict[str, AlertResult]) -> str:
    lines   = []
    ts      = time.strftime("%Y-%m-%d %H:%M:%S")
    pcap    = results.get("PCAP-Analyzer")
    bls     = {k:v for k,v in results.items() if k != "PCAP-Analyzer"}
    has_sim = pcap and (pcap.alert_count > 0 or pcap.tp + pcap.fp > 0)

    lines += [
        "="*98,
        "  PCAP-Analyzer — Snort Rule Evaluation Report",
        "  SCIE Paper Evaluation Section",
        "="*98,
        f"  Generated : {ts}",
        f"  Mode      : {'PCAP Simulation (scapy content-match)' if has_sim else 'Static Analysis (rule-level)'}",
        f"  Systems   : {len(results)} ({', '.join(results.keys())})",
        "",
    ]

    # Table 1: Summary
    lines += [
        "─"*98,
        "  Table 1. Rule Count & Detection Performance Summary",
        "─"*98,
        f"  {'System':<26} {'Rules':>6} {'Alerts':>7} {'UniSIDs':>8} "
        f"{'Precision':>10} {'Recall':>8} {'F1':>8} {'FPR':>8} {'Jaccard':>8}",
        "  "+"-"*84,
    ]
    for label, r in results.items():
        mark = "★ " if label == "PCAP-Analyzer" else "  "
        lines.append(
            f"  {mark+label:<26} {r.rule_count:>6} {r.alert_count:>7} {r.unique_sids:>8} "
            f"{r.precision:>10.4f} {r.recall:>8.4f} {r.f1:>8.4f} "
            f"{r.fpr:>8.4f} {r.jaccard:>8.4f}"
        )
    lines.append("")

    # Table 2: Confusion Matrix (PCAP 시뮬레이션 시만)
    if has_sim:
        lines += [
            "─"*98,
            "  Table 2. Confusion Matrix (PCAP Simulation)",
            "─"*98,
            f"  {'System':<26} {'TP':>7} {'FP':>7} {'FN':>7} {'TN':>7} {'Specificity(TNR)':>17}",
            "  "+"-"*72,
        ]
        for label, r in results.items():
            lines.append(
                f"  {label:<26} {r.tp:>7} {r.fp:>7} {r.fn:>7} {r.tn:>7} {r.specificity:>17.4f}"
            )
        lines.append("")

    # Table 3: Quality & Complexity
    lines += [
        "─"*98,
        "  Table 3. Rule Quality & Complexity Metrics",
        "─"*98,
        f"  {'System':<26} {'Specificity':>12} {'Uniqueness%':>12} {'Avg Opts':>9} {'Avg CLen':>9}",
        "  "+"-"*70,
    ]
    for label, r in results.items():
        lines.append(
            f"  {label:<26} {r.specificity_score:>12.2f} {r.uniqueness_ratio:>11.1f}% "
            f"{r.avg_options:>9.2f} {r.avg_content_len:>9.2f}"
        )
    lines.append("")

    # Table 4: Overlap
    lines += [
        "─"*98,
        "  Table 4. Content Pattern Overlap  (vs PCAP-Analyzer)",
        "─"*98,
        f"  {'Baseline':<26} {'Overlap':>8} {'Only-PCAP':>10} {'Only-BL':>9} {'Jaccard':>8}",
        "  "+"-"*64,
    ]
    for label, r in bls.items():
        lines.append(
            f"  {label:<26} {r.overlap:>8} {r.only_in_pcap:>10} "
            f"{r.only_in_target:>9} {r.jaccard:>8.4f}"
        )
    lines.append("")

    # Table 5: Severity
    sevs = ["CRITICAL","HIGH","MEDIUM","LOW","INFO","UNKNOWN"]
    lines += [
        "─"*98,
        "  Table 5. Severity Distribution (%)",
        "─"*98,
        "  "+"System".ljust(26) + "".join(f"{s:>11}" for s in sevs),
        "  "+"-"*74,
    ]
    for label, r in results.items():
        row = f"  {label:<26}" + "".join(f"{r.severity_dist.get(s,0):>10.1f}%" for s in sevs)
        lines.append(row)
    lines.append("")

    # Table 6: Coverage
    if pcap:
        lines += [
            "─"*98,
            "  Table 6. PCAP-Analyzer Coverage Detail",
            "─"*98,
        ]
        for proto, cnt in sorted(pcap.proto_coverage.items(), key=lambda x:-x[1]):
            pct = cnt / max(pcap.rule_count,1)*100
            lines.append(f"  Protocol  {proto.upper():<8} {cnt:>5}  {_bar(pct,25)} {pct:.1f}%")
        lines.append("")
        for cat, cnt in sorted(pcap.attack_coverage.items(), key=lambda x:-x[1]):
            pct = cnt / max(pcap.rule_count,1)*100
            lines.append(f"  AttackCat {cat:<18} {cnt:>5}  {_bar(pct,20)} {pct:.1f}%")
        lines.append("")

    lines.append("="*98)
    return "\n".join(lines)


def generate_csv_report(results: Dict[str, AlertResult]) -> str:
    """
    CSV 리포트 (UTF-8 BOM — Windows Excel 직접 열기 가능).
    논문 Table 데이터를 spreadsheet에서 바로 사용.
    """
    buf = io.StringIO()
    buf.write("\ufeff")   # BOM
    writer = csv.writer(buf)
    writer.writerow([
        "System", "Rule_Count", "Alert_Count", "Unique_SIDs",
        "Precision", "Recall", "F1_Score", "FPR",
        "Specificity_TNR", "Specificity_Score",
        "Uniqueness_Pct", "Jaccard",
        "TP", "FP", "FN", "TN",
        "Avg_Options", "Avg_Content_Len",
        "Overlap_with_PCAP", "Only_PCAP", "Only_BL",
        "Sev_CRITICAL_%", "Sev_HIGH_%", "Sev_MEDIUM_%", "Sev_LOW_%",
        "Proto_UDP", "Proto_TCP",
        "Cat_DNS", "Cat_HTTP", "Cat_FTP", "Cat_PHISHING", "Cat_MALWARE",
    ])
    for label, r in results.items():
        sd = r.severity_dist; pc = r.proto_coverage; ac = r.attack_coverage
        writer.writerow([
            label, r.rule_count, r.alert_count, r.unique_sids,
            f"{r.precision:.4f}", f"{r.recall:.4f}",
            f"{r.f1:.4f}", f"{r.fpr:.4f}",
            f"{r.specificity:.4f}", f"{r.specificity_score:.2f}",
            f"{r.uniqueness_ratio:.1f}", f"{r.jaccard:.4f}",
            r.tp, r.fp, r.fn, r.tn,
            f"{r.avg_options:.2f}", f"{r.avg_content_len:.2f}",
            r.overlap, r.only_in_pcap, r.only_in_target,
            f"{sd.get('CRITICAL',0):.1f}", f"{sd.get('HIGH',0):.1f}",
            f"{sd.get('MEDIUM',0):.1f}",  f"{sd.get('LOW',0):.1f}",
            pc.get("udp",0), pc.get("tcp",0),
            ac.get("DNS",0), ac.get("HTTP",0), ac.get("FTP",0),
            ac.get("PHISHING",0), ac.get("MALWARE",0),
        ])
    return buf.getvalue()


def generate_json_report(results: Dict[str, AlertResult]) -> dict:
    return {
        "meta": {
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "system_count": len(results),
        },
        "results": {label: asdict(r) for label, r in results.items()},
    }


# ──────────────────────────────────────────────────────────────────────────────
# 8. 편의 함수 (Flask 라우트에서 직접 호출)
# ──────────────────────────────────────────────────────────────────────────────

def run_full_comparison(
    pcap_rules_text:  str,
    custom_baselines: Optional[Dict[str, str]] = None,
    pcap_file_path:   Optional[str] = None,
    active_builtins:  Optional[List[str]] = None,
) -> dict:
    """
    통합 비교 실행 — Flask /baseline-compare/run 에서 호출.

    pcap_file_path 지정 시 scapy로 PCAP을 읽어 실제 매칭 수행.
    미지정 시 정적(룰 레벨) 분석만 수행.
    """
    pcap_rules = parse_rules_from_text(pcap_rules_text, "pcap_analyzer")

    # 베이스라인 구성
    baselines: Dict[str, List[ParsedRule]] = {}
    cached = get_cached_baselines()
    for label, rules in cached.items():
        if not active_builtins or label in active_builtins:
            baselines[label] = rules
    if not baselines:
        demos = _get_demo_baselines()
        baselines = {k:v for k,v in demos.items()
                     if not active_builtins or k in active_builtins}
    if custom_baselines:
        for label, text in custom_baselines.items():
            parsed = parse_rules_from_text(text, label)
            if parsed:
                baselines[label] = parsed

    # PCAP 로드
    pcap_packets = None
    if pcap_file_path and Path(pcap_file_path).exists():
        try:
            from scapy.all import rdpcap
            pcap_packets = list(rdpcap(str(pcap_file_path)))
            print(f"[Baseline] PCAP 로드: {len(pcap_packets)} 패킷")
        except Exception as e:
            print(f"[Baseline] PCAP 로드 실패: {e}")

    results   = run_evaluation(pcap_rules, baselines, pcap_packets)
    json_rep  = generate_json_report(results)
    json_rep["text_report"] = generate_text_report(results)
    json_rep["csv_report"]  = generate_csv_report(results)
    return json_rep


# ──────────────────────────────────────────────────────────────────────────────
# 9. 내장 데모 베이스라인
# ──────────────────────────────────────────────────────────────────────────────

def _get_demo_baselines() -> Dict[str, List[ParsedRule]]:
    demos = {
        "ET_Open_DNS": r"""
alert udp $HOME_NET any -> any 53 (msg:"ET DNS Query for Known Malware Domain"; content:"|01 00 00 01 00 00 00 00 00 00|"; depth:10; content:"malware"; nocase; sid:2000001; rev:1;)
alert udp $HOME_NET any -> any 53 (msg:"ET DNS Possible DGA Domain High Entropy"; pcre:"/[a-z]{20,}\.(com|net|org)/i"; sid:2000002; rev:1;)
alert udp any any -> $DNS_SERVERS 53 (msg:"ET DNS Possible Typosquatting Domain"; content:"paypa"; nocase; sid:2000003; rev:1;)
alert udp any any -> $DNS_SERVERS 53 (msg:"ET DNS Phishing Domain Query"; content:"instagram-login"; nocase; sid:2000004; rev:1;)
alert udp any any -> $DNS_SERVERS 53 (msg:"ET DNS Suspicious TLD .cfd Query"; content:".cfd"; nocase; sid:2000005; rev:1;)
""",
        "ET_Open_HTTP": r"""
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ET WEB_CLIENT SQL Injection UNION SELECT"; flow:established,to_server; content:"union"; http_uri; nocase; content:"select"; distance:0; nocase; sid:2001001; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ET WEB_CLIENT XSS Attempt"; flow:established,to_server; content:"<script"; http_uri; nocase; sid:2001002; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ET WEB_CLIENT Path Traversal ../"; content:"../"; http_uri; sid:2001003; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ET WEB_SERVER Log4Shell CVE-2021-44228"; content:"${jndi:"; http_uri; nocase; sid:2001004; rev:1;)
alert tcp any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET SCAN Nikto Web Scanner"; content:"Nikto"; http_header; nocase; sid:2001005; rev:1;)
""",
        "Snort_Community": r"""
alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"FTP Bad Login"; flow:from_server,established; content:"530 "; depth:4; sid:3000001; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET 21 (msg:"FTP PASSWD Command Cleartext"; flow:to_server,established; content:"PASS "; nocase; sid:3000002; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET 21 (msg:"FTP Path Traversal ../"; content:"../"; sid:3000003; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET 25 (msg:"SMTP Suspicious Attachment Base64"; content:"Content-Type: application/"; nocase; sid:3000004; rev:1;)
alert tcp any any -> $TELNET_SERVERS 23 (msg:"TELNET IAC Command"; flow:to_server,established; content:"|ff f6|"; sid:3000005; rev:1;)
""",
        "Suricata_Rules": r"""
alert dns $HOME_NET any -> any any (msg:"SURICATA DNS Malware Domain Lookup"; dns.query; content:"botnet"; nocase; sid:4000001; rev:1;)
alert dns any any -> any any (msg:"SURICATA DNS Typosquatting High Entropy"; dns.query; pcre:"/[0-9]{2}[a-z]{3}[0-9]{2}/"; sid:4000002; rev:1;)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"SURICATA HTTP SQLi UNION SELECT"; http.uri; content:"union"; nocase; content:"select"; nocase; distance:0; sid:4000003; rev:1;)
alert http any any -> $HOME_NET any (msg:"SURICATA HTTP Log4j Exploit Attempt"; http.request_body; content:"${jndi:"; nocase; sid:4000004; rev:1;)
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"SURICATA TLS Suspicious SNI .cfd"; tls.sni; content:".cfd"; endswith; sid:4000005; rev:1;)
""",
    }
    return {label: parse_rules_from_text(text, label) for label, text in demos.items()}


# 이전 버전 호환
def get_builtin_baselines() -> Dict[str, List[ParsedRule]]:
    cached = get_cached_baselines()
    return cached if cached else _get_demo_baselines()
