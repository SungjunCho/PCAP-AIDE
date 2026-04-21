"""
protocol_rule_engine.py
========================
프로토콜별 탐지 룰 자동 생성 + 헤더/Payload 복합 탐지 룰 엔진

지원 프로토콜: HTTP, DNS, FTP, Telnet, SMTP
룰 포맷: Snort / Suricata 호환
"""

from scapy.all import IP, IPv6, TCP, UDP, ICMP, Raw, DNS, DNSQR, DNSRR
from whitelist_engine import check_global_whitelist
from noise_filter_engine import is_noise, _compute_shannon_entropy, _check_shannon_entropy
from file_reputation_engine import analyze_file_in_packet, get_file_rep_summary
from dns_reputation_engine import check_domain as _dns_rep_check, _check_whitelist as _dns_wl_check
import re
import yaml
from pathlib import Path
from keyword_rule_engine import detect_and_build_rules as _kw_detect


# ══════════════════════════════════════════════════════
# 1. 프로토콜 식별
# ══════════════════════════════════════════════════════

def detect_protocol(packet, payload: bytes) -> str:
    """패킷의 애플리케이션 프로토콜 판별"""

    if TCP in packet:
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        ports = {sport, dport}

        # HTTP
        http_methods = (b"GET ", b"POST ", b"PUT ", b"DELETE ",
                        b"HEAD ", b"OPTIONS ", b"PATCH ", b"HTTP/")
        if any(payload.startswith(m) for m in http_methods):
            return "HTTP"
        if ports & {80, 8080, 8000, 8443}:
            return "HTTP"

        # FTP
        ftp_cmds = (b"USER ", b"PASS ", b"LIST", b"RETR ", b"STOR ",
                    b"QUIT", b"PORT ", b"PASV", b"TYPE ", b"CWD ",
                    b"MKD ", b"RMD ", b"DELE ")
        if any(payload.upper().startswith(c) for c in ftp_cmds):
            return "FTP"
        if b"220 " in payload[:20] or b"230 " in payload[:20]:
            return "FTP"
        if ports & {20, 21}:
            return "FTP"

        # Telnet (IAC = 0xFF)
        if payload and payload[0] == 0xFF:
            return "TELNET"
        if dport == 23 or sport == 23:
            return "TELNET"

        # SMTP
        smtp_cmds = (b"EHLO ", b"HELO ", b"MAIL FROM", b"RCPT TO",
                     b"DATA\r\n", b"QUIT\r\n", b"AUTH ", b"STARTTLS")
        if any(payload.upper().startswith(c) for c in smtp_cmds):
            return "SMTP"
        if b"220 " in payload[:20] and b"SMTP" in payload[:60].upper():
            return "SMTP"
        if ports & {25, 465, 587}:
            return "SMTP"

    if UDP in packet:
        sport = packet[UDP].sport
        dport = packet[UDP].dport
        if dport == 53 or sport == 53:
            return "DNS"

    if ICMP in packet:
        return "ICMP"

    return "OTHER"


# ══════════════════════════════════════════════════════
# 2. 헤더 파싱 헬퍼
# ══════════════════════════════════════════════════════

def get_tcp_flags_str(flags: int) -> str:
    """TCP 플래그 비트마스크 → 사람이 읽을 수 있는 문자열"""
    names = [(0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"),
             (0x08, "PSH"), (0x10, "ACK"), (0x20, "URG")]
    return ",".join(name for bit, name in names if flags & bit) or "NONE"


def extract_header_features(packet) -> dict:
    """IP/TCP/UDP 헤더에서 룰 생성에 필요한 필드 추출"""
    feat = {
        "src_ip":     "any",
        "dst_ip":     "any",
        "src_port":   "any",
        "dst_port":   "any",
        "ttl":        None,
        "tcp_flags":  None,
        "tcp_window": None,
        "proto":      "tcp",
    }

    if IP in packet:
        feat["ttl"] = packet[IP].ttl

    if TCP in packet:
        feat["proto"]      = "tcp"
        feat["src_port"]   = str(packet[TCP].sport)
        feat["dst_port"]   = str(packet[TCP].dport)
        feat["tcp_flags"]  = int(packet[TCP].flags)
        feat["tcp_window"] = packet[TCP].window
    elif UDP in packet:
        feat["proto"]    = "udp"
        feat["src_port"] = str(packet[UDP].sport)
        feat["dst_port"] = str(packet[UDP].dport)
    elif ICMP in packet:
        feat["proto"]    = "icmp"
        feat["dst_port"] = "any"   # ICMP는 포트 없음

    return feat


# ══════════════════════════════════════════════════════
# 3. Payload 파싱 (프로토콜별)
# ══════════════════════════════════════════════════════

def parse_http_payload(payload: bytes) -> dict:
    """HTTP 요청/응답 파싱"""
    info = {
        "method": "", "uri": "", "host": "",
        "user_agent": "", "status_code": 0,
        "suspicious_patterns": [],
    }
    try:
        text = payload.decode("utf-8", errors="ignore")
        lines = text.split("\r\n")
        first = lines[0]

        m = re.match(r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(\S+)\s+HTTP", first)
        if m:
            info["method"] = m.group(1)
            info["uri"]    = m.group(2)

        m2 = re.match(r"^HTTP/[\d.]+ (\d+)", first)
        if m2:
            info["status_code"] = int(m2.group(1))

        for line in lines[1:]:
            low = line.lower()
            if low.startswith("host:"):
                info["host"] = line.split(":", 1)[1].strip()
            elif low.startswith("user-agent:"):
                info["user_agent"] = line.split(":", 1)[1].strip()

        text_upper = text.upper()
        # ── HTTP 공격 패턴 탐지 (keywords/http_attack_patterns.yaml 기반) ──
        for _pat_def in _load_http_patterns():
            pid = _pat_def.get('pattern_id', '')
            if pid and pid not in info['suspicious_patterns']:
                if _match_http_pattern(_pat_def, text, text_upper):
                    info['suspicious_patterns'].append(pid)


        # ── User-Agent 의심 패턴 탐지 ─────────────────────────────────────
        ua = info.get("user_agent", "")
        if ua:
            ua_result = _check_suspicious_ua(ua)
            info["ua_suspicious"] = ua_result
            if ua_result:
                info["suspicious_patterns"].append("SUSPICIOUS_UA")
        else:
            info["ua_suspicious"] = None

    except Exception:
        pass
    return info


# ── 의심 User-Agent 패턴 정의 ─────────────────────────────────────────────────
# (regex,  분류명,  심각도)
_UA_PATTERNS: list[tuple] = [
    # 공격·스캐너 도구
    (r"sqlmap",                               "SQLMap Scanner",           "CRITICAL"),
    (r"nikto",                                "Nikto Scanner",            "HIGH"),
    (r"nmap|masscan|zmap",                    "Port Scanner",             "HIGH"),
    (r"nessus|openvas|acunetix|burpsuite",    "Vulnerability Scanner",    "HIGH"),
    (r"dirbuster|gobuster|wfuzz|ffuf|dirb",  "Directory Brute-Force",    "HIGH"),
    (r"hydra|medusa|patator|crowbar",         "Credential Brute-Force",   "CRITICAL"),
    (r"metasploit|msfpayload|meterpreter",    "Metasploit Framework",     "CRITICAL"),
    (r"havij|pangolin|sqlninja",              "SQL Injection Tool",       "CRITICAL"),
    (r"nuclei|httpx|subfinder|amass",         "Recon/Enum Tool",          "MEDIUM"),
    (r"zgrab|masscan|zmap",                   "Mass Scanner",             "HIGH"),
    (r"w3af|skipfish|grabber",                "Web App Scanner",          "HIGH"),
    # CVE·취약점 익스플로잇 시그니처 in UA
    (r"\$\{jndi:",                            "Log4Shell UA Inject",      "CRITICAL"),
    (r"(;|&&|\|\|)\s*(id|whoami|uname|cat)",  "Command Inject in UA",     "CRITICAL"),
    (r"(\.\.\/){2,}",                         "Path Traversal in UA",     "HIGH"),
    (r"<script[^>]*>",                        "XSS in UA",                "HIGH"),
    (r"union\s+select",                       "SQLi in UA",               "CRITICAL"),
    # 봇·자동화 도구 (LOW — 정보성)
    (r"python-requests/[0-9]",               "Python requests",           "LOW"),
    (r"python-urllib/[0-9]",                 "Python urllib",             "LOW"),
    (r"go-http-client/[0-9]",               "Go HTTP Client",             "LOW"),
    (r"^curl/[0-9]",                         "curl",                      "LOW"),
    (r"^wget/[0-9]",                         "wget",                      "LOW"),
    (r"libwww-perl",                         "Perl HTTP Client",          "MEDIUM"),
    (r"scrapy/[0-9]",                        "Scrapy Crawler",            "MEDIUM"),
    (r"java/[0-9]",                          "Java HTTP Client",          "LOW"),
]


# ── 타이포스쿼팅 / 피싱 도메인 패턴 탐지 ─────────────────────────────────────
# 알려진 브랜드 도메인과 유사한 이름을 가진 의심 도메인을 탐지한다.
# VT API 없이도 동작하며, 다음 패턴을 탐지한다:
#   1. 숫자-알파벳 동형자 치환 (homoglyph): 0→o, 1→l/i, rn→m 등
#   2. 위장 키워드 하이픈: -login, -secure, -verify, -account 등
#   3. 의심 TLD: .cfd, .xyz, .top, .tk, .ml, .ga, .cf 등
#   4. 알려진 브랜드 이름 포함 + 추가 문자


# ══════════════════════════════════════════════════════════════════════════════
# HTTP 공격 패턴 YAML 로더
# keywords/http_attack_patterns.yaml 에서 탐지 패턴과 Snort 룰 옵션을 로드
# ══════════════════════════════════════════════════════════════════════════════

_HTTP_PATTERN_FILE = Path(__file__).parent / "keywords" / "http_attack_patterns.yaml"
_http_patterns:     list = []
_http_pattern_mtime: float = 0.0


def _load_http_patterns() -> list:
    """http_attack_patterns.yaml 로드 (변경 감지 시 자동 재로드)"""
    global _http_patterns, _http_pattern_mtime
    try:
        mtime = _HTTP_PATTERN_FILE.stat().st_mtime
        if mtime == _http_pattern_mtime and _http_patterns:
            return _http_patterns
        with _HTTP_PATTERN_FILE.open(encoding="utf-8") as f:
            data = yaml.safe_load(f)
        _http_patterns = [p for p in data.get("patterns", []) if p.get("enabled", True)]
        _http_pattern_mtime = mtime
        print(f"[HTTP Patterns] 로드 완료 — {len(_http_patterns)}개 패턴")
    except Exception as e:
        print(f"[HTTP Patterns] 로드 실패: {e}")
    return _http_patterns


def _match_http_pattern(pattern_def: dict, text: str, text_upper: str) -> bool:
    """
    단일 패턴 정의를 텍스트에 매칭.
    detection.type 에 따라 다른 매칭 방법 사용.
    """
    det     = pattern_def.get("detection", {})
    dtype   = det.get("type", "regex")
    nocase  = det.get("nocase", True)
    flags   = re.IGNORECASE if nocase else 0
    target  = text_upper if dtype == "contains_upper" else text

    if dtype in ("regex", "contains_upper"):
        pat = det.get("pattern", "")
        if not pat:
            return False
        if dtype == "contains_upper":
            return pat.upper() in text_upper
        return bool(re.search(pat, target, flags))

    elif dtype == "contains":
        pat = det.get("pattern", "")
        return (pat.lower() in text.lower()) if nocase else (pat in text)

    elif dtype == "multi_contains":
        patterns = det.get("patterns", [])
        target_c = text.lower() if nocase else text
        return any((p.lower() if nocase else p) in target_c for p in patterns)

    elif dtype == "smuggling":
        pat1 = det.get("pattern", "")
        pat2 = det.get("pattern2", "")
        if nocase:
            return pat1.lower() in text.lower() and pat2.lower() in text.lower()
        return pat1 in text and pat2 in text

    return False

# ─────────────────────────────────────────────────────────────────────────────
# 타이포스쿼팅 / 피싱 도메인 패턴 탐지 (VT 독립적)
# ─────────────────────────────────────────────────────────────────────────────

_BRAND_DOMAINS = {
    # brand_keyword: canonical_domain
    'google':     'google.com',
    'youtube':    'youtube.com',
    'microsoft':  'microsoft.com',
    'windows':    'microsoft.com',
    'apple':      'apple.com',
    'icloud':     'icloud.com',     # icloud.com은 정상 도메인이므로 SAFE_DOMAINS에도 등록
    'amazon':     'amazon.com',
    'netflix':    'netflix.com',
    'facebook':   'facebook.com',
    'instagram':  'instagram.com',
    'paypal':     'paypal.com',
    'github':     'github.com',
    'twitter':    'twitter.com',
    'linkedin':   'linkedin.com',
    'dropbox':    'dropbox.com',
    'adobe':      'adobe.com',
    'naver':      'naver.com',
    'kakao':      'kakao.com',
    'daum':       'daum.net',
}

# 브랜드 키워드를 포함하지만 실제로는 정상 서비스 도메인인 경우 → 타이포스쿼팅 탐지 제외
_BRAND_SAFE_DOMAINS = {
    'icloud.com', 'icloud.com.', 'me.com', 'mac.com',     # Apple iCloud 정상 도메인
    'youtu.be',                                             # YouTube 단축 URL
    'microsoftonline.com', 'microsoft365.com',             # Microsoft 정상
    'googlemail.com', 'googlevideo.com', 'goo.gl',         # Google 정상
    'amazontrust.com', 'amazonsmile.com',                  # Amazon 정상
    'netflixstudios.com',                                  # Netflix 정상
    'facebookincubator.github.io',                         # Meta/Facebook 정상
    # 정상 기업 도메인 — -secure/-login 등의 서브도메인을 오탐 방지
    'oracle.com', 'oraclecloud.com', 'oracleimg.com',      # Oracle 공식
    'salesforce.com', 'force.com', 'salesforceliveagent.com',  # Salesforce
    'adobe.com', 'adobelogin.com', 'adobedtm.com',        # Adobe
    'zoom.us', 'zoomgov.com',                              # Zoom
    'slack.com', 'slack-edge.com',                         # Slack
    'atlassian.com', 'atlassian.net', 'jira.com',          # Atlassian
    'twitch.tv', 'twitchapps.com',                         # Twitch
    'spotify.com',                                          # Spotify
    'ebay.com', 'ebayimg.com',                             # eBay
    'samsung.com', 'samsungcloud.com',                     # Samsung
    'lg.com', 'lgtvsdp.com',                               # LG
    'skype.com', 'teams.microsoft.com',                    # MS Teams/Skype
}

# oracle.com처럼 서브도메인 전체를 safe로 처리할 도메인 접미사
_SAFE_DOMAIN_SUFFIXES = {
    '.oracle.com', '.oraclecloud.com',
    '.salesforce.com', '.force.com',
    '.adobe.com',
    '.zoom.us',
    '.slack.com',
    '.atlassian.com', '.atlassian.net',
    '.samsung.com',
    '.lg.com',
    '.skype.com',
    '.microsoft.com', '.microsoftonline.com',
    '.google.com', '.googleapis.com',
    '.amazon.com', '.amazonaws.com',
    '.apple.com', '.icloud.com',
}

_SUSPICIOUS_KEYWORDS = {
    '-login', '-signin', '-secure', '-security', '-verify', '-verification',
    '-account', '-update', '-support', '-help', '-service', '-portal',
    '-auth', '-access', '-password', '-recover', '-restore', '-alert',
}

_SUSPICIOUS_TLDS = {
    '.cfd', '.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq',
    '.pw', '.cc', '.ws', '.click', '.link',
    '.online', '.site', '.web', '.space', '.live',
}

# 숫자→알파벳 동형자 치환 (1 → l AND i 두 경우 모두 처리)
_HOMOGLYPH_EXPAND = {
    # 각 숫자/문자가 어떤 알파벳을 대체할 수 있는지 (다중 가능)
    '0': ['o'],
    '1': ['l', 'i'],   # 1은 l과 i 모두 대체 가능 (netfl1x → netfix/netflx)
    '3': ['e'],
    '4': ['a'],
    '5': ['s'],
    '6': ['b'],
    '8': ['b'],
    '@': ['a'],
}


def _normalize_variants(s: str):
    """
    문자열의 동형자(homoglyph) 변형을 정규화한 후보 집합을 반환한다.
    예: 'netfl1x' → {'netflx', 'netflix', 'netfllx'}
    """
    s = s.lower()
    # rn → m, vv → w (문자열 수준 치환)
    s = s.replace('rn', 'm').replace('vv', 'w')
    # 대문자 I가 l처럼 보이는 경우 → 이미 .lower()로 i가 됨
    # i ↔ l 쌍방향: 소문자 i를 l로도 읽을 수 있음
    variants = {s}
    # 1 → l or i 변형
    for ch, replacements in _HOMOGLYPH_EXPAND.items():
        new_variants = set()
        for v in variants:
            if ch in v:
                for r in replacements:
                    new_variants.add(v.replace(ch, r))
        variants |= new_variants
    # i ↔ l 쌍방향 추가
    more = set()
    for v in variants:
        more.add(v.replace('i', 'l'))
        more.add(v.replace('l', 'i'))
    variants |= more
    return variants


def _check_typosquatting(domain: str) -> dict | None:
    """
    타이포스쿼팅 / 피싱 도메인 패턴 탐지.
    Returns: {"type": str, "brand": str, "severity": str, "reason": str} or None
    """
    if not domain:
        return None

    domain_low = domain.lower().rstrip('.')

    # 정상 서비스 도메인은 탐지 제외
    if domain_low in _BRAND_SAFE_DOMAINS:
        return None
    # 브랜드 canonical 도메인 자체도 제외
    if domain_low in _BRAND_DOMAINS.values():
        return None
    # 정상 기업 서브도메인 접미사 매칭 (예: *.oracle.com → 제외)
    for suffix in _SAFE_DOMAIN_SUFFIXES:
        if domain_low.endswith(suffix) or domain_low == suffix.lstrip('.'):
            return None

    parts = domain_low.split('.')
    if len(parts) < 2:
        return None

    tld = '.' + parts[-1]
    sld = parts[-2] if len(parts) >= 2 else ''
    full_no_tld = '.'.join(parts[:-1])
    clean = full_no_tld.replace('-', '')

    # ── 1. 의심 TLD + 브랜드 포함 ─────────────────────────────────────────
    if tld in _SUSPICIOUS_TLDS:
        sld_clean_variants = _normalize_variants(full_no_tld.replace('-', ''))
        for brand, canonical in _BRAND_DOMAINS.items():
            brand_clean = brand.replace('-', '')
            # sld의 동형자 정규화 변형 중 brand를 포함하는 것이 있으면 탐지
            if any(brand_clean in v for v in sld_clean_variants) and full_no_tld != brand:
                return {
                    "type": "suspicious_tld",
                    "brand": canonical,
                    "severity": "CRITICAL",
                    "reason": f"의심 TLD({tld})에 브랜드 '{brand}' 포함 (도메인: {domain_low})",
                }
        # 브랜드 무관 의심 TLD
        return {
            "type": "suspicious_tld",
            "brand": "",
            "severity": "MEDIUM",
            "reason": f"의심 TLD 사용: {tld}",
        }

    # ── 2. 위장 키워드 하이픈 + 브랜드 ──────────────────────────────────────
    for kw in _SUSPICIOUS_KEYWORDS:
        if kw in domain_low:
            clean_variants = _normalize_variants(clean)
            for brand, canonical in _BRAND_DOMAINS.items():
                brand_clean = brand.replace('-', '')
                if brand_clean in clean_variants:
                    return {
                        "type": "brand_impersonation",
                        "brand": canonical,
                        "severity": "CRITICAL",
                        "reason": f"브랜드 '{brand}' + 위장 키워드 '{kw}'",
                    }
            return {
                "type": "suspicious_keyword",
                "brand": "",
                "severity": "HIGH",
                "reason": f"위장 키워드 포함: {kw}",
            }

    # ── 3. 동형자 치환 (homoglyph) ───────────────────────────────────────────
    clean_variants = _normalize_variants(clean)
    for brand, canonical in _BRAND_DOMAINS.items():
        brand_clean = brand.replace('-', '')
        if brand_clean in clean_variants and domain_low != canonical:
            # 변형된 도메인이 브랜드를 정확히 포함하되 원래 도메인과 다름
            return {
                "type": "homoglyph",
                "brand": canonical,
                "severity": "HIGH",
                "reason": f"동형자 치환: '{domain_low}' ≈ '{canonical}'",
            }

    return None



def _check_suspicious_ua(ua: str) -> dict | None:
    """
    User-Agent 문자열에서 의심 패턴을 탐지한다.
    Returns: {"category": str, "severity": str, "matched": str, "ua": str} or None
    """
    ua_low = ua.lower()
    for pattern, category, severity in _UA_PATTERNS:
        m = re.search(pattern, ua_low, re.I)
        if m:
            return {
                "category": category,
                "severity": severity,
                "matched":  m.group(0)[:60],
                "ua":       ua[:120],
            }
    return None


def _parse_dns_name_wire(data: bytes, offset: int) -> tuple[str, int]:
    """
    DNS wire format 도메인명 파싱 (포인터 지원).
    scapy 레이어 파싱 실패 시 fallback 으로 사용.
    Returns (domain_str, next_offset)
    """
    labels: list[str] = []
    visited: set[int] = set()
    while offset < len(data):
        if offset in visited:
            break
        visited.add(offset)
        length = data[offset]
        if length == 0:
            offset += 1
            break
        elif (length & 0xC0) == 0xC0:          # 압축 포인터
            if offset + 1 >= len(data):
                break
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            part, _ = _parse_dns_name_wire(data, ptr)
            if part:
                labels.append(part)
            offset += 2
            break
        else:
            offset += 1
            end = offset + length
            if end > len(data):
                break
            try:
                labels.append(data[offset:end].decode("utf-8", errors="replace"))
            except Exception:
                labels.append(data[offset:end].hex())
            offset = end
    return ".".join(labels), offset


def parse_dns_payload(packet, payload: bytes) -> dict:
    """DNS 페이로드 파싱 — scapy 레이어 우선, wire format 직접 파싱 fallback"""
    info = {
        "query_name": "", "query_type": 0,
        "is_response": False, "answer_count": 0,
        "suspicious_patterns": [],
        "dns_reputation": None,
    }
    try:
        # ── 1차: scapy DNS 레이어 파싱 ────────────────────────────────────
        if DNS in packet:
            dns = packet[DNS]
            info["is_response"]  = bool(dns.qr)
            info["answer_count"] = dns.ancount
            if dns.qd:
                try:
                    info["query_name"] = dns.qd.qname.decode("utf-8", errors="ignore").rstrip(".")
                except Exception:
                    info["query_name"] = str(dns.qd.qname)
                info["query_type"] = dns.qd.qtype

        # ── 2차: scapy 파싱 실패 시 wire format 직접 파싱 ────────────────
        if not info["query_name"] and len(payload) >= 13:
            flags   = (payload[2] << 8) | payload[3]
            info["is_response"]  = bool((flags >> 15) & 1)
            info["answer_count"] = (payload[6] << 8) | payload[7]
            qdcount = (payload[4] << 8) | payload[5]
            if qdcount > 0:
                name, off = _parse_dns_name_wire(payload, 12)
                info["query_name"] = name
                if off + 2 <= len(payload):
                    info["query_type"] = (payload[off] << 8) | payload[off + 1]

        name = info["query_name"]
        if len(name) > 50:
            info["suspicious_patterns"].append("LONG_DOMAIN")
        # DNS 터널링 탐지 (entropy 기반 고도화)
        if name:
            labels = name.split(".")
            # 방법 1: 서브도메인 길이 ≥ 32자 (high-entropy 서브도메인)
            long_labels = [l for l in labels if len(l) >= 32]
            # 방법 2: 서브도메인이 hex/base64 패턴 (20자 이상)
            hex_labels  = [l for l in labels if re.match(r"^[0-9a-f]{20,}$", l, re.I)]
            b64_labels  = [l for l in labels if re.match(r"^[A-Za-z0-9+/]{20,}={0,2}$", l)]
            # 방법 3: 전체 도메인 길이 ≥ 60자
            total_long  = len(name) >= 60
            if long_labels or hex_labels or b64_labels or total_long:
                info["suspicious_patterns"].append("DNS_TUNNELING")
        if re.search(r"(malware|botnet|c2|cnc|rat\.|shell\.)", name, re.I):
            info["suspicious_patterns"].append("SUSPICIOUS_DOMAIN")
        if info["query_type"] == 16:
            info["suspicious_patterns"].append("DNS_TXT_QUERY")

        # ── 타이포스쿼팅 / 피싱 도메인 패턴 탐지 (VT 독립적) ─────────────
        if name and not info["is_response"]:
            typo = _check_typosquatting(name)
            if typo:
                info["typosquatting"] = typo
                info["suspicious_patterns"].append("TYPOSQUATTING")

        # ── DNS Reputation 체크 (화이트리스트 → 캐시 → SB → VirusTotal) ──
        if name and not info["is_response"]:   # 응답 패킷은 조회 제외
            rep = _dns_rep_check(name)
            info["dns_reputation"] = rep
            if rep["verdict"] == "MALICIOUS":
                info["suspicious_patterns"].append("MALICIOUS_DOMAIN")
            elif rep["verdict"] == "SUSPICIOUS":
                info["suspicious_patterns"].append("SUSPICIOUS_DOMAIN_VT")
            elif rep["verdict"] == "SAFE":
                # SB 또는 VT가 SAFE 판정 → TYPOSQUATTING 오탐 억제
                # (정상 기업 도메인이 -secure 등 키워드 포함할 수 있음)
                if "TYPOSQUATTING" in info["suspicious_patterns"]:
                    info["suspicious_patterns"].remove("TYPOSQUATTING")
                    info["typosquatting"] = None
                    info.setdefault("suppressed_by", []).append(
                        f"TYPOSQUATTING suppressed: {rep['source']} SAFE")

    except Exception:
        pass
    return info


def parse_ftp_payload(payload: bytes) -> dict:
    """FTP 명령/응답 파싱"""
    info = {
        "command": "", "argument": "",
        "response_code": 0,
        "suspicious_patterns": [],
    }
    try:
        text = payload.decode("utf-8", errors="ignore").strip()
        m = re.match(r"^(\d{3})\s+(.*)", text)
        if m:
            info["response_code"] = int(m.group(1))
        else:
            parts = text.split(" ", 1)
            info["command"]  = parts[0].upper()
            info["argument"] = parts[1] if len(parts) > 1 else ""

        cmd = info["command"]
        arg = info["argument"]
        if cmd == "USER" and arg.lower() in ("root", "admin", "administrator"):
            info["suspicious_patterns"].append("PRIVILEGED_LOGIN_ATTEMPT")
        if cmd == "USER" and arg.lower() in ("anonymous", "ftp", "guest"):
            info["suspicious_patterns"].append("ANONYMOUS_LOGIN_ATTEMPT")
        if cmd == "PORT":
            # FTP Bounce Attack: PORT 명령으로 외부 호스트 지정
            info["suspicious_patterns"].append("FTP_PORT_COMMAND")
            if re.search(r"PORT\s+(?!192\.168|10\.|172\.(1[6-9]|2[0-9]|3[01]))", arg):
                info["suspicious_patterns"].append("FTP_BOUNCE_ATTEMPT")
        if cmd == "PASS":
            info["suspicious_patterns"].append("FTP_PASSWORD_TRANSMITTED")
        if re.search(r"(\.\./|\.\.\\)", arg):
            info["suspicious_patterns"].append("FTP_PATH_TRAVERSAL")
        if re.search(r"\.(exe|sh|bat|ps1|py)$", arg, re.I):
            info["suspicious_patterns"].append("EXECUTABLE_TRANSFER")
        if info["response_code"] == 530:
            info["suspicious_patterns"].append("FTP_LOGIN_FAILURE")
        if info["response_code"] == 331:
            info["suspicious_patterns"].append("FTP_PASSWORD_REQUIRED")
    except Exception:
        pass
    return info


def parse_telnet_payload(payload: bytes) -> dict:
    """Telnet 페이로드 파싱 (IAC 명령 + 평문 데이터)"""
    info = {
        "iac_commands": [],
        "text_data": "",
        "suspicious_patterns": [],
    }
    try:
        i = 0
        text_bytes = bytearray()
        while i < len(payload):
            if payload[i] == 0xFF and i + 1 < len(payload):  # IAC
                cmd_byte = payload[i + 1]
                cmd_name = {0xFB: "WILL", 0xFC: "WONT",
                            0xFD: "DO",   0xFE: "DONT",
                            0xF4: "IP",   0xF2: "DM"}.get(cmd_byte, f"0x{cmd_byte:02x}")
                if i + 2 < len(payload):
                    opt = payload[i + 2]
                    info["iac_commands"].append(f"{cmd_name}({opt})")
                    i += 3
                else:
                    i += 2
            else:
                text_bytes.append(payload[i])
                i += 1

        info["text_data"] = text_bytes.decode("utf-8", errors="ignore")
        text = info["text_data"]

        if re.search(r"(password|passwd|login)[\s:]+\S+", text, re.I):
            info["suspicious_patterns"].append("CREDENTIAL_IN_CLEARTEXT")
        if re.search(r"(rm\s+-rf|mkfs|dd\s+if=|wget\s+http|curl\s+http)", text, re.I):
            info["suspicious_patterns"].append("DANGEROUS_COMMAND")
        if re.search(r"(chmod\s+[0-7]*7[0-7]*|chown\s+root)", text, re.I):
            info["suspicious_patterns"].append("PRIVILEGE_ESCALATION")
        if re.search(r"(/etc/shadow|/etc/passwd|/proc/)", text, re.I):
            info["suspicious_patterns"].append("SENSITIVE_FILE_ACCESS")
        if re.search(r"(nc\s+-|netcat|/dev/tcp/)", text, re.I):
            info["suspicious_patterns"].append("REVERSE_SHELL")
    except Exception:
        pass
    return info


def parse_smtp_payload(payload: bytes) -> dict:
    """SMTP 명령/응답 파싱"""
    info = {
        "command": "", "from_addr": "",
        "to_addr": "", "subject": "",
        "response_code": 0,
        "suspicious_patterns": [],
    }
    try:
        text = payload.decode("utf-8", errors="ignore")
        lines = text.split("\r\n")
        first = lines[0].strip()

        m = re.match(r"^(\d{3})[\s-](.*)", first)
        if m:
            info["response_code"] = int(m.group(1))
        else:
            parts = first.split(" ", 1)
            info["command"] = parts[0].upper()

        for line in lines:
            mf = re.match(r"(?i)^MAIL FROM:\s*<(.+?)>", line)
            if mf:
                info["from_addr"] = mf.group(1)
            mt = re.match(r"(?i)^RCPT TO:\s*<(.+?)>", line)
            if mt:
                info["to_addr"] = mt.group(1)
            ms = re.match(r"(?i)^Subject:\s*(.*)", line)
            if ms:
                info["subject"] = ms.group(1)

        full = text.upper()
        if "AUTH LOGIN" in full or "AUTH PLAIN" in full:
            info["suspicious_patterns"].append("SMTP_AUTH_ATTEMPT")
        if info["response_code"] == 535:
            info["suspicious_patterns"].append("SMTP_AUTH_FAILURE")
        if re.search(r"X-MAILER:.*(MASS|BULK|BLAST)", text, re.I):
            info["suspicious_patterns"].append("SPAM_MAILER")
        if re.search(r"(phishing|verify\s+your\s+account|click\s+here\s+to\s+confirm)", text, re.I):
            info["suspicious_patterns"].append("PHISHING_CONTENT")
        if re.search(r"content-transfer-encoding:\s*base64", text, re.I):
            info["suspicious_patterns"].append("BASE64_ENCODED_ATTACHMENT")
        rcpt_count = text.upper().count("RCPT TO:")
        if rcpt_count > 10:
            info["suspicious_patterns"].append(f"MASS_RECIPIENTS({rcpt_count})")
        # Open Relay 탐지: 외부→외부 relay (from/to 도메인 불일치)
        if info["from_addr"] and info["to_addr"]:
            from_domain = info["from_addr"].split("@")[-1].lower() if "@" in info["from_addr"] else ""
            to_domain   = info["to_addr"].split("@")[-1].lower()   if "@" in info["to_addr"]   else ""
            if from_domain and to_domain and from_domain != to_domain:
                info["suspicious_patterns"].append("SMTP_OPEN_RELAY_ATTEMPT")
        # Reply-To 스푸핑 탐지
        for line in lines:
            if re.match(r"(?i)^Reply-To:", line):
                rt_addr = line.split(":", 1)[-1].strip()
                if info["from_addr"] and rt_addr and rt_addr != info["from_addr"]:
                    info["suspicious_patterns"].append("SMTP_REPLY_TO_SPOOF")
    except Exception:
        pass
    return info


# ══════════════════════════════════════════════════════
# 4. 복합 룰 생성 (헤더 + Payload)
# ══════════════════════════════════════════════════════

# ── content 길이 제한 상수 ───────────────────────────
CONTENT_MIN_BYTES = 3    # content 최소 유효 길이 (3 bytes 미만 생성 금지)
CONTENT_MAX_BYTES = 40   # content 최대 유효 길이
BLOCKED_DST_PORTS = {443}  # 자동 룰 생성 제외 포트 목록


def _safe_content(raw: str, max_len: int = CONTENT_MAX_BYTES) -> str:
    """
    Snort content 필드용 문자열 정제.
    - 최대 max_len(기본 CONTENT_MAX_BYTES=40) bytes로 자름
    - 제어문자(개행·탭) 공백 치환
    """
    cleaned = raw.replace('"', '\\"').replace("\n", " ").replace("\r", " ").replace("\t", " ").strip()
    return cleaned[:max_len]


def _is_valid_content(s: str) -> bool:
    """
    content 문자열 유효성 검사.
    - CONTENT_MIN_BYTES(3) 이상 CONTENT_MAX_BYTES(40) 이하
    - 공백만으로 구성된 경우 제외
    """
    stripped = s.strip()
    return CONTENT_MIN_BYTES <= len(stripped) <= CONTENT_MAX_BYTES


def _bytes_to_hex_content(data: bytes, max_bytes: int = CONTENT_MAX_BYTES) -> str:
    """bytes → Snort hex content 문자열 (최대 CONTENT_MAX_BYTES bytes)"""
    return "|" + " ".join(f"{b:02x}" for b in data[:max_bytes]) + "|"


def build_http_rules(app: dict, hdr: dict, rule_id: int, frame_no: int) -> list:
    """HTTP 전용 룰 — 실제 목적지 포트 포함, 기본값 80/8080"""
    rules = []
    # 실제 캡처된 dst_port 우선, 없으면 HTTP 기본 포트 그룹
    raw_port = hdr.get("dst_port", "any")
    dst_port = raw_port if raw_port not in ("any", "0") else "[80,8080,8000,8443]"

    if app["method"] and app["uri"]:
        uri_safe = _safe_content(app["uri"], 60)
        host_opt = f'content:"{_safe_content(app["host"])}"; http_header; ' if app["host"] else ""
        rules.append(
            f'# Frame {frame_no}\n'
            f'alert tcp any any -> any {dst_port} '
            f'(msg:"HTTP {app["method"]} Request"; '
            f'flow:to_server,established; '
            f'content:"{app["method"]}"; http_method; '
            f'content:"{uri_safe}"; http_uri; '
            f'{host_opt}'
            f'sid:{rule_id}; rev:1;)'
        )
        rule_id += 1

    # ── Snort 룰 옵션: keywords/http_attack_patterns.yaml 기반 동적 로드 ──────
    _http_pats    = _load_http_patterns()
    pattern_rules = {
        p["pattern_id"]: (
            p["snort_rule"]["msg"],
            p["snort_rule"]["options"],
        )
        for p in _http_pats
        if "snort_rule" in p
    }
    for pat in app["suspicious_patterns"]:
        if pat == "SUSPICIOUS_UA":
            # User-Agent 기반 룰: ua_suspicious 정보 활용
            ua_info = app.get("ua_suspicious")
            if ua_info:
                sev      = ua_info.get("severity", "MEDIUM")
                category = ua_info.get("category", "Suspicious UA")
                ua_val   = _safe_content(ua_info.get("matched", ""), 40)
                if ua_val:
                    rules.append(
                        f'# Frame {frame_no}\n'
                        f'alert tcp any any -> any {dst_port} '
                        f'(msg:"{sev} Suspicious User-Agent: {category}"; '
                        f'flow:to_server,established; '
                        f'content:"{ua_val}"; http_header; nocase; '
                        f'sid:{rule_id}; rev:1;)'
                    )
                    rule_id += 1
        elif pat in pattern_rules:
            label, content_opt = pattern_rules[pat]
            rules.append(
                f'# Frame {frame_no}\n'
                f'alert tcp any any -> any {dst_port} '
                f'(msg:"{label}"; '
                f'flow:to_server,established; '
                f'{content_opt}'
                f'sid:{rule_id}; rev:1;)'
            )
            rule_id += 1

    return rules


def build_dns_rules(app: dict, hdr: dict, rule_id: int, frame_no: int) -> list:
    """DNS 전용 룰 — 목적지 포트는 항상 53으로 고정.
    DNS 응답 패킷(src=53, dst=높은포트)에서도 룰은 dst 53으로 생성한다."""
    rules    = []
    dst_port = "53"   # DNS 쿼리는 반드시 dst:53 으로 제한

    # 위협 패턴이 탐지된 경우 기본 Query 룰 생성 생략
    # → 아래 pattern_rules 루프에서 더 높은 심각도의 룰만 생성
    threat_patterns = {"TYPOSQUATTING", "MALICIOUS_DOMAIN", "SUSPICIOUS_DOMAIN_VT",
                       "SUSPICIOUS_DOMAIN", "DNS_TUNNELING", "DNS_TXT_QUERY"}
    has_threat = any(p in threat_patterns for p in app.get("suspicious_patterns", []))

    # ── 기본 DNS Query 룰 (위협 미탐지 시에만 생성) ──────────────────────────
    if app["query_name"] and not has_threat:
        name_safe = _safe_content(app["query_name"], 50)
        rules.append(
            f'# Frame {frame_no}\n'
            f'alert udp any any -> any {dst_port} '
            f'(msg:"DNS:QUERY {name_safe}"; '
            f'content:"{name_safe}"; '
            f'sid:{rule_id}; rev:1;)'
        )
        rule_id += 1

    pattern_rules = {
        "LONG_DOMAIN":           ("DNS:LONG-DOMAIN",
                                   "dsize:>100; "),
        "DNS_TUNNELING":         ("DNS:TUNNELING",
                                   'content:"|00 10|"; offset:2; depth:4; '),
        "SUSPICIOUS_DOMAIN":     ("DNS:SUSPICIOUS",
                                   f'content:"{_safe_content(app["query_name"], 30)}"; nocase; '),
        "DNS_TXT_QUERY":         ("DNS:TXT-QUERY",
                                   'content:"|00 10|"; '),
        "MALICIOUS_DOMAIN":      ("DNS:MALICIOUS",
                                   f'content:"{_safe_content(app["query_name"], 40)}"; nocase; '),
        "SUSPICIOUS_DOMAIN_VT":  ("DNS:SUSPICIOUS",
                                   f'content:"{_safe_content(app["query_name"], 40)}"; nocase; '),
        "TYPOSQUATTING":         ("",  # label은 아래에서 동적 생성
                                   f'content:"{_safe_content(app["query_name"], 40)}"; nocase; '),
    }
    for pat in app["suspicious_patterns"]:
        if pat not in pattern_rules:
            continue
        label, content_opt = pattern_rules[pat]

        # ── 공통: 판정 출처 접두어 결정 ──────────────────────────────────
        # source: "virustotal" → "VT:", "safebrowsing" → "SB:", "cache" → 캐시된 원본 표시
        def _rep_prefix(rep: dict) -> str:
            """reputation 결과의 출처를 짧은 접두어로 반환"""
            src = rep.get("source", "unknown")
            if src == "virustotal":
                return "VT"
            if src == "safebrowsing":
                return "SB"
            if src == "cache":
                # 캐시된 결과는 reason에서 원본 출처 유추
                reason = rep.get("reason", "")
                if "Safe Browsing" in reason:
                    return "SB(cache)"
                if "VirusTotal" in reason:
                    return "VT(cache)"
                return "cache"
            return "API"

        # ── TYPOSQUATTING: 브랜드 사칭 정보 포함 ─────────────────────────
        if pat == "TYPOSQUATTING":
            typo = app.get("typosquatting") or {}
            brand = typo.get("brand", "")
            brand_info = f" impersonates {brand}" if brand else ""
            rep = app.get("dns_reputation") or {}
            rep_verdict = rep.get("verdict", "UNKNOWN")
            if rep_verdict in ("MALICIOUS", "SUSPICIOUS"):
                mal    = rep.get("malicious", 0)
                total  = rep.get("total", 0)
                prefix = _rep_prefix(rep)
                label  = f"DNS:TYPO+{rep_verdict} ({prefix}:{mal}/{total}){brand_info}"
            else:
                label = f"DNS:TYPO{brand_info}"

        # ── MALICIOUS_DOMAIN / SUSPICIOUS_DOMAIN_VT: 수치 포함 ────────────
        elif pat in ("MALICIOUS_DOMAIN", "SUSPICIOUS_DOMAIN_VT"):
            rep    = app.get("dns_reputation") or {}
            mal    = rep.get("malicious", 0)
            total  = rep.get("total", 0)
            prefix = _rep_prefix(rep)
            label  = f"{label} ({prefix}:{mal}/{total})"

        rules.append(
            f'# Frame {frame_no}\n'
            f'alert udp any any -> any {dst_port} '
            f'(msg:"{label}"; '
            f'{content_opt}'
            f'sid:{rule_id}; rev:1;)'
        )
        rule_id += 1

    return rules



def parse_icmp_payload(packet, payload: bytes) -> dict:
    """ICMP 패킷 분석 — 터널링·대형 패킷·스윕 탐지"""
    info = {
        "icmp_type": -1, "icmp_code": -1,
        "payload_size": len(payload),
        "suspicious_patterns": [],
    }
    try:
        from scapy.all import ICMP as _ICMP
        if _ICMP in packet:
            info["icmp_type"] = int(packet[_ICMP].type)
            info["icmp_code"] = int(packet[_ICMP].code)
    except Exception:
        pass

    size = len(payload)
    # Large ICMP: payload > 1024 bytes (Ping of Death 전조)
    if size > 1024:
        info["suspicious_patterns"].append("LARGE_ICMP")
    # ICMP Tunnel: payload에 HTTP/TCP 상위 프로토콜 헤더 포함
    if size > 64 and (b"HTTP/" in payload or b"GET " in payload[:8]
                      or b"POST " in payload[:8] or b"SSH-" in payload[:8]):
        info["suspicious_patterns"].append("ICMP_TUNNEL")
    # ICMP Echo Sweep (itype=8, 소형 패킷)
    if info["icmp_type"] == 8 and size <= 64:
        info["suspicious_patterns"].append("ICMP_SWEEP")
    return info


def build_icmp_rules(app: dict, hdr: dict, rule_id: int, frame_no: int) -> list:
    """ICMP 탐지 Snort 룰 생성"""
    rules    = []
    patterns = app.get("suspicious_patterns", [])
    pat_map  = {
        "LARGE_ICMP":  ("HIGH ICMP Large Packet (Ping of Death Precursor)",
                        "itype:8; dsize:>1024; "),
        "ICMP_TUNNEL": ("HIGH ICMP Tunneling Detected",
                        'itype:8; dsize:>64; content:"HTTP/"; nocase; '),
        "ICMP_SWEEP":  ("MEDIUM ICMP Echo Sweep / Ping Scan",
                        "itype:8; icode:0; "),
    }
    for pat in patterns:
        if pat in pat_map:
            msg_label, opts = pat_map[pat]
            rules.append(
                f"# Frame {frame_no}\n"
                f"alert icmp any any -> any any "
                f'(msg:"{msg_label}"; '
                f"{opts}"
                f"sid:{rule_id}; rev:1;)"
            )
            rule_id += 1
    return rules

def build_ftp_rules(app: dict, hdr: dict, rule_id: int, frame_no: int) -> list:
    """FTP 전용 룰 — 실제 목적지 포트 포함, 기본값 21"""
    rules = []
    raw_port = hdr.get("dst_port", "any")
    dst_port = raw_port if raw_port not in ("any", "0") else "21"

    if app["command"]:
        arg_opt = f'content:"{_safe_content(app["argument"])}"; distance:1; ' if app["argument"] else ""
        rules.append(
            f'# Frame {frame_no}\n'
            f'alert tcp any any -> any {dst_port} '
            f'(msg:"FTP Command {app["command"]}"; '
            f'flow:to_server,established; '
            f'content:"{app["command"]}"; '
            f'{arg_opt}'
            f'sid:{rule_id}; rev:1;)'
        )
        rule_id += 1

    pattern_rules = {
        "PRIVILEGED_LOGIN_ATTEMPT": ("HIGH FTP Privileged Account Login Attempt",
                                     'content:"USER"; nocase; content:"root"; distance:1; nocase; '),
        "FTP_PASSWORD_TRANSMITTED": ("MEDIUM FTP Cleartext Password Transmission",
                                     'content:"PASS"; nocase; '),
        "FTP_PATH_TRAVERSAL":       ("HIGH FTP Path Traversal Attempt",
                                     'content:"../"; '),
        "EXECUTABLE_TRANSFER":      ("HIGH FTP Executable File Transfer",
                                     'content:".exe"; nocase; '),
        "FTP_LOGIN_FAILURE":        ("MEDIUM FTP Login Failure (530)",
                                     'content:"530"; depth:3; '),
            "ANONYMOUS_LOGIN_ATTEMPT": ("MEDIUM FTP Anonymous Login Attempt",
                              'content:"USER anonymous"; nocase; '),
        "FTP_BOUNCE_ATTEMPT":      ("HIGH FTP Bounce Attack Attempt",
                              'content:"PORT "; nocase; '),
        }
    for pat in app["suspicious_patterns"]:
        if pat in pattern_rules:
            label, content_opt = pattern_rules[pat]
            rules.append(
                f'# Frame {frame_no}\n'
                f'alert tcp any any -> any {dst_port} '
                f'(msg:"{label}"; '
                f'flow:to_server,established; '
                f'{content_opt}'
                f'sid:{rule_id}; rev:1;)'
            )
            rule_id += 1

    return rules


def build_telnet_rules(app: dict, hdr: dict, rule_id: int, frame_no: int) -> list:
    """Telnet 전용 룰 — 실제 목적지 포트 포함, 기본값 23"""
    rules = []
    raw_port = hdr.get("dst_port", "any")
    dst_port = raw_port if raw_port not in ("any", "0") else "23"

    rules.append(
        f'# Frame {frame_no}\n'
        f'alert tcp any any -> any {dst_port} '
        f'(msg:"TELNET Session Detected (Cleartext Protocol)"; '
        f'flow:to_server,established; '
        f'content:"|ff|"; depth:1; '
        f'sid:{rule_id}; rev:1;)'
    )
    rule_id += 1

    pattern_rules = {
        "CREDENTIAL_IN_CLEARTEXT": ("CRITICAL Telnet Cleartext Credential Transmission",
                                    'content:"password"; nocase; '),
        "DANGEROUS_COMMAND":       ("CRITICAL Telnet Dangerous Command Execution",
                                    'content:"rm -rf"; nocase; '),
        "PRIVILEGE_ESCALATION":    ("HIGH Telnet Privilege Escalation Attempt",
                                    'content:"chmod"; nocase; '),
        "SENSITIVE_FILE_ACCESS":   ("HIGH Telnet Sensitive File Access",
                                    'content:"/etc/passwd"; '),
        "REVERSE_SHELL":           ("CRITICAL Telnet Reverse Shell Attempt",
                                    'content:"/dev/tcp/"; '),
    }
    for pat in app["suspicious_patterns"]:
        if pat in pattern_rules:
            label, content_opt = pattern_rules[pat]
            rules.append(
                f'# Frame {frame_no}\n'
                f'alert tcp any any -> any {dst_port} '
                f'(msg:"{label}"; '
                f'flow:to_server,established; '
                f'{content_opt}'
                f'sid:{rule_id}; rev:1;)'
            )
            rule_id += 1

    return rules


def build_smtp_rules(app: dict, hdr: dict, rule_id: int, frame_no: int) -> list:
    """SMTP 전용 룰 — 실제 목적지 포트 포함, 기본값 [25,465,587]"""
    rules = []
    raw_port = hdr.get("dst_port", "any")
    dst_port = raw_port if raw_port not in ("any", "0") else "[25,465,587]"

    if app["command"]:
        addr_opt = f'content:"{_safe_content(app["from_addr"])}"; distance:0; ' if app["from_addr"] else ""
        rules.append(
            f'# Frame {frame_no}\n'
            f'alert tcp any any -> any {dst_port} '
            f'(msg:"SMTP Command {app["command"]}"; '
            f'flow:to_server,established; '
            f'content:"{app["command"]}"; nocase; '
            f'{addr_opt}'
            f'sid:{rule_id}; rev:1;)'
        )
        rule_id += 1

    pattern_rules = {
        "SMTP_AUTH_ATTEMPT":         ("MEDIUM SMTP Authentication Attempt",
                                      'content:"AUTH"; nocase; content:"LOGIN"; distance:1; nocase; '),
        "SMTP_AUTH_FAILURE":         ("HIGH SMTP Authentication Failure (535)",
                                      'content:"535"; depth:3; '),
        "SPAM_MAILER":               ("HIGH SMTP Bulk/Spam Mailer Detected",
                                      'content:"X-Mailer"; nocase; content:"MASS"; distance:0; nocase; '),
        "PHISHING_CONTENT":          ("HIGH SMTP Phishing Email Detected",
                                      'content:"verify your account"; nocase; '),
        "BASE64_ENCODED_ATTACHMENT": ("MEDIUM SMTP Base64 Encoded Attachment",
                                      'content:"Content-Transfer-Encoding"; nocase; content:"base64"; distance:0; nocase; '),
            "SMTP_OPEN_RELAY_ATTEMPT": ("HIGH SMTP Open Relay Attempt",
                               'content:"RCPT TO:"; nocase; content:"@"; distance:0; '),
        "SMTP_REPLY_TO_SPOOF":    ("MEDIUM SMTP Reply-To Header Spoofing",
                               'content:"Reply-To:"; nocase; '),
        }
    for pat in app["suspicious_patterns"]:
        if pat in pattern_rules:
            label, content_opt = pattern_rules[pat]
            rules.append(
                f'# Frame {frame_no}\n'
                f'alert tcp any any -> any {dst_port} '
                f'(msg:"{label}"; '
                f'flow:to_server,established; '
                f'{content_opt}'
                f'sid:{rule_id}; rev:1;)'
            )
            rule_id += 1

    return rules


def build_generic_rule(hdr: dict, payload: bytes, rule_id: int, frame_no: int):
    """
    지원 외 프로토콜 범용 룰 — payload content만 사용.
    content가 3~40 bytes 범위를 벗어나면 None 반환 (룰 생성 생략).
    """
    proto    = hdr["proto"]
    dst_port = hdr["dst_port"]
    port_str = f"any {dst_port}" if dst_port != "any" else "any any"

    # printable 문자 추출 → 최대 40 bytes 로 자름
    printable   = payload.decode("utf-8", errors="ignore")
    content_str = _safe_content(printable, CONTENT_MAX_BYTES)

    # printable content 가 3 bytes 미만이면 hex 로 대체 시도
    if not _is_valid_content(content_str):
        hex_str = _bytes_to_hex_content(payload, CONTENT_MAX_BYTES)
        # hex content 파이프 제외 실제 바이트 수 계산 ("|xx xx xx|" → 바이트 수)
        hex_bytes = payload[:CONTENT_MAX_BYTES]
        if len(hex_bytes) < CONTENT_MIN_BYTES:
            return None   # payload 자체가 너무 짧으면 룰 생성 포기
        content_str = hex_str

    return (
        f'# Frame {frame_no}\n'
        f'alert {proto} any any -> {port_str} '
        f'(msg:"Generic Payload Rule"; '
        f'content:"{content_str}"; '
        f'sid:{rule_id}; rev:1;)'
    )


# ══════════════════════════════════════════════════════
# 4b. ICMP 룰 생성 (화이트리스트 미일치 패킷용)
# ══════════════════════════════════════════════════════

_ICMP_TYPE_NAMES = {
    0: "Echo Reply",       3: "Destination Unreachable",
    4: "Source Quench",    5: "Redirect",
    8: "Echo Request",     9: "Router Advertisement",
    10: "Router Solicitation", 11: "Time Exceeded",
    12: "Parameter Problem",   13: "Timestamp Request",
    14: "Timestamp Reply",     15: "Information Request",
    16: "Information Reply",   17: "Address Mask Request",
    18: "Address Mask Reply",  30: "Traceroute",
}
_STANDARD_ICMP_TYPES = {0, 3, 4, 5, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 30}


def _build_icmp_rules_inline(packet, payload: bytes, icmp_type: int, icmp_code: int,
                              hdr: dict, rule_id: int, frame_no: int):
    """
    화이트리스트 미일치 ICMP 패킷에 대해 의심 패턴을 분석하고
    Snort 룰을 생성한다.

    Returns: (raw_rules: list, app_info: dict)
    """
    src_ip = hdr.get("src_ip", "any")
    dst_ip = hdr.get("dst_ip", "any")

    # src/dst IP 추출
    try:
        if IP in packet:
            src_ip = str(packet[IP].src)
            dst_ip = str(packet[IP].dst)
    except Exception:
        pass

    type_name = _ICMP_TYPE_NAMES.get(icmp_type, f"Type{icmp_type}")
    type_opt  = f"itype:{icmp_type}; " if icmp_type >= 0 else ""
    code_opt  = f"icode:{icmp_code}; " if icmp_code >= 0 else ""

    # ── 의심 패턴 분석 ─────────────────────────────────────────────────────
    suspicious = []
    if len(payload) > 1024:
        suspicious.append("LARGE_PAYLOAD")
    if icmp_type >= 0 and icmp_type not in _STANDARD_ICMP_TYPES:
        suspicious.append("UNUSUAL_TYPE")
    tunnel_sigs = [b"GET ", b"POST ", b"HTTP/", b"SSH-", b"\x00\x00\x00\x00\x00\x01"]
    if any(sig in payload for sig in tunnel_sigs):
        suspicious.append("TUNNEL_PATTERN")
    if len(payload) > 8:
        non_print = sum(1 for b in payload if not (32 <= b <= 126))
        if non_print / len(payload) > 0.6 and "LARGE_PAYLOAD" not in suspicious:
            suspicious.append("SUSPICIOUS_DATA")

    app_info = {
        "icmp_type":           icmp_type,
        "icmp_code":           icmp_code,
        "icmp_type_name":      type_name,
        "suspicious_patterns": suspicious,
    }

    rules     = []
    curr_id   = rule_id
    pat_rules = {
        "LARGE_PAYLOAD":  (f"HIGH ICMP Large Payload - Possible Flood or Tunnel",
                           f"dsize:>1024; {type_opt}{code_opt}"),
        "TUNNEL_PATTERN": (f"HIGH ICMP Tunneling Detected - Application Protocol in ICMP",
                           f"{type_opt}{code_opt}"),
        "UNUSUAL_TYPE":   (f"MEDIUM ICMP Unusual Type {icmp_type} Detected",
                           f"{type_opt}{code_opt}"),
        "SUSPICIOUS_DATA":(f"MEDIUM ICMP Suspicious Binary Payload",
                           f"{type_opt}{code_opt}"),
    }

    for pat in suspicious:
        if pat not in pat_rules:
            continue
        label, opts = pat_rules[pat]
        content_opt = ""
        if pat == "TUNNEL_PATTERN" and payload:
            pstr = _safe_content(payload.decode("utf-8", errors="ignore"), CONTENT_MAX_BYTES)
            if CONTENT_MIN_BYTES <= len(pstr.strip()) <= CONTENT_MAX_BYTES:
                content_opt = f'content:"{pstr}"; '
        rules.append(
            f'# Frame {frame_no}\n'
            f'alert icmp {src_ip} any -> {dst_ip} any '
            f'(msg:"{label}"; {opts}{content_opt}sid:{curr_id}; rev:1;)'
        )
        curr_id += 1

    # 패턴 없어도 화이트리스트 미일치이므로 기본 룰 생성
    if not suspicious:
        pstr = _safe_content(payload.decode("utf-8", errors="ignore") if payload else "",
                             CONTENT_MAX_BYTES)
        if CONTENT_MIN_BYTES <= len(pstr.strip()) <= CONTENT_MAX_BYTES:
            content_opt = f'content:"{pstr}"; '
        else:
            hex_bytes = payload[:CONTENT_MAX_BYTES] if payload else b""
            content_opt = (f'content:"|{" ".join(f"{b:02x}" for b in hex_bytes)}|"; '
                           if len(hex_bytes) >= CONTENT_MIN_BYTES else "")
        rules.append(
            f'# Frame {frame_no}\n'
            f'alert icmp {src_ip} any -> {dst_ip} any '
            f'(msg:"MEDIUM ICMP {type_name} - Not in Whitelist"; '
            f'{type_opt}{code_opt}{content_opt}sid:{curr_id}; rev:1;)'
        )

    return rules, app_info




def generate_rules_for_packet(packet, payload: bytes, rule_id: int, frame_no: int = 0) -> dict:
    """
    [처리 순서]
    0a단계 — 포트 443(HTTPS) 차단: 암호화 트래픽은 룰 생성 불가
    0b단계 — 전역 화이트리스트 검사: 정상 패킷이면 룰 생성 제외 (모든 프로토콜 공통)
    1단계  — 키워드 탐지 우선 실행
    2단계  — 프로토콜별 Snort 룰 자동 생성 (content 3~40 bytes 범위 필터)

    Returns:
        {
          "protocol":              str,
          "rules":                 [str, ...],
          "app_info":              dict,
          "suspicious_patterns":   [str, ...],
          "next_rule_id":          int,
          "kw_detected":           bool,
          "kw_matched_keywords":   [str, ...],
          "kw_matched_categories": [str, ...],
          "kw_severity_max":       str,
          "kw_rules":              [str, ...],
          "skipped_reason":        str or None,
          "wl_matched":            bool,
          "wl_reason":             str,
        }
    """
    protocol = detect_protocol(packet, payload)
    hdr      = extract_header_features(packet)
    dst_port = hdr.get("dst_port", "any")

    # ── ICMP type/code 추출 (화이트리스트 검사용) ─────────────────────────────
    icmp_type = -1
    icmp_code = -1
    if protocol == "ICMP" and ICMP in packet:
        try:
            icmp_type = int(packet[ICMP].type)
            icmp_code = int(packet[ICMP].code)
        except Exception:
            pass

    # ══════════════════════════════════════════════════════
    # 0a단계: 포트 443 (HTTPS) → 룰 생성 전면 차단
    # ══════════════════════════════════════════════════════
    try:
        port_num = int(dst_port)
    except (ValueError, TypeError):
        port_num = 0

    if port_num in BLOCKED_DST_PORTS:
        return {
            "protocol":              protocol,
            "rules":                 [],
            "app_info":              {},
            "suspicious_patterns":   [],
            "next_rule_id":          rule_id,
            "kw_detected":           False,
            "kw_matched_keywords":   [],
            "kw_matched_categories": [],
            "kw_severity_max":       "LOW",
            "kw_rules":              [],
            "skipped_reason":        f"dst_port {dst_port} is blocked (HTTPS/encrypted — no rule generated)",
            "wl_matched":            False,
            "wl_reason":             "",
        }

    # ══════════════════════════════════════════════════════
    # 0a-2단계: 노이즈 필터 — 의미 없는 payload 조기 제외
    # irregularity_score 체크는 OTHER 프로토콜에만 적용됩니다.
    # ══════════════════════════════════════════════════════
    noise_result = is_noise(payload, protocol)
    if noise_result["noise"]:
        return {
            "protocol":              protocol,
            "rules":                 [],
            "app_info":              {},
            "suspicious_patterns":   [],
            "next_rule_id":          rule_id,
            "kw_detected":           False,
            "kw_matched_keywords":   [],
            "kw_matched_categories": [],
            "kw_severity_max":       "LOW",
            "kw_rules":              [],
            "skipped_reason":        noise_result["reason"],
            "wl_matched":            False,
            "wl_reason":             "",
        }

    # ══════════════════════════════════════════════════════
    # 0b단계: 전역 화이트리스트 검사 (모든 프로토콜 공통)
    # ══════════════════════════════════════════════════════
    wl_result = check_global_whitelist(
        payload   = payload,
        protocol  = protocol,
        icmp_type = icmp_type,
        icmp_code = icmp_code,
    )

    if wl_result["matched"]:
        # 정상 패킷 → 룰 생성 없이 즉시 반환
        return {
            "protocol":              protocol,
            "rules":                 [],
            "app_info":              {},
            "suspicious_patterns":   [],
            "next_rule_id":          rule_id,
            "kw_detected":           False,
            "kw_matched_keywords":   [],
            "kw_matched_categories": [],
            "kw_severity_max":       "LOW",
            "kw_rules":              [],
            "skipped_reason":        None,
            "wl_matched":            True,
            "wl_reason":             wl_result["reason"],
        }

    # ══════════════════════════════════════════════════════
    # 0c단계: DNS 목적지 포트 + 화이트리스트 검사
    # DNS 룰은 dst_port=53 (쿼리)에서만 생성.
    # dst_port≠53 이면 응답 패킷 → 분석 제외.
    # dns_whitelist.yaml 에 등록된 도메인도 분석 제외.
    # ══════════════════════════════════════════════════════
    if protocol == "DNS":
        # 응답 패킷(dst_port=랜덤 높은 포트) → 룰 생성 불필요
        try:
            _dst = int(hdr.get("dst_port", 53))
        except (ValueError, TypeError):
            _dst = 53
        if _dst != 53:
            return {
                "protocol":              protocol,
                "rules":                 [],
                "app_info":              {},
                "suspicious_patterns":   [],
                "next_rule_id":          rule_id,
                "kw_detected":           False,
                "kw_matched_keywords":   [],
                "kw_matched_categories": [],
                "kw_severity_max":       "LOW",
                "kw_rules":              [],
                "skipped_reason":        f"DNS 응답 패킷 (dst_port={_dst}, 룰 생성 제외)",
                "wl_matched":            False,
                "wl_reason":             "",
            }
        # dns_whitelist.yaml 직접 확인 (캐시·API 무관)
        if payload:
            _dns_info = parse_dns_payload(packet, payload)
            _qname    = _dns_info.get("query_name", "")
            if _qname:
                _qname_low = _qname.lower().rstrip(".")

                # 1) dns_whitelist.yaml 등록 도메인
                _wl_entry = _dns_wl_check(_qname)

                # 2) _SAFE_DOMAIN_SUFFIXES 등록 기업 서브도메인
                #    (*.oracle.com, *.salesforce.com 등 — 타이포스쿼팅 오탐 방지 목록과 공유)
                if not _wl_entry:
                    for _sfx in _SAFE_DOMAIN_SUFFIXES:
                        if _qname_low.endswith(_sfx) or _qname_low == _sfx.lstrip("."):
                            _wl_entry = {"category": f"Trusted Enterprise ({_sfx.lstrip('.')})"}
                            break

                if _wl_entry:
                    return {
                        "protocol":              protocol,
                        "rules":                 [],
                        "app_info":              _dns_info,
                        "suspicious_patterns":   [],
                        "next_rule_id":          rule_id,
                        "kw_detected":           False,
                        "kw_matched_keywords":   [],
                        "kw_matched_categories": [],
                        "kw_severity_max":       "LOW",
                        "kw_rules":              [],
                        "skipped_reason":        f"DNS whitelist: {_qname} ({_wl_entry.get('category', '')})",
                        "wl_matched":            True,
                        "wl_reason":             f"dns_whitelist / safe_suffix: {_qname}",
                    }
    kw_result   = _kw_detect(payload, protocol, dst_port, frame_no)
    kw_detected = bool(kw_result["matched_keywords"])

    if kw_detected:
        return {
            "protocol":              protocol,
            "rules":                 kw_result["rules"],
            "app_info":              {},
            "suspicious_patterns":   [f"[KW] {c}" for c in kw_result["matched_categories"]],
            "next_rule_id":          rule_id,
            "kw_detected":           True,
            "kw_matched_keywords":   kw_result["matched_keywords"],
            "kw_matched_categories": kw_result["matched_categories"],
            "kw_severity_max":       kw_result["severity_max"],
            "kw_rules":              kw_result["rules"],
            "skipped_reason":        None,
            "wl_matched":            False,
            "wl_reason":             "",
        }

    # ══════════════════════════════════════════════════════
    # 2단계: 프로토콜별 Snort 룰 자동 생성
    # ══════════════════════════════════════════════════════
    raw_rules = []
    app_info  = {}

    if protocol == "HTTP":
        app_info  = parse_http_payload(payload)
        raw_rules = build_http_rules(app_info, hdr, rule_id, frame_no)

    elif protocol == "DNS":
        app_info  = parse_dns_payload(packet, payload)
        raw_rules = build_dns_rules(app_info, hdr, rule_id, frame_no)

    elif protocol == "FTP":
        app_info  = parse_ftp_payload(payload)
        raw_rules = build_ftp_rules(app_info, hdr, rule_id, frame_no)

    elif protocol == "TELNET":
        app_info  = parse_telnet_payload(payload)
        raw_rules = build_telnet_rules(app_info, hdr, rule_id, frame_no)

    elif protocol == "SMTP":
        app_info  = parse_smtp_payload(payload)
        raw_rules = build_smtp_rules(app_info, hdr, rule_id, frame_no)

    elif protocol == "ICMP":
        # 신규: parse_icmp_payload + build_icmp_rules (LARGE/TUNNEL/SWEEP)
        app_info  = parse_icmp_payload(packet, payload)
        raw_rules = build_icmp_rules(app_info, hdr, rule_id, frame_no)
        # 기존 inline 분석 결과도 병합 (Tunnel 패턴 등)
        inline_rules, inline_info = _build_icmp_rules_inline(
            packet, payload, icmp_type, icmp_code, hdr, rule_id + len(raw_rules), frame_no
        )
        raw_rules.extend(inline_rules)
        app_info.update({k: v for k, v in inline_info.items() if k not in app_info})

    else:
        generic   = build_generic_rule(hdr, payload, rule_id, frame_no)
        raw_rules = [generic] if generic is not None else []
        app_info  = {}

    # ── content 유효성 필터 (3 bytes 이상 ~ 40 bytes 이하) ───────────────────
    def _content_in_range(rule_str: str) -> bool:
        matches = re.findall(r'content:"([^"]*)"', rule_str)
        if not matches:
            return True   # content 없는 룰은 통과
        for m in matches:
            if m.startswith('|') and m.endswith('|'):
                byte_len = len(m[1:-1].replace(' ', '')) // 2
            else:
                byte_len = len(m.encode('utf-8'))
            if not (CONTENT_MIN_BYTES <= byte_len <= CONTENT_MAX_BYTES):
                return False
        return True

    rules = [r for r in raw_rules if r is not None and _content_in_range(r)]


    # ══════════════════════════════════════════════════════════════════════
    # 파일 평판 분석 (HTTP/FTP/SMTP 실행파일 추출 → VT 해시 조회 → 룰 생성)
    # file_reputation_engine.py 가 처리하며 VT API 키가 없으면 스킵됩니다.
    # ══════════════════════════════════════════════════════════════════════
    if protocol in ("HTTP", "FTP", "SMTP") and payload:
        try:
            _file_rep = analyze_file_in_packet(
                payload  = payload,
                protocol = protocol,
                hdr      = hdr,
                frame_no = frame_no,
                rule_id  = rule_id,
            )
            if _file_rep["rules"]:
                raw_rules.extend(_file_rep["rules"])
                rule_id = _file_rep["next_rule_id"]
            if _file_rep["verdicts"]:
                for _v in _file_rep["verdicts"]:
                    if _v.verdict in ("MALICIOUS", "SUSPICIOUS"):
                        app_info.setdefault("file_verdicts", []).append({
                            "filename":  _v.filename,
                            "sha256":    _v.sha256,
                            "verdict":   _v.verdict,
                            "malicious": _v.malicious,
                            "total":     _v.total,
                            "reason":    _v.reason,
                        })
        except Exception as _fe:
            pass

    return {
        "protocol":              protocol,
        "rules":                 rules,
        "app_info":              app_info,
        "suspicious_patterns":   app_info.get("suspicious_patterns", []),
        "next_rule_id":          rule_id + len(rules),
        "kw_detected":           False,
        "kw_matched_keywords":   [],
        "kw_matched_categories": [],
        "kw_severity_max":       "LOW",
        "kw_rules":              [],
        "skipped_reason":        None,
        "wl_matched":            False,
        "wl_reason":             "",
    }

