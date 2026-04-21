from flask import Flask, render_template, request, jsonify
from scapy.all import rdpcap, Raw, IP, TCP, UDP, ICMP, DNS
from protocol_rule_engine import generate_rules_for_packet
from keyword_rule_engine import get_keywords_summary, get_keywords_file_path, get_keywords_file_mtime, reload_keywords
from whitelist_engine import (get_whitelist_summary, get_whitelist_file_path,
                              get_whitelist_file_mtime, reload_whitelist,
                              get_whitelist_total, add_whitelist_entry)
from noise_filter_engine import (reload_noise_filter, get_noise_filter_summary,
                                  get_noise_filter_file_path, get_noise_filter_mtime,
                                  get_noise_filter_total)
from dns_reputation_engine import (get_cache_stats, get_cache_entries, delete_cache_entry,
                                    clear_mem_cache, reload_whitelist as reload_dns_whitelist,
                                    get_whitelist_domains, save_vt_api_key, get_vt_key_status,
                                    save_sb_api_key, get_sb_key_status)
from auto_learn_engine import (run_auto_learn, get_learn_log, get_auto_categories,
                                delete_keyword, get_stats,
                                reload_ai_config, save_ai_config, get_providers_status)
import tempfile
import os
import binascii

app = Flask(__name__)

# ─────────────────────────────────────────────
# 유틸
# ─────────────────────────────────────────────

def _extract_payload(packet) -> bytes | None:
    """
    scapy 패킷에서 애플리케이션 레이어 payload bytes 를 추출한다.

    scapy 는 프로토콜을 인식하면 Raw 대신 전용 레이어(DNS 등)를 붙이므로
    Raw 만 확인하면 DNS · ICMP 패킷이 누락된다.

    우선순위
    --------
    1. Raw 레이어  — HTTP, FTP, TELNET, SMTP 등
    2. DNS 레이어  — scapy 가 UDP/53 을 DNS 로 파싱한 경우
    3. UDP payload — Raw/DNS 없이 UDP 로만 파싱된 경우
    4. ICMP payload
    """
    # 1순위: Raw
    if Raw in packet:
        data = bytes(packet[Raw].load)
        if data:
            return data

    # 2순위: DNS (scapy 가 DNS 레이어로 파싱)
    if DNS in packet:
        try:
            data = bytes(packet[DNS])
            if data:
                return data
        except Exception:
            pass

    # 3순위: UDP payload (Raw·DNS 없는 UDP)
    if UDP in packet:
        try:
            pl = packet[UDP].payload
            if pl and pl.name != 'NoPayload':
                data = bytes(pl)
                if data:
                    return data
        except Exception:
            pass

    # 4순위: ICMP payload
    if ICMP in packet:
        try:
            pl = packet[ICMP].payload
            if pl and pl.name != 'NoPayload':
                data = bytes(pl)
                if data:
                    return data
        except Exception:
            pass

    return None


def format_hex_dump(data, bytes_per_row=16):
    """offset | hex | ascii 3열 hex dump 생성"""
    rows = []
    for i in range(0, len(data), bytes_per_row):
        chunk = data[i:i + bytes_per_row]
        offset    = f"{i:08x}"
        hex_bytes = ' '.join(f"{b:02x}" for b in chunk).ljust(bytes_per_row * 3 - 1)
        ascii_rep = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
        rows.append({'offset': offset, 'hex': hex_bytes, 'ascii': ascii_rep})
    return rows


# ─────────────────────────────────────────────
# 패킷 분석 (프로토콜별 복합 룰 생성)
# ─────────────────────────────────────────────

# 프로토콜별 심각도 색상 매핑
PROTOCOL_COLORS = {
    "HTTP":   "#3498db",
    "DNS":    "#9b59b6",
    "FTP":    "#e67e22",
    "TELNET": "#e74c3c",
    "SMTP":   "#2ecc71",
    "OTHER":  "#95a5a6",
}

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

def get_rule_severity(rule: str) -> str:
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if sev in rule:
            return sev
    return "LOW"


def _content_key(rule: str) -> str:
    """
    Snort 룰의 실질적 동일성 판별 키.
    프로토콜 + 정렬된 content 값 목록 기준으로 비교하여
    msg/sid/nocase/포트가 달라도 탐지 대상이 같으면 동일 룰로 판단한다.
    """
    import re
    proto_m  = re.match(r'alert\s+(\w+)', rule)
    proto    = proto_m.group(1).lower() if proto_m else "?"
    contents = sorted(re.findall(r'content:"([^"]+)"', rule))
    return f"{proto}|{contents}"


_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

def _rule_severity(rule: str) -> int:
    for sev, order in _SEV_ORDER.items():
        if sev in rule:
            return order
    return 4


def _dedup_rules(new_rules: list, seen_content_keys: set) -> list:
    """
    새로 생성된 룰 목록에서 이미 탐지된 content 와 동일한 룰을 제거한다.

    중복 판별 기준: 프로토콜 + content 값 조합 (msg·sid·nocase·포트 무관)
    seen_content_keys 도 함께 갱신된다.
    """
    unique = []
    for rule in new_rules:
        key = _content_key(rule.split('\n')[-1].strip())
        if key and key not in seen_content_keys:
            seen_content_keys.add(key)
            unique.append(rule)
    return unique


def _merge_same_content_rules(rules: list) -> list:
    """
    전체 룰 목록에서 content 가 동일한 룰들을 하나로 병합한다.

    병합 정책
    ---------
    - content_key 가 같은 그룹 내에서 가장 높은 심각도의 msg 를 채택한다.
    - nocase 가 하나라도 있으면 최종 룰에 포함한다.
    - sid 는 그룹 내 가장 먼저 등장한 룰의 sid 를 유지한다.
    - # Frame 주석은 첫 번째 룰 기준으로 유지한다.
    """
    import re
    groups: dict = {}
    order:  list = []
    for rule in rules:
        body = rule.split('\n')[-1].strip()
        k = _content_key(body)
        if k not in groups:
            groups[k] = []
            order.append(k)
        groups[k].append(rule)

    merged = []
    for k in order:
        grp = groups[k]
        if len(grp) == 1:
            merged.append(grp[0])
            continue

        best = min(grp, key=lambda r: _rule_severity(r.split('\n')[-1]))

        first_body = grp[0].split('\n')[-1].strip()
        best_body  = best.split('\n')[-1].strip()
        first_sid_m = re.search(r'sid:(\d+)', first_body)
        best_sid_m  = re.search(r'sid:(\d+)', best_body)
        if first_sid_m and best_sid_m:
            best_body = best_body.replace(
                f'sid:{best_sid_m.group(1)}',
                f'sid:{first_sid_m.group(1)}')

        has_nocase = any('nocase' in r.split('\n')[-1] for r in grp)
        if has_nocase and 'nocase' not in best_body:
            best_body = re.sub(r'(sid:\d+)', r'nocase; ', best_body)

        first_lines = grp[0].split('\n')
        frame_comment = first_lines[0] if len(first_lines) > 1 else ''
        final = f"{frame_comment}\n{best_body}" if frame_comment else best_body
        merged.append(final)

    return merged


def analyze_packets(packets):
    """패킷 분석 – 프로토콜별 복합 룰 생성 (중복 룰 자동 제거)"""
    rules            = []
    payload_info     = []
    seen_payloads    = set()
    seen_rule_bodies = set()   # content 기반 중복 제거용
    rule_id          = 1000001

    # 프로토콜별 룰 카운터
    proto_stats = {"HTTP": 0, "DNS": 0, "FTP": 0, "TELNET": 0, "SMTP": 0, "ICMP": 0, "OTHER": 0}

    # ── 트래픽 요약 집계 구조 ─────────────────────────────────────────────────
    # proto → { 'tx': int, 'rx': int, 'bytes_tx': int, 'bytes_rx': int }
    # 송신(tx)/수신(rx) 기준: 패킷 내 가장 작은 src_ip = 클라이언트로 가정
    # (pcap 캡처 특성상 절대 기준이 없으므로 src/dst 양방향을 모두 집계)
    traffic_raw: dict[str, dict] = {}   # proto → {src_ip: cnt, ...}
    _all_ips: set[str] = set()

    def _get_ips(pkt):
        try:
            if IP in pkt:
                return pkt[IP].src, pkt[IP].dst
        except Exception:
            pass
        return None, None

    print(f"Total packets: {len(packets)}")

    for i, packet in enumerate(packets):
        payload = _extract_payload(packet)
        if payload is None or len(payload) == 0:
            continue

        # ── 프로토콜별 룰 생성 (frame 번호 = 1-based 패킷 인덱스) ──
        frame_no = i + 1
        result   = generate_rules_for_packet(packet, payload, rule_id, frame_no)
        protocol = result["protocol"]
        app_info = result["app_info"]
        patterns = result["suspicious_patterns"]

        new_rules    = result["rules"]
        rule_id      = result["next_rule_id"]
        kw_detected  = result.get("kw_detected", False)
        kw_keywords  = result.get("kw_matched_keywords", [])
        kw_categories= result.get("kw_matched_categories", [])
        kw_sev       = result.get("kw_severity_max", "LOW")
        kw_rules     = result.get("kw_rules", [])
        skipped_reason  = result.get("skipped_reason", None)
        # 전역 화이트리스트 결과 (모든 프로토콜 공통)
        wl_matched = result.get("wl_matched", False)
        wl_reason  = result.get("wl_reason", "")

        # 중복 payload 건너뜀 + 룰 중복 제거
        payload_key = payload[:64]
        if payload_key not in seen_payloads:
            seen_payloads.add(payload_key)
        unique_rules = _dedup_rules(new_rules, seen_rule_bodies)
        rules.extend(unique_rules)
        proto_stats[protocol] = proto_stats.get(protocol, 0) + len(unique_rules)

        # ── 트래픽 집계 (송신/수신/바이트) ────────────────────────────────
        src_ip, dst_ip = _get_ips(packet)
        if src_ip and dst_ip:
            _all_ips.add(src_ip); _all_ips.add(dst_ip)
        plen = len(payload)
        if protocol not in traffic_raw:
            traffic_raw[protocol] = {"frames": [], "total_bytes": 0}
        traffic_raw[protocol]["frames"].append({
            "frame_no": frame_no,
            "src": src_ip or "?",
            "dst": dst_ip or "?",
            "bytes": plen,
        })
        traffic_raw[protocol]["total_bytes"] += plen

        # ── 표시용 legacy 패턴 (기존 UI 호환) ──────────
        important_patterns = []
        for p in patterns:
            emoji_map = {
                "LOG4J_INJECTION":          "🚨 LOG4J SHELL ATTACK DETECTED!",
                "PATH_TRAVERSAL":           "⚠️ Path Traversal Attempt",
                "XSS":                      "⚠️ XSS Attempt",
                "SQL_INJECTION":            "🚨 SQL Injection Attempt",
                "SENSITIVE_PATH":           "⚠️ Sensitive Path Disclosure",
                "COMMAND_EXECUTION":        "🚨 Command Execution Attempt",
                "DNS_TUNNELING":            "🚨 DNS Tunneling Detected",
                "SUSPICIOUS_DOMAIN":        "⚠️ Suspicious Domain Query",
                "MALICIOUS_DOMAIN":         "🚨 DNS — Known Malicious Domain (VirusTotal)",
                "SUSPICIOUS_DOMAIN_VT":     "⚠️ DNS — Suspicious Domain (VirusTotal)",
                "PRIVILEGED_LOGIN_ATTEMPT": "🚨 FTP Privileged Login Attempt",
                "FTP_PASSWORD_TRANSMITTED": "⚠️ FTP Cleartext Password",
                "EXECUTABLE_TRANSFER":      "🚨 FTP Executable Transfer",
                "CREDENTIAL_IN_CLEARTEXT":  "🚨 Telnet Cleartext Credentials",
                "DANGEROUS_COMMAND":        "🚨 Telnet Dangerous Command",
                "REVERSE_SHELL":            "🚨 Reverse Shell Attempt",
                "SMTP_AUTH_FAILURE":        "⚠️ SMTP Auth Failure",
                "PHISHING_CONTENT":         "🚨 Phishing Email Detected",
                "SPAM_MAILER":              "⚠️ Spam Mailer Detected",
                "SUSPICIOUS_UA":            "🕵️ Suspicious User-Agent",
            }
            important_patterns.append(emoji_map.get(p, f"⚠️ {p}"))

        # HTTP 요청도 표시
        if protocol == "HTTP" and app_info.get("method"):
            important_patterns.append(f"🌐 HTTP {app_info['method']} {app_info.get('uri','')[:40]}")

        # DNS 쿼리 도메인 표시
        if protocol == "DNS" and app_info.get("query_name"):
            qname = app_info["query_name"]
            rep   = app_info.get("dns_reputation") or {}
            verdict = rep.get("verdict", "UNKNOWN")
            typo  = app_info.get("typosquatting") or {}

            # 타이포스쿼팅이 탐지됐으면 우선 표시
            if typo:
                sev_emoji = {"CRITICAL":"🚨","HIGH":"⚠️","MEDIUM":"⚠️"}.get(typo.get("severity",""), "⚠️")
                important_patterns.insert(0, f"{sev_emoji} DNS Typosquatting: {qname} — {typo.get('reason','')}")
            else:
                verdict_emoji = {"MALICIOUS": "🚨", "SUSPICIOUS": "⚠️",
                                 "SAFE": "✅", "UNKNOWN": "🔍"}.get(verdict, "🔍")
                important_patterns.insert(0, f"{verdict_emoji} DNS Query: {qname}  [{verdict}]")

        # ── dns_reputation 별도 추출 (템플릿 표시용) ─────────────────────
        dns_rep = None
        if protocol == "DNS":
            dns_rep = app_info.get("dns_reputation")

        # ── Payload 표시 정보 ────────────────────────────
        payload_str     = payload.decode("utf-8", errors="ignore")
        full_hex        = ' '.join(f"{b:02x}" for b in payload)
        hex_rows        = format_hex_dump(payload)
        printable_chars = sum(1 for b in payload if 32 <= b <= 126)
        printable_pct   = round(printable_chars / max(len(payload), 1) * 100, 1)
        null_count      = payload.count(0)

        if all(32 <= b <= 126 for b in payload):
            ascii_range = "All printable"
        elif any(32 <= b <= 126 for b in payload):
            ascii_range = "Mixed"
        else:
            ascii_range = "Binary"

        payload_info.append({
            'index':            i,
            'packet_num':       i + 1,
            'frame_no':         i + 1,          # Wireshark 호환 frame 번호
            'length':           len(payload),
            'protocol':         protocol,
            'protocol_color':   PROTOCOL_COLORS.get(protocol, "#95a5a6"),
            'full_hex':         full_hex,
            'hex_rows':         hex_rows,       # offset | hex | ascii 3열
            'full_ascii':       ''.join(chr(b) if 32 <= b <= 126 else '.' for b in payload),
            'payload':          payload_str[:500] + ('...' if len(payload_str) > 500 else ''),
            'patterns':         important_patterns,
            'has_pattern':      len(important_patterns) > 0 or (
                                    dns_rep is not None and
                                    dns_rep.get('verdict') in ('MALICIOUS', 'SUSPICIOUS')),
            'printable_percent': printable_pct,
            'null_count':       null_count,
            'ascii_range':      ascii_range,
            'generated_rules':  new_rules,
            'skipped_reason':   skipped_reason,
            'wl_matched':  wl_matched,
            'wl_reason':   wl_reason,
            'kw_detected':     kw_detected,
            'kw_keywords':      kw_keywords,
            'kw_categories':    kw_categories,
            'kw_severity':      kw_sev,
            'kw_rules':         kw_rules,
            'app_info':         {k: v for k, v in app_info.items()
                                 if k != "suspicious_patterns"},
            'dns_rep':          dns_rep,
        })
    # False Positive 점수 계산
    if rules:
        critical_count = sum(1 for r in rules if "CRITICAL" in r)
        high_count     = sum(1 for r in rules if "HIGH" in r)
        fp_score = max(0, min(100,
            50
            - critical_count * 15
            - high_count * 8
            + (len([r for r in rules if "Generic" in r]) / max(len(rules), 1)) * 30
        ))
    else:
        fp_score = 0

    # ── content 기반 최종 룰 병합 (동일 content 중 최고 심각도 msg 채택) ─────
    rules = _merge_same_content_rules(rules)

    # ── 트래픽 요약 계산 ──────────────────────────────────────────────────────
    # 가장 빈번한 src_ip 를 "로컬(송신 기준)"으로 추정
    from collections import Counter
    ip_count: Counter = Counter()
    for proto_data in traffic_raw.values():
        for f in proto_data["frames"]:
            if f["src"] != "?": ip_count[f["src"]] += 1
            if f["dst"] != "?": ip_count[f["dst"]] += 1

    # 가장 많이 등장하는 IP 를 내부 로컬 IP 로 간주 (PCAP 캡처 호스트)
    local_ip = ip_count.most_common(1)[0][0] if ip_count else None

    total_frames = sum(len(v["frames"]) for v in traffic_raw.values())
    total_bytes  = sum(v["total_bytes"]   for v in traffic_raw.values())

    traffic_summary: list[dict] = []
    for proto in ["HTTP", "DNS", "FTP", "TELNET", "SMTP", "ICMP", "OTHER"]:
        data   = traffic_raw.get(proto, {"frames": [], "total_bytes": 0})
        frames = data["frames"]
        tx = sum(1 for f in frames if f["src"] == local_ip) if local_ip else 0
        rx = sum(1 for f in frames if f["dst"] == local_ip) if local_ip else 0
        # local_ip 특정 불가 시 src/dst 절반씩 추정
        if local_ip is None:
            tx = len(frames) // 2
            rx = len(frames) - tx
        total_p = len(frames)
        pct     = round(total_p / max(total_frames, 1) * 100, 1)
        bytes_p = data["total_bytes"]
        bpct    = round(bytes_p / max(total_bytes, 1) * 100, 1)
        other_dir = total_p - tx - rx   # 브로드캐스트/멀티캐스트 등
        traffic_summary.append({
            "proto":       proto,
            "total":       total_p,
            "tx":          tx,
            "rx":          rx,
            "other":       other_dir,
            "bytes":       bytes_p,
            "pct_frames":  pct,
            "pct_bytes":   bpct,
        })

    # 전체 합계 행
    traffic_total = {
        "proto":      "TOTAL",
        "total":      total_frames,
        "tx":         sum(t["tx"] for t in traffic_summary),
        "rx":         sum(t["rx"] for t in traffic_summary),
        "bytes":      total_bytes,
        "pct_frames": 100.0,
        "pct_bytes":  100.0,
        "local_ip":   local_ip or "N/A",
    }

    return rules, round(fp_score, 2), payload_info, proto_stats, traffic_summary, traffic_total


# ─────────────────────────────────────────────
# 파일 처리
# ─────────────────────────────────────────────

def process_pcap_file(file_storage):
    temp_fd, temp_path = tempfile.mkstemp(suffix='.pcap')
    try:
        file_storage.save(temp_path)
        file_size = os.path.getsize(temp_path)
        print(f"File saved: {temp_path} ({file_size} bytes)")

        if file_size == 0:
            return [], 0, [{"error": "Empty file"}], {}, [], {}

        try:
            packets = rdpcap(temp_path)
            print(f"Read {len(packets)} packets")
        except Exception as e:
            return [], 0, [{"error": f"Pcap read error: {e}"}], {}, [], {}

        rules, fp_score, payload_info, proto_stats, traffic_summary, traffic_total = analyze_packets(packets)
        return rules, fp_score, payload_info, proto_stats, traffic_summary, traffic_total

    except Exception as e:
        import traceback; traceback.print_exc()
        return [], 0, [{"error": f"Error: {e}"}], {}, [], {}
    finally:
        os.close(temp_fd)
        if os.path.exists(temp_path):
            os.remove(temp_path)


# ─────────────────────────────────────────────
# Flask 라우트
# ─────────────────────────────────────────────

@app.route('/', methods=['GET', 'POST'])
def index():
    rules            = []
    false_positive_score = 0
    payload_info     = []
    error_message    = None
    stats            = {}
    proto_stats      = {}
    traffic_summary  = []
    traffic_total    = {}
    learn_result     = None   # 자동학습 결과

    if request.method == 'POST':
        if 'pcap_file' not in request.files:
            error_message = 'No file uploaded'
        else:
            file = request.files['pcap_file']
            if file.filename == '':
                error_message = 'No file selected'
            else:
                print(f"\n=== Processing: {file.filename} ===")
                rules, false_positive_score, payload_info, proto_stats, \
                    traffic_summary, traffic_total = process_pcap_file(file)

                if not rules and not payload_info:
                    error_message = 'No packets with payload found'
                else:
                    stats = {
                        'total_packets':        len(payload_info),
                        'packets_with_patterns': sum(1 for p in payload_info if p.get('has_pattern')),
                        'rules_generated':      len(rules),
                        'total_bytes':          sum(p.get('length', 0) for p in payload_info),
                    }

                    # ── 자동학습 실행 (미탐지 패킷 → AI 분석 → keywords.yaml 자동 추가) ──
                    auto_learn_enabled = request.form.get('auto_learn', 'on') != 'off'
                    if auto_learn_enabled:
                        print("[AutoLearn] 자동학습 시작...")
                        learn_result = run_auto_learn(payload_info)
                        if learn_result.get('added', 0) > 0:
                            print("[AutoLearn] 키워드 추가됨 — 재분석 중...")
                            rules2, fp2, payload_info2, proto_stats2, \
                                ts2, tt2 = process_pcap_file(file)
                            if rules2:
                                rules, false_positive_score, payload_info, proto_stats = \
                                    rules2, fp2, payload_info2, proto_stats2
                                traffic_summary, traffic_total = ts2, tt2
                                stats['rules_generated'] = len(rules)

    return render_template('index.html',
                           rules=rules,
                           false_positive_score=false_positive_score,
                           payload_info=payload_info,
                           error=error_message,
                           stats=stats,
                           proto_stats=proto_stats,
                           traffic_summary=traffic_summary,
                           traffic_total=traffic_total,
                           learn_result=learn_result)


# ─────────────────────────────────────────────
# 자동학습 관리 라우트
# ─────────────────────────────────────────────

@app.route('/auto-learn', methods=['GET'])
def auto_learn_page():
    """자동학습 현황 및 학습된 키워드 관리 페이지"""
    return render_template('auto_learn.html',
                           stats=get_stats(),
                           auto_cats=get_auto_categories(),
                           log=get_learn_log(50))

@app.route('/auto-learn/log', methods=['GET'])
def auto_learn_log():
    """학습 로그 JSON API"""
    return jsonify(get_learn_log(100))

@app.route('/auto-learn/delete', methods=['POST'])
def auto_learn_delete():
    """특정 자동학습 키워드 삭제 API"""
    data     = request.get_json() or {}
    category = data.get('category', '')
    keyword  = data.get('keyword', '')
    ok = delete_keyword(category, keyword)
    if ok:
        reload_keywords()
    return jsonify({'status': 'ok' if ok else 'not_found'})


# ─────────────────────────────────────────────
# AI 공급자 설정 라우트
# ─────────────────────────────────────────────

@app.route('/ai-settings', methods=['GET'])
def ai_settings_page():
    return render_template('ai_settings.html',
                           providers=get_providers_status())

@app.route('/ai-settings/save', methods=['POST'])
def ai_settings_save():
    payload = request.get_json(silent=True) or {}
    ok = save_ai_config(payload)
    result = reload_ai_config()
    return jsonify({'status': 'ok' if ok else 'error', **result})

@app.route('/ai-settings/reload', methods=['POST'])
def ai_settings_reload():
    return jsonify(reload_ai_config())

@app.route('/ai-settings/status', methods=['GET'])
def ai_settings_status():
    return jsonify(get_providers_status())




# ─────────────────────────────────────────────
# 키워드 관리 라우트
# ─────────────────────────────────────────────

@app.route('/keywords', methods=['GET'])
def keywords_page():
    """키워드 목록 및 관리 페이지"""
    from flask import jsonify
    summary  = get_keywords_summary()
    filepath = get_keywords_file_path()
    mtime    = get_keywords_file_mtime()
    return render_template('keywords.html',
                           categories=summary,
                           filepath=filepath,
                           mtime=mtime)

@app.route('/keywords/reload', methods=['POST'])
def keywords_reload():
    """키워드 파일 재로드 API"""
    from flask import jsonify
    reload_keywords()
    summary = get_keywords_summary()
    total   = sum(c['keyword_count'] for c in summary)
    return jsonify({'status': 'ok', 'categories': len(summary), 'total_keywords': total})


@app.route('/whitelist', methods=['GET'])
def whitelist_page():
    """ICMP 화이트리스트 관리 페이지"""
    summary = get_whitelist_summary()
    return render_template('whitelist.html',
                           entries=summary,
                           filepath=get_whitelist_file_path(),
                           mtime=get_whitelist_file_mtime(),
                           total=len(summary))

@app.route('/whitelist/reload', methods=['POST'])
def whitelist_reload():
    """ICMP 화이트리스트 파일 재로드 API"""
    from flask import jsonify
    count = reload_whitelist()
    return jsonify({'status': 'ok', 'total_entries': count})


@app.route('/whitelist/add', methods=['POST'])
def whitelist_add():
    """페이로드 카드에서 화이트리스트 등록 API"""
    data = request.get_json(silent=True) or {}
    result = add_whitelist_entry(data)
    return jsonify(result)


# ─────────────────────────────────────────────
# 노이즈 필터 관리 라우트
# ─────────────────────────────────────────────

@app.route('/noise-filter', methods=['GET'])
def noise_filter_page():
    """노이즈 필터 관리 페이지"""
    return render_template('noise_filter.html',
                           rules=get_noise_filter_summary(),
                           filepath=get_noise_filter_file_path(),
                           mtime=get_noise_filter_mtime(),
                           total=get_noise_filter_total())

@app.route('/noise-filter/reload', methods=['POST'])
def noise_filter_reload():
    """노이즈 필터 파일 재로드 API"""
    count = reload_noise_filter()
    return jsonify({'status': 'ok', 'total_rules': count})


# ─────────────────────────────────────────────
# DNS Reputation 관리 라우트
# ─────────────────────────────────────────────

@app.route('/dns-reputation', methods=['GET'])
def dns_reputation_page():
    """DNS Reputation 관리 페이지"""
    return render_template('dns_reputation.html',
                           cache_stats=get_cache_stats(),
                           cache_entries=get_cache_entries(200),
                           whitelist_domains=get_whitelist_domains(),
                           vt_status=get_vt_key_status(),
                           sb_status=get_sb_key_status())

@app.route('/dns-reputation/vt-key', methods=['POST'])
def dns_rep_set_vt_key():
    """VirusTotal API 키 저장"""
    data = request.get_json(silent=True) or {}
    key  = data.get('api_key', '').strip()
    ok   = save_vt_api_key(key)
    return jsonify({'status': 'ok' if ok else 'error',
                    'configured': bool(key)})

@app.route('/dns-reputation/sb-key', methods=['POST'])
def dns_rep_set_sb_key():
    """Google Safe Browsing API 키 저장"""
    data = request.get_json(silent=True) or {}
    key  = data.get('api_key', '').strip()
    ok   = save_sb_api_key(key)
    return jsonify({'status': 'ok' if ok else 'error',
                    'configured': bool(key)})

@app.route('/dns-reputation/cache', methods=['GET'])
def dns_rep_cache():
    """캐시 목록 JSON API"""
    return jsonify(get_cache_entries(500))

@app.route('/dns-reputation/cache/delete', methods=['POST'])
def dns_rep_cache_delete():
    """캐시 항목 삭제"""
    data   = request.get_json(silent=True) or {}
    domain = data.get('domain', '')
    ok     = delete_cache_entry(domain)
    return jsonify({'status': 'ok' if ok else 'not_found'})

@app.route('/dns-reputation/cache/clear', methods=['POST'])
def dns_rep_cache_clear():
    """메모리 캐시 초기화"""
    count = clear_mem_cache()
    return jsonify({'status': 'ok', 'cleared': count})

@app.route('/dns-reputation/whitelist/reload', methods=['POST'])
def dns_rep_wl_reload():
    """DNS 화이트리스트 재로드"""
    count = reload_dns_whitelist()
    return jsonify({'status': 'ok', 'total_domains': count})



# ══════════════════════════════════════════════════════════════════════════════
# ══════════════════════════════════════════════════════════════════════════════
# Baseline Comparator v2 (SCIE 논문 평가)
# ══════════════════════════════════════════════════════════════════════════════
from baseline_comparator import (
    run_full_comparison, parse_rules_from_text,
    get_builtin_baselines, get_cached_baselines,
    list_available_rulesets, download_ruleset,
    run_evaluation, generate_json_report,
    generate_text_report, generate_csv_report,
    build_malicious_idx,
)
import threading as _bl_thread
_dl_status: dict = {}


@app.route('/baseline-compare', methods=['GET'])
def baseline_compare_page():
    return render_template('baseline_compare.html')


@app.route('/baseline-compare/run', methods=['POST'])
def baseline_compare_run():
    data            = request.get_json(silent=True) or {}
    rules_text      = data.get('rules_text', '')
    active_builtins = data.get('active_builtins', [])
    custom_bls      = data.get('custom_baselines', {})
    use_pcap        = data.get('use_pcap', False)

    from baseline_comparator import _get_demo_baselines
    cached    = get_cached_baselines()
    source    = cached if cached else _get_demo_baselines()
    baselines = {k: v for k, v in source.items()
                 if not active_builtins or k in active_builtins}
    for label, text in custom_bls.items():
        parsed = parse_rules_from_text(text, label)
        if parsed: baselines[label] = parsed

    pcap_path  = getattr(app, '_last_pcap_path', None) if use_pcap else None
    pcap_rules = parse_rules_from_text(rules_text, 'pcap_analyzer')
    pkts = None
    if pcap_path:
        try:
            from scapy.all import rdpcap
            pkts = list(rdpcap(str(pcap_path)))
        except Exception: pkts = None

    mal_idx  = build_malicious_idx(pcap_rules, pkts) if pkts else None
    results  = run_evaluation(pcap_rules, baselines, pkts, mal_idx)
    json_rep = generate_json_report(results)
    json_rep['text_report'] = generate_text_report(results)
    json_rep['csv_report']  = generate_csv_report(results)
    return jsonify(json_rep)


@app.route('/baseline-compare/session-rules', methods=['GET'])
def baseline_compare_session_rules():
    rules = getattr(app, '_last_generated_rules', [])
    return jsonify({'rules': rules, 'count': len(rules)})


@app.route('/baseline-compare/rulesets', methods=['GET'])
def baseline_compare_rulesets():
    import importlib, baseline_comparator as _bc
    importlib.reload(_bc)
    from baseline_comparator import list_available_rulesets as _lar, get_cached_baselines as _gcb
    cached = list(_gcb().keys())
    return jsonify({'available': _lar(), 'cached': cached})


@app.route('/baseline-compare/download', methods=['POST'])
def baseline_compare_download():
    data  = request.get_json(silent=True) or {}
    url   = data.get('url', '')
    label = data.get('label', url.split('/')[-1])
    if not url: return jsonify({'status': 'error', 'msg': 'url 필수'})
    from pathlib import Path as _P
    save_to = _P(__file__).parent / 'baselines' / f"{label.replace('/','_')}.rules"
    fallback_url = data.get('fallback_url', None)
    def _dl():
        _dl_status[label] = {'status': 'downloading', 'done': 0, 'total': 0}
        def cb(d, t): _dl_status[label].update({'done': d, 'total': t})
        rules, msg = download_ruleset(url, label, save_to, cb, fallback_url=fallback_url)
        _dl_status[label] = {'status': 'done' if rules else 'error',
                              'msg': msg, 'count': len(rules)}
    _bl_thread.Thread(target=_dl, daemon=True).start()
    return jsonify({'status': 'started', 'label': label})


@app.route('/baseline-compare/download/status', methods=['GET'])
def baseline_compare_dl_status():
    return jsonify(_dl_status)


if __name__ == '__main__':
    print("=" * 60)
    print("PCAP Analyzer — Protocol-Aware Single-file Version")
    print("Protocols: HTTP | DNS | FTP | Telnet | SMTP | ICMP")
    print("Keyword Manager : http://127.0.0.1:5000/keywords")
    print("Whitelist       : http://127.0.0.1:5000/whitelist")
    print("Noise Filter    : http://127.0.0.1:5000/noise-filter")
    print("DNS Reputation  : http://127.0.0.1:5000/dns-reputation")
    print("Auto Learn      : http://127.0.0.1:5000/auto-learn")
    print("AI Settings     : http://127.0.0.1:5000/ai-settings")
    print("=" * 60)
    app.run(debug=True, host='127.0.0.1', port=5000)
