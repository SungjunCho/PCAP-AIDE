from flask import Flask, render_template, request, jsonify, send_file
from scapy.all import rdpcap, Raw, IP, TCP, UDP, ICMP, DNS
from protocol_rule_engine import generate_rules_for_packet
from keyword_rule_engine import (detect_and_build_rules as _kw_detect,
                                  get_keywords_summary, get_keywords_file_path,
                                  get_keywords_file_mtime, reload_keywords)
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
from auto_learn_engine import (run_auto_learn, get_learn_log,
                                get_auto_categories, delete_keyword, get_stats,
                                reload_ai_config, save_ai_config, get_providers_status)
import tempfile
import os
import zipfile
import io
import time
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500 MB

# ─────────────────────────────────────────────
# 템플릿 선택
# ─────────────────────────────────────────────

def get_template_name():
    templates_dir = os.path.join(app.root_path, 'templates')
    for name in ('multi_upload.html', 'index.html'):
        if os.path.exists(os.path.join(templates_dir, name)):
            print(f"📄 Using template: {name}")
            return name
    print("❌ No template found!")
    return None


# ─────────────────────────────────────────────
# 유틸
# ─────────────────────────────────────────────

def _extract_payload(packet) -> bytes | None:
    """
    scapy 패킷에서 애플리케이션 레이어 payload 추출.
    Raw 레이어가 없는 DNS·ICMP 패킷도 포함한다.
    """
    if Raw in packet:
        data = bytes(packet[Raw].load)
        if data: return data
    if DNS in packet:
        try:
            data = bytes(packet[DNS])
            if data: return data
        except Exception: pass
    if UDP in packet:
        try:
            pl = packet[UDP].payload
            if pl and pl.name != 'NoPayload':
                data = bytes(pl)
                if data: return data
        except Exception: pass
    if ICMP in packet:
        try:
            pl = packet[ICMP].payload
            if pl and pl.name != 'NoPayload':
                data = bytes(pl)
                if data: return data
        except Exception: pass
    return None


def format_hex_dump(data, bytes_per_row=16):
    rows = []
    for i in range(0, len(data), bytes_per_row):
        chunk = data[i:i + bytes_per_row]
        rows.append({
            'offset': f"{i:08x}",
            'hex':    ' '.join(f"{b:02x}" for b in chunk).ljust(bytes_per_row * 3 - 1),
            'ascii':  ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk),
        })
    return rows


PROTOCOL_COLORS = {
    "HTTP":   "#3498db",
    "DNS":    "#9b59b6",
    "FTP":    "#e67e22",
    "TELNET": "#e74c3c",
    "SMTP":   "#2ecc71",
    "OTHER":  "#95a5a6",
}

PATTERN_EMOJI = {
    "LOG4J_INJECTION":          "🚨 LOG4J SHELL ATTACK",
    "PATH_TRAVERSAL":           "⚠️ Path Traversal",
    "XSS":                      "⚠️ XSS Attempt",
    "SQL_INJECTION":            "🚨 SQL Injection",
    "SENSITIVE_PATH":           "⚠️ Sensitive Path",
    "COMMAND_EXECUTION":        "🚨 Command Execution",
    "DNS_TUNNELING":            "🚨 DNS Tunneling",
    "SUSPICIOUS_DOMAIN":        "⚠️ Suspicious Domain",
    "MALICIOUS_DOMAIN":         "🚨 DNS — Known Malicious Domain (VirusTotal)",
    "SUSPICIOUS_DOMAIN_VT":     "⚠️ DNS — Suspicious Domain (VirusTotal)",
    "PRIVILEGED_LOGIN_ATTEMPT": "🚨 FTP Privileged Login",
    "FTP_PASSWORD_TRANSMITTED": "⚠️ FTP Cleartext Password",
    "EXECUTABLE_TRANSFER":      "🚨 FTP Executable Transfer",
    "CREDENTIAL_IN_CLEARTEXT":  "🚨 Telnet Cleartext Creds",
    "DANGEROUS_COMMAND":        "🚨 Telnet Dangerous Cmd",
    "REVERSE_SHELL":            "🚨 Reverse Shell",
    "SMTP_AUTH_FAILURE":        "⚠️ SMTP Auth Failure",
    "PHISHING_CONTENT":         "🚨 Phishing Email",
    "SPAM_MAILER":              "⚠️ Spam Mailer",
    "SUSPICIOUS_UA":            "🕵️ Suspicious User-Agent",
}


# ─────────────────────────────────────────────
# 단일 PCAP 분석
# ─────────────────────────────────────────────

def _content_key(rule: str) -> str:
    """프로토콜 + 정렬된 content 값 목록 → 중복 판별 키"""
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
    """content 기반 중복 제거 — msg/sid/포트 달라도 content 같으면 중복 처리"""
    unique = []
    for rule in new_rules:
        key = _content_key(rule.split('\n')[-1].strip())
        if key and key not in seen_content_keys:
            seen_content_keys.add(key)
            unique.append(rule)
    return unique


def _merge_same_content_rules(rules: list) -> list:
    """content 동일 룰들을 최고 심각도 msg 로 병합, sid는 최초 번호 유지"""
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
            best_body = re.sub(r'(sid:\d+)', r'nocase; \1', best_body)
        first_lines   = grp[0].split('\n')
        frame_comment = first_lines[0] if len(first_lines) > 1 else ''
        final = f"{frame_comment}\n{best_body}" if frame_comment else best_body
        merged.append(final)
    return merged



def analyze_single_pcap(file_path, filename):
    try:
        from collections import Counter
        packets = rdpcap(file_path)
        rules            = []
        payload_info     = []
        seen_payloads    = set()
        seen_rule_bodies = set()   # content 기반 중복 제거용
        rule_id          = 1000001
        proto_stats      = {"HTTP": 0, "DNS": 0, "FTP": 0, "TELNET": 0, "SMTP": 0, "ICMP": 0, "OTHER": 0}

        # ── 트래픽 집계 구조 ──────────────────────────────────────────────
        traffic_raw: dict = {}
        _all_ips_counter: Counter = Counter()

        def _get_ips(pkt):
            try:
                if IP in pkt:
                    return pkt[IP].src, pkt[IP].dst
            except Exception:
                pass
            return None, None

        print(f"Analyzing {filename}: {len(packets)} packets")

        for i, packet in enumerate(packets):
            payload = _extract_payload(packet)
            if payload is None or not payload:
                continue

            frame_no  = i + 1
            result    = generate_rules_for_packet(packet, payload, rule_id, frame_no)
            protocol  = result["protocol"]
            app_info  = result["app_info"]
            patterns  = result["suspicious_patterns"]
            new_rules = result["rules"]
            rule_id   = result["next_rule_id"]
            kw_detected   = result.get("kw_detected", False)
            kw_keywords   = result.get("kw_matched_keywords", [])
            kw_categories = result.get("kw_matched_categories", [])
            kw_sev        = result.get("kw_severity_max", "LOW")
            kw_rules      = result.get("kw_rules", [])
            skipped_reason  = result.get("skipped_reason", None)
            wl_matched = result.get("wl_matched", False)
            wl_reason  = result.get("wl_reason", "")

            payload_key = payload[:64]
            if payload_key not in seen_payloads:
                seen_payloads.add(payload_key)
            unique_rules = _dedup_rules(new_rules, seen_rule_bodies)
            rules.extend(unique_rules)
            proto_stats[protocol] = proto_stats.get(protocol, 0) + len(unique_rules)

            # ── 트래픽 집계 ───────────────────────────────────────────────
            src_ip, dst_ip = _get_ips(packet)
            if src_ip: _all_ips_counter[src_ip] += 1
            if dst_ip: _all_ips_counter[dst_ip] += 1
            if protocol not in traffic_raw:
                traffic_raw[protocol] = {"frames": [], "total_bytes": 0}
            traffic_raw[protocol]["frames"].append({
                "frame_no": frame_no,
                "src": src_ip or "?",
                "dst": dst_ip or "?",
                "bytes": len(payload),
            })
            traffic_raw[protocol]["total_bytes"] += len(payload)

            # ── 표시용 패턴 목록 ──────────────────────────────────────────
            display_patterns = [PATTERN_EMOJI.get(p, f"⚠️ {p}") for p in patterns]

            if protocol == "HTTP" and app_info.get("method"):
                display_patterns.append(
                    f"🌐 HTTP {app_info['method']} {app_info.get('uri','')[:40]}"
                )

            # DNS 쿼리 도메인 + reputation + typosquatting 표시
            if protocol == "DNS" and app_info.get("query_name"):
                qname = app_info["query_name"]
                rep   = app_info.get("dns_reputation") or {}
                verdict = rep.get("verdict", "UNKNOWN")
                typo  = app_info.get("typosquatting") or {}

                if typo:
                    sev_emoji = {"CRITICAL":"🚨","HIGH":"⚠️","MEDIUM":"⚠️"}.get(typo.get("severity",""), "⚠️")
                    display_patterns.insert(0,
                        f"{sev_emoji} DNS Typosquatting: {qname} — {typo.get('reason','')}")
                else:
                    verdict_emoji = {"MALICIOUS":"🚨","SUSPICIOUS":"⚠️",
                                     "SAFE":"✅","UNKNOWN":"🔍"}.get(verdict, "🔍")
                    display_patterns.insert(0,
                        f"{verdict_emoji} DNS Query: {qname}  [{verdict}]")

            # dns_rep 별도 추출
            dns_rep = app_info.get("dns_reputation") if protocol == "DNS" else None

            payload_str     = payload.decode("utf-8", errors="ignore")
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
                'packet_num':        i + 1,
                'frame_no':          i + 1,
                'length':            len(payload),
                'protocol':          protocol,
                'protocol_color':    PROTOCOL_COLORS.get(protocol, "#95a5a6"),
                'full_hex':          ' '.join(f"{b:02x}" for b in payload),
                'hex_rows':          format_hex_dump(payload),
                'full_ascii':        ''.join(chr(b) if 32 <= b <= 126 else '.' for b in payload),
                'payload':           payload_str[:500] + ('...' if len(payload_str) > 500 else ''),
                'patterns':          display_patterns,
                'has_pattern':       len(display_patterns) > 0 or (
                                         dns_rep is not None and
                                         dns_rep.get('verdict') in ('MALICIOUS','SUSPICIOUS')),
                'printable_percent': printable_pct,
                'null_count':        null_count,
                'ascii_range':       ascii_range,
                'generated_rules':   new_rules,
                'skipped_reason':    skipped_reason,
                'wl_matched':        wl_matched,
                'wl_reason':         wl_reason,
                'kw_detected':       kw_detected,
                'kw_keywords':       kw_keywords,
                'kw_categories':     kw_categories,
                'kw_severity':       kw_sev,
                'kw_rules':          kw_rules,
                'app_info':          {k: v for k, v in app_info.items()
                                      if k != "suspicious_patterns"},
                'dns_rep':           dns_rep,
            })

        # ── False Positive 점수 ───────────────────────────────────────────
        if rules:
            critical = sum(1 for r in rules if "CRITICAL" in r)
            high     = sum(1 for r in rules if "HIGH" in r)
            generic  = sum(1 for r in rules if "Generic" in r)
            fp_score = max(0, min(100,
                50 - critical * 15 - high * 8 + (generic / max(len(rules), 1)) * 30
            ))
        else:
            fp_score = 0

        # ── content 기반 최종 룰 병합 ────────────────────────────────────
        rules = _merge_same_content_rules(rules)

        # ── 트래픽 요약 계산 ──────────────────────────────────────────────
        local_ip = _all_ips_counter.most_common(1)[0][0] if _all_ips_counter else None
        total_frames = sum(len(v["frames"]) for v in traffic_raw.values())
        total_bytes  = sum(v["total_bytes"]   for v in traffic_raw.values())

        traffic_summary: list[dict] = []
        for proto in ["HTTP","DNS","FTP","TELNET","SMTP","ICMP","OTHER"]:
            data   = traffic_raw.get(proto, {"frames": [], "total_bytes": 0})
            frames = data["frames"]
            tx = sum(1 for f in frames if f["src"] == local_ip) if local_ip else len(frames)//2
            rx = sum(1 for f in frames if f["dst"] == local_ip) if local_ip else len(frames)-len(frames)//2
            other_dir = len(frames) - tx - rx
            pct   = round(len(frames) / max(total_frames, 1) * 100, 1)
            bpct  = round(data["total_bytes"] / max(total_bytes, 1) * 100, 1)
            traffic_summary.append({
                "proto":      proto,
                "total":      len(frames),
                "tx":         tx,
                "rx":         rx,
                "other":      other_dir,
                "bytes":      data["total_bytes"],
                "pct_frames": pct,
                "pct_bytes":  bpct,
            })

        traffic_total = {
            "proto":    "TOTAL",
            "total":    total_frames,
            "tx":       sum(t["tx"] for t in traffic_summary),
            "rx":       sum(t["rx"] for t in traffic_summary),
            "bytes":    total_bytes,
            "pct_frames": 100.0,
            "pct_bytes":  100.0,
            "local_ip": local_ip or "N/A",
        }

        # ── 자동학습 ──────────────────────────────────────────────────────
        learn_result = run_auto_learn(payload_info)
        if learn_result.get('added', 0) > 0:
            print(f"[AutoLearn] {filename}: +{learn_result['added']} 키워드 추가됨")

        return {
            'filename':             filename,
            'success':              True,
            'packet_count':         len(packets),
            'payload_count':        len(payload_info),
            'rules':                rules,          # 전체 룰 반환 (이전 :50 제한 제거)
            'rule_count':           len(rules),
            'payload_info':         payload_info,   # 전체 페이로드 반환 (이전 :30 제한 제거)
            'false_positive_score': round(fp_score, 2),
            'has_patterns':         any(p['has_pattern'] for p in payload_info),
            'proto_stats':          proto_stats,
            'traffic_summary':      traffic_summary,
            'traffic_total':        traffic_total,
            'learn_result':         learn_result,
        }

    except Exception as e:
        return {'filename': filename, 'success': False, 'error': str(e)}


# ─────────────────────────────────────────────
# Flask 라우트
# ─────────────────────────────────────────────

@app.route('/', methods=['GET'])
def index():
    template_name = get_template_name()
    if template_name is None:
        return "Error: No template found.", 500
    return render_template(template_name)


@app.route('/analyze', methods=['POST'])
def analyze_files():
    if 'pcap_files' not in request.files:
        return jsonify({'error': 'No files uploaded'}), 400

    files = request.files.getlist('pcap_files')
    if not files or files[0].filename == '':
        return jsonify({'error': 'No files selected'}), 400

    def is_pcap(filename):
        """대소문자 무관하게 .pcap / .pcapng 확장자 허용"""
        return filename.lower().endswith('.pcap') or filename.lower().endswith('.pcapng')

    results    = []
    start_time = time.time()

    for file in files:
        if not file or not file.filename:
            continue
        if not is_pcap(file.filename):
            results.append({
                'filename': file.filename,
                'success':  False,
                'error':    f'Unsupported file type: {file.filename} (only .pcap / .pcapng allowed)',
            })
            continue

        # secure_filename 이 빈 문자열을 반환할 경우 원본 이름 사용
        safe_name = secure_filename(file.filename)
        if not safe_name:
            safe_name = file.filename

        temp_fd, temp_path = tempfile.mkstemp(suffix='.pcap')
        try:
            file.save(temp_path)
            result = analyze_single_pcap(temp_path, safe_name)
            results.append(result)
        except Exception as e:
            results.append({'filename': safe_name, 'success': False, 'error': str(e)})
        finally:
            os.close(temp_fd)
            if os.path.exists(temp_path):
                os.remove(temp_path)

    total_time = round(time.time() - start_time, 2)

    if not results:
        return jsonify({'error': 'No valid PCAP files were processed. '
                                 'Only .pcap and .pcapng files are accepted (case-insensitive).'}), 400

    successful = [r for r in results if r.get('success')]

    # 프로토콜별 통계 집계
    combined_proto = {"HTTP": 0, "DNS": 0, "FTP": 0, "TELNET": 0, "SMTP": 0, "ICMP": 0, "OTHER": 0}
    for r in successful:
        for proto, cnt in r.get('proto_stats', {}).items():
            combined_proto[proto] = combined_proto.get(proto, 0) + cnt

    # 전체 파일 traffic_summary 합산
    combined_traffic: dict = {}
    for r in successful:
        for row in r.get('traffic_summary', []):
            p = row["proto"]
            if p not in combined_traffic:
                combined_traffic[p] = {"total":0,"tx":0,"rx":0,"other":0,"bytes":0}
            combined_traffic[p]["total"] += row["total"]
            combined_traffic[p]["tx"]    += row["tx"]
            combined_traffic[p]["rx"]    += row["rx"]
            combined_traffic[p]["other"] += row["other"]
            combined_traffic[p]["bytes"] += row["bytes"]

    total_frames_all = sum(v["total"] for v in combined_traffic.values())
    total_bytes_all  = sum(v["bytes"] for v in combined_traffic.values())
    combined_traffic_summary = []
    for proto in ["HTTP","DNS","FTP","TELNET","SMTP","ICMP","OTHER"]:
        d = combined_traffic.get(proto, {"total":0,"tx":0,"rx":0,"other":0,"bytes":0})
        combined_traffic_summary.append({
            "proto":      proto,
            "total":      d["total"],
            "tx":         d["tx"],
            "rx":         d["rx"],
            "other":      d["other"],
            "bytes":      d["bytes"],
            "pct_frames": round(d["total"] / max(total_frames_all, 1) * 100, 1),
            "pct_bytes":  round(d["bytes"] / max(total_bytes_all, 1) * 100, 1),
        })

    combined_traffic_total = {
        "total":    total_frames_all,
        "tx":       sum(v["tx"]    for v in combined_traffic.values()),
        "rx":       sum(v["rx"]    for v in combined_traffic.values()),
        "bytes":    total_bytes_all,
        "local_ip": "N/A (다중 파일)",
    }

    return jsonify({
        'results': results,
        'statistics': {
            'total_files':       len(results),
            'successful':        len(successful),
            'failed':            len(results) - len(successful),
            'total_rules':       sum(r.get('rule_count', 0) for r in successful),
            'total_packets':     sum(r.get('packet_count', 0) for r in successful),
            'processing_time':   total_time,
            'proto_stats':       combined_proto,
            'traffic_summary':   combined_traffic_summary,
            'traffic_total':     combined_traffic_total,
        }
    })


@app.route('/download/rules', methods=['POST'])
def download_rules():
    data    = request.get_json()
    results = data.get('results', [])

    lines = [
        "# Snort Rules Generated by PCAP Analyzer (Protocol-Aware)",
        f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        "# Protocols: HTTP, DNS, FTP, Telnet, SMTP",
        "#" + "=" * 55,
        "",
    ]

    # プロトコル別セクション出力
    for proto in ("HTTP", "DNS", "FTP", "TELNET", "SMTP", "OTHER"):
        proto_rules = []
        for r in results:
            if r.get('success'):
                for rule in r.get('rules', []):
                    # 프로토콜 포트/키워드로 분류
                    port_map = {
                        "HTTP":   ["any 80", "any 8080", "http_method", "http_uri"],
                        "DNS":    ["any 53"],
                        "FTP":    ["any 21", "any 20", "FTP"],
                        "TELNET": ["any 23", "TELNET", "|ff|"],
                        "SMTP":   ["any 25", "any 465", "any 587", "SMTP", "MAIL"],
                    }
                    markers = port_map.get(proto, [])
                    if proto == "OTHER":
                        if not any(m in rule for pm in port_map.values() for m in pm):
                            proto_rules.append(rule)
                    elif any(m in rule for m in markers):
                        proto_rules.append(rule)

        if proto_rules:
            lines.append(f"# ── {proto} Rules ({'─'*40}")
            lines.extend(proto_rules)
            lines.append("")

    mem_file = io.BytesIO()
    mem_file.write('\n'.join(lines).encode('utf-8'))
    mem_file.seek(0)

    return send_file(mem_file, mimetype='text/plain', as_attachment=True,
                     download_name=f'snort_rules_{time.strftime("%Y%m%d_%H%M%S")}.rules')


@app.route('/download/zip', methods=['POST'])
def download_zip():
    data    = request.get_json()
    results = data.get('results', [])

    mem_zip = io.BytesIO()
    with zipfile.ZipFile(mem_zip, 'w', zipfile.ZIP_DEFLATED) as zf:
        for result in results:
            if not result.get('success'):
                continue
            base = result['filename'].replace('.pcap', '').replace('.pcapng', '')

            # 룰 파일
            rule_lines = [
                f"# Snort Rules — {result['filename']}",
                f"# False Positive Score : {result['false_positive_score']}/100",
                f"# Protocol Stats       : {result.get('proto_stats', {})}",
                "#" + "=" * 50,
                "",
            ]
            rule_lines.extend(result.get('rules', []))
            zf.writestr(f'{base}_rules.rules', '\n'.join(rule_lines))

            # 요약 파일
            ps = result.get('proto_stats', {})
            summary_lines = [
                "PCAP Analysis Report",
                "=" * 40,
                f"File          : {result['filename']}",
                f"Total Packets : {result['packet_count']}",
                f"With Payload  : {result['payload_count']}",
                f"Rules Generated: {result['rule_count']}",
                f"FP Score      : {result['false_positive_score']}/100",
                f"Has Attacks   : {result['has_patterns']}",
                "",
                "Protocol Rule Breakdown:",
            ]
            for proto, cnt in ps.items():
                if cnt:
                    summary_lines.append(f"  {proto:8s}: {cnt} rules")

            summary_lines.append("\nDetected Patterns:")
            for p in result.get('payload_info', []):
                if p.get('patterns'):
                    summary_lines.append(
                        f"  Pkt #{p['packet_num']} [{p['protocol']}]: "
                        + ', '.join(p['patterns'])
                    )

            zf.writestr(f'{base}_summary.txt', '\n'.join(summary_lines))

    mem_zip.seek(0)
    return send_file(mem_zip, mimetype='application/zip', as_attachment=True,
                     download_name=f'pcap_analysis_{time.strftime("%Y%m%d_%H%M%S")}.zip')



@app.route('/keywords', methods=['GET'])
def keywords_page():
    from flask import jsonify
    summary  = get_keywords_summary()
    return render_template('keywords.html',
                           categories=summary,
                           filepath=get_keywords_file_path(),
                           mtime=get_keywords_file_mtime())

@app.route('/keywords/reload', methods=['POST'])
def keywords_reload():
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
    count = reload_whitelist()
    return jsonify({'status': 'ok', 'total_entries': count})


@app.route('/whitelist/add', methods=['POST'])
def whitelist_add():
    """페이로드 카드에서 화이트리스트 등록 API"""
    data = request.get_json(silent=True) or {}
    result = add_whitelist_entry(data)
    return jsonify(result)


@app.route('/noise-filter', methods=['GET'])
def noise_filter_page():
    return render_template('noise_filter.html',
                           rules=get_noise_filter_summary(),
                           filepath=get_noise_filter_file_path(),
                           mtime=get_noise_filter_mtime(),
                           total=get_noise_filter_total())

@app.route('/noise-filter/reload', methods=['POST'])
def noise_filter_reload():
    count = reload_noise_filter()
    return jsonify({'status': 'ok', 'total_rules': count})


# ─────────────────────────────────────────────
# DNS Reputation 관리 라우트
# ─────────────────────────────────────────────

@app.route('/dns-reputation', methods=['GET'])
def dns_reputation_page():
    return render_template('dns_reputation.html',
                           cache_stats=get_cache_stats(),
                           cache_entries=get_cache_entries(200),
                           whitelist_domains=get_whitelist_domains(),
                           vt_status=get_vt_key_status(),
                           sb_status=get_sb_key_status())

@app.route('/dns-reputation/vt-key', methods=['POST'])
def dns_rep_set_vt_key():
    data = request.get_json(silent=True) or {}
    ok   = save_vt_api_key(data.get('api_key', '').strip())
    return jsonify({'status': 'ok' if ok else 'error'})

@app.route('/dns-reputation/sb-key', methods=['POST'])
def dns_rep_set_sb_key():
    """Google Safe Browsing API 키 저장"""
    data = request.get_json(silent=True) or {}
    ok   = save_sb_api_key(data.get('api_key', '').strip())
    return jsonify({'status': 'ok' if ok else 'error'})

@app.route('/dns-reputation/cache', methods=['GET'])
def dns_rep_cache():
    return jsonify(get_cache_entries(500))

@app.route('/dns-reputation/cache/delete', methods=['POST'])
def dns_rep_cache_delete():
    data = request.get_json(silent=True) or {}
    ok   = delete_cache_entry(data.get('domain', ''))
    return jsonify({'status': 'ok' if ok else 'not_found'})

@app.route('/dns-reputation/cache/clear', methods=['POST'])
def dns_rep_cache_clear():
    count = clear_mem_cache()
    return jsonify({'status': 'ok', 'cleared': count})

@app.route('/dns-reputation/whitelist/reload', methods=['POST'])
def dns_rep_wl_reload():
    count = reload_dns_whitelist()
    return jsonify({'status': 'ok', 'total_domains': count})


# ─────────────────────────────────────────────
# 자동학습 관리 라우트
# ─────────────────────────────────────────────

@app.route('/auto-learn', methods=['GET'])
def auto_learn_page():
    return render_template('auto_learn.html',
                           stats=get_stats(),
                           auto_cats=get_auto_categories(),
                           log=get_learn_log(50))

@app.route('/auto-learn/log', methods=['GET'])
def auto_learn_log():
    return jsonify(get_learn_log(100))

@app.route('/auto-learn/delete', methods=['POST'])
def auto_learn_delete():
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
        if parsed:
            baselines[label] = parsed

    pcap_path  = getattr(app, '_last_pcap_path', None) if use_pcap else None
    pcap_rules = parse_rules_from_text(rules_text, 'pcap_analyzer')

    pkts = None
    if pcap_path:
        try:
            from scapy.all import rdpcap
            pkts = list(rdpcap(str(pcap_path)))
        except Exception:
            pkts = None

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


_dl_status: dict = {}


@app.route('/baseline-compare/download', methods=['POST'])
def baseline_compare_download():
    data  = request.get_json(silent=True) or {}
    url   = data.get('url', '')
    label = data.get('label', url.split('/')[-1])
    if not url:
        return jsonify({'status': 'error', 'msg': 'url 필수'})
    from pathlib import Path as _P
    save_to = _P(__file__).parent / 'baselines' / f"{label.replace('/','_')}.rules"

    fallback_url = data.get('fallback_url', None)
    def _dl():
        _dl_status[label] = {'status': 'downloading', 'done': 0, 'total': 0}
        def cb(done, total):
            _dl_status[label]['done']  = done
            _dl_status[label]['total'] = total
        rules, msg = download_ruleset(url, label, save_to, cb, fallback_url=fallback_url)
        _dl_status[label] = {
            'status': 'done' if rules else 'error',
            'msg': msg, 'count': len(rules),
        }
    _bl_thread.Thread(target=_dl, daemon=True).start()
    return jsonify({'status': 'started', 'label': label})


@app.route('/baseline-compare/download/status', methods=['GET'])
def baseline_compare_dl_status():
    return jsonify(_dl_status)


if __name__ == '__main__':
    print("=" * 60)
    print("PCAP Analyzer — Protocol-Aware Multi-file Version")
    print("Protocols: HTTP | DNS | FTP | Telnet | SMTP | ICMP")
    print("=" * 60)
    template_name = get_template_name()
    if template_name:
        print(f"✅ Template       : {template_name}")
    else:
        print("❌ No template found in templates/")
    print("Server            : http://127.0.0.1:5000")
    print("Keyword Manager   : http://127.0.0.1:5000/keywords")
    print("ICMP Whitelist    : http://127.0.0.1:5000/whitelist")
    print("Noise Filter      : http://127.0.0.1:5000/noise-filter")
    print("Auto Learn        : http://127.0.0.1:5000/auto-learn")
    print("AI Settings       : http://127.0.0.1:5000/ai-settings")
    print("Max upload size   : 500 MB")
    print("=" * 60)
    app.run(debug=True, host='127.0.0.1', port=5000)

