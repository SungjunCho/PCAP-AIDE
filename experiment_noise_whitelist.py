"""
experiment_noise_whitelist.py
==============================
논문: "화이트리스트 및 Noise Filter를 결합한 IDS 오탐지율 감소 기법 연구"
PCAP-AIDE 기반 Web Attack·Botnet 실증 분석

실행 전 준비:
  1. pip install -r requirements.txt
  2. ./pcap_data/ 에 Thursday.pcap, Friday.pcap 준비

실행:
  python experiment_noise_whitelist.py

결과: ./experiment_results/ 폴더에 CSV + TXT 리포트 저장
"""

import sys
import json
import time
import csv
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from scapy.all import rdpcap, Raw, DNS, UDP, TCP
# ── 실제 API (클래스 없음, 함수형) ──────────────────────────────────────────
from noise_filter_engine import is_noise          # is_noise(payload, protocol) -> dict
from whitelist_engine    import check_global_whitelist  # check_global_whitelist(payload, protocol) -> dict
from protocol_rule_engine import generate_rules_for_packet
from baseline_comparator import (
    parse_rules_from_text,
    run_evaluation,
    build_malicious_idx,
    get_cached_baselines,
    load_or_download_et,
    generate_text_report,
    generate_csv_report,
    _get_demo_baselines,
)

OUTPUT_DIR = Path("./experiment_results")
OUTPUT_DIR.mkdir(exist_ok=True)

PCAP_DIR = Path("./pcap_data")

EXPERIMENTS = [
    {"attack_type": "Web Attack", "pcap": "Thursday.pcap"},
    {"attack_type": "Botnet",     "pcap": "Friday.pcap"},
]

# Entropy threshold 감도 분석용 (논문 표 2)
# 실제 구현은 Irregularity Score 임계값 (Shannon Entropy 아님)
IRREGULARITY_THRESHOLDS = [10, 13, 16, 19, 22, 25]   # noise_filter.yaml value 값에 대응


# ──────────────────────────────────────────────────────────────────────────────
# 유틸: payload 추출
# ──────────────────────────────────────────────────────────────────────────────

def extract_payload(pkt) -> bytes:
    if Raw in pkt:   return bytes(pkt[Raw].load)
    if DNS in pkt:   return bytes(pkt[DNS])
    if UDP in pkt:
        try: return bytes(pkt[UDP].payload)
        except Exception: pass
    if TCP in pkt:
        try: return bytes(pkt[TCP].payload)
        except Exception: pass
    return b""


def detect_protocol_simple(pkt) -> str:
    """scapy 패킷에서 프로토콜 간단 판별"""
    if DNS in pkt or (UDP in pkt and (pkt[UDP].dport == 53 or pkt[UDP].sport == 53)):
        return "DNS"
    if TCP in pkt:
        port = pkt[TCP].dport
        if port in (80, 8080, 8000): return "HTTP"
        if port == 21:               return "FTP"
        if port == 23:               return "TELNET"
        if port == 25:               return "SMTP"
    return "OTHER"


# ──────────────────────────────────────────────────────────────────────────────
# Case 처리 함수
# ──────────────────────────────────────────────────────────────────────────────

def filter_noise_only(packets: list, threshold: int = 19) -> list:
    """
    Noise Filter만 적용.
    실제 구현: irregularity_score 기반 (논문의 Shannon Entropy 아님)
    threshold = noise_filter.yaml 의 irregularity_score value
    """
    from noise_filter_engine import _check_irregularity_score

    filtered = []
    for pkt in packets:
        payload  = extract_payload(pkt)
        proto    = detect_protocol_simple(pkt)
        if not payload:
            filtered.append(pkt)
            continue
        result = is_noise(payload, proto)
        if not result["noise"]:
            filtered.append(pkt)
    return filtered


def filter_whitelist_only(packets: list) -> list:
    """Whitelist만 적용 (check_global_whitelist)"""
    filtered = []
    for pkt in packets:
        payload = extract_payload(pkt)
        proto   = detect_protocol_simple(pkt)
        if not payload:
            filtered.append(pkt)
            continue
        wl = check_global_whitelist(payload, proto)
        if not wl["matched"]:
            filtered.append(pkt)
    return filtered


def filter_noise_then_whitelist(packets: list, threshold: int = 19) -> list:
    """Noise → Whitelist 순서 (논문 제안 기법)"""
    after_noise = filter_noise_only(packets, threshold)
    return filter_whitelist_only(after_noise)


def filter_whitelist_then_noise(packets: list, threshold: int = 19) -> list:
    """Whitelist → Noise 순서 (비교용)"""
    after_wl = filter_whitelist_only(packets)
    return filter_noise_only(after_wl, threshold)


# ──────────────────────────────────────────────────────────────────────────────
# 룰 생성 및 평가
# ──────────────────────────────────────────────────────────────────────────────

def generate_rules(packets: list) -> str:
    """패킷 리스트에서 Snort 룰 생성"""
    rules    = []
    rule_id  = 1000001
    for i, pkt in enumerate(packets):
        payload = extract_payload(pkt)
        if not payload: continue
        result  = generate_rules_for_packet(pkt, payload, rule_id, i + 1)
        rules.extend(result.get("rules", []))
        rule_id = result.get("next_rule_id", rule_id + 1)
    return "\n".join(rules)


def evaluate_case(
    label:      str,
    packets:    list,          # 필터 적용 후 패킷
    all_pkts:   list,          # 전체 원본 패킷 (ground-truth용)
    baselines:  dict,
    pcap_rules_text: str,
) -> dict:
    """단일 케이스 평가 → 지표 dict 반환"""
    pcap_rules = parse_rules_from_text(pcap_rules_text, "pcap_aide")
    if not pcap_rules:
        return {"label": label, "error": "생성된 룰 없음"}

    mal_idx = build_malicious_idx(pcap_rules, all_pkts)
    results = run_evaluation(pcap_rules, baselines, packets, mal_idx)

    r = results.get("PCAP-Analyzer", next(iter(results.values())))
    return {
        "label":       label,
        "packets":     len(packets),
        "rule_count":  len(pcap_rules),
        "alerts":      r.alert_count,
        "tp":          r.tp,
        "fp":          r.fp,
        "fn":          r.fn,
        "tn":          r.tn,
        "precision":   round(r.precision, 3),
        "recall":      round(r.recall,    3),
        "f1":          round(r.f1,        3),
        "fpr":         round(r.fpr,       3),
    }


# ──────────────────────────────────────────────────────────────────────────────
# Ablation Study (논문 표 1)
# ──────────────────────────────────────────────────────────────────────────────

def run_ablation_study(all_pkts: list, baselines: dict, attack_type: str) -> list:
    """
    Case 1~5 Ablation Study 실행.
    실제 API:
      - NoiseFilterEngine.filter()  → filter_noise_only()
      - WhitelistEngine.apply()     → filter_whitelist_only()
    """
    print(f"\n  [Ablation Study] {attack_type}")
    rows = []
    t0   = time.time()

    cases = [
        ("Case1_Baseline",        all_pkts),
        ("Case2_NoiseOnly",       filter_noise_only(all_pkts)),
        ("Case3_WhitelistOnly",   filter_whitelist_only(all_pkts)),
        ("Case4_Noise→Whitelist", filter_noise_then_whitelist(all_pkts)),
        ("Case5_Whitelist→Noise", filter_whitelist_then_noise(all_pkts)),
    ]

    base_alerts = None
    for label, pkts in cases:
        t_case = time.time()
        rules_text = generate_rules(pkts)
        metrics    = evaluate_case(label, pkts, all_pkts, baselines, rules_text)
        elapsed    = round(time.time() - t_case, 2)

        if base_alerts is None:
            base_alerts = metrics.get("alerts", 1)

        alert_reduction = (
            round((base_alerts - metrics.get("alerts", 0)) / max(base_alerts, 1) * 100, 1)
            if base_alerts else 0
        )
        metrics["alert_reduction_pct"] = alert_reduction
        metrics["elapsed_s"]           = elapsed
        metrics["attack_type"]         = attack_type
        rows.append(metrics)

        print(f"    {label:<30} packets={len(pkts):>6}  "
              f"P={metrics.get('precision','—'):.3f}  "
              f"R={metrics.get('recall','—'):.3f}  "
              f"F1={metrics.get('f1','—'):.3f}  "
              f"FPR={metrics.get('fpr','—'):.3f}  "
              f"Alert감소={alert_reduction:.1f}%")

    print(f"  [*] Ablation Study 완료: {round(time.time()-t0, 1)}s")
    return rows


# ──────────────────────────────────────────────────────────────────────────────
# Threshold Sensitivity (논문 표 2)
# 실제 구현: Shannon Entropy 임계값이 아닌 Irregularity Score 임계값
# ──────────────────────────────────────────────────────────────────────────────

def run_threshold_sensitivity(all_pkts: list, baselines: dict, attack_type: str) -> list:
    """
    Irregularity Score threshold 변화에 따른 성능 변화.
    논문은 Shannon Entropy threshold [3.5~5.5]로 기술했으나
    실제 구현은 Irregularity Score threshold [10~25] 임.
    """
    print(f"\n  [Threshold Sensitivity] {attack_type}")
    rows = []

    for thr in IRREGULARITY_THRESHOLDS:
        pkts       = filter_noise_only(all_pkts, threshold=thr)
        rules_text = generate_rules(pkts)
        metrics    = evaluate_case(f"Thr={thr}", pkts, all_pkts, baselines, rules_text)
        metrics["threshold"]   = thr
        metrics["attack_type"] = attack_type
        rows.append(metrics)
        print(f"    threshold={thr:<3}  packets={len(pkts):>6}  "
              f"P={metrics.get('precision','—'):.3f}  "
              f"R={metrics.get('recall','—'):.3f}  "
              f"FPR={metrics.get('fpr','—'):.3f}")

    return rows


# ──────────────────────────────────────────────────────────────────────────────
# Processing Time 측정 (논문 Processing Time 항목)
# ──────────────────────────────────────────────────────────────────────────────

def measure_processing_time(packets: list, sample: int = 1000) -> dict:
    """ms/packet 및 packets/sec 측정"""
    sample_pkts = packets[:sample]

    # Baseline (필터 없음)
    t0 = time.perf_counter()
    for pkt in sample_pkts:
        _ = extract_payload(pkt)
    t_base = (time.perf_counter() - t0) / len(sample_pkts) * 1000

    # Proposed (Noise → Whitelist)
    t0 = time.perf_counter()
    for pkt in sample_pkts:
        payload = extract_payload(pkt)
        proto   = detect_protocol_simple(pkt)
        if payload:
            is_noise(payload, proto)
            check_global_whitelist(payload, proto)
    t_prop = (time.perf_counter() - t0) / len(sample_pkts) * 1000

    return {
        "baseline_ms_per_pkt":  round(t_base, 3),
        "proposed_ms_per_pkt":  round(t_prop, 3),
        "baseline_pkt_per_sec": round(1000 / max(t_base, 0.001)),
        "proposed_pkt_per_sec": round(1000 / max(t_prop, 0.001)),
    }


# ──────────────────────────────────────────────────────────────────────────────
# 결과 저장
# ──────────────────────────────────────────────────────────────────────────────

def save_csv(rows: list, filename: str):
    if not rows: return
    path = OUTPUT_DIR / filename
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    print(f"  [*] CSV 저장: {path}")


# ──────────────────────────────────────────────────────────────────────────────
# 메인
# ──────────────────────────────────────────────────────────────────────────────

def main():
    print("=" * 70)
    print("  PCAP-AIDE 실험: Noise Filter + Whitelist FPR 감소 검증")
    print("  (논문 재현 스크립트 — 실제 API 기반)")
    print("=" * 70)

    # 베이스라인 로드
    print("\n[1] 베이스라인 룰셋 로드")
    baselines = get_cached_baselines()
    if not baselines:
        print("  캐시 없음 — ET Open 다운로드 시도")
        for cat in ["emerging-web_client", "emerging-malware", "emerging-trojan"]:
            rules, msg = load_or_download_et(cat, engine="snort")
            if rules:
                baselines[f"ET_{cat}"] = rules
                print(f"  ✅ {cat}: {len(rules)}개")
    if not baselines:
        print("  ET 다운로드 실패 — 데모 베이스라인 사용")
        baselines = _get_demo_baselines()

    all_ablation   = []
    all_threshold  = []
    all_timing     = []

    for exp in EXPERIMENTS:
        attack_type = exp["attack_type"]
        pcap_file   = PCAP_DIR / exp["pcap"]

        print(f"\n{'='*50}")
        print(f"[실험] {attack_type} — {pcap_file.name}")
        print(f"{'='*50}")

        if not pcap_file.exists():
            print(f"  [!] 파일 없음: {pcap_file} — 건너뜀")
            continue

        print("  PCAP 로드 중...")
        all_pkts = list(rdpcap(str(pcap_file)))[:5000]
        print(f"  패킷 수: {len(all_pkts)}")

        # Ablation Study
        abl_rows = run_ablation_study(all_pkts, baselines, attack_type)
        all_ablation.extend(abl_rows)

        # Threshold Sensitivity
        thr_rows = run_threshold_sensitivity(all_pkts, baselines, attack_type)
        all_threshold.extend(thr_rows)

        # Processing Time
        timing = measure_processing_time(all_pkts)
        timing["attack_type"] = attack_type
        all_timing.append(timing)
        print(f"\n  Processing Time:")
        print(f"    Baseline : {timing['baseline_ms_per_pkt']} ms/pkt  "
              f"({timing['baseline_pkt_per_sec']} pkt/s)")
        print(f"    Proposed : {timing['proposed_ms_per_pkt']} ms/pkt  "
              f"({timing['proposed_pkt_per_sec']} pkt/s)")

    # 결과 저장
    print("\n[결과 저장]")
    save_csv(all_ablation,  "ablation_study_results.csv")
    save_csv(all_threshold, "threshold_sensitivity_results.csv")
    save_csv(all_timing,    "processing_time_results.csv")

    # 최종 요약 출력
    print("\n" + "=" * 70)
    print("  Ablation Study 요약 (논문 표 1 기준)")
    print("=" * 70)
    print(f"  {'Case':<30} {'P':>6} {'R':>6} {'F1':>6} {'FPR':>6} {'Alert감소':>10}")
    print("  " + "-" * 62)
    for row in all_ablation:
        if row.get("attack_type") != all_ablation[0].get("attack_type"):
            continue  # 첫 번째 PCAP만 요약 출력
        print(f"  {row.get('label',''):<30} "
              f"{row.get('precision',0):>6.3f} "
              f"{row.get('recall',0):>6.3f} "
              f"{row.get('f1',0):>6.3f} "
              f"{row.get('fpr',0):>6.3f} "
              f"{row.get('alert_reduction_pct',0):>9.1f}%")

    print("\n실험 완료.")
    print(f"결과 폴더: {OUTPUT_DIR.resolve()}")


if __name__ == "__main__":
    main()
