#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import csv
from pathlib import Path
from typing import Dict, List

from scapy.all import rdpcap  # type: ignore

import keyword_rule_engine as kw_engine
from auto_learn_engine import run_auto_learn
from protocol_rule_engine import generate_rules_for_packet
from baseline_comparator import (
    parse_rules_from_text,
    run_evaluation,
    get_cached_baselines,
)


def extract_payload(packet):
    try:
        from scapy.all import Raw, DNS, UDP, TCP  # type: ignore
        if Raw in packet:
            return bytes(packet[Raw].load)
        if DNS in packet:
            return bytes(packet[DNS])
        if UDP in packet and packet[UDP].payload:
            return bytes(packet[UDP].payload)
        if TCP in packet and packet[TCP].payload:
            return bytes(packet[TCP].payload)
    except Exception:
        pass
    return b""


def generate_pcapaide_rules_and_payload_info(packets):
    rules: List[str] = []
    payload_info: List[dict] = []
    rule_id = 1000001

    for i, pkt in enumerate(packets):
        payload = extract_payload(pkt)
        if not payload:
            continue

        frame_no = i + 1
        result = generate_rules_for_packet(pkt, payload, rule_id, frame_no)
        rule_id = result.get("next_rule_id", rule_id)
        rules.extend(result.get("rules", []))

        payload_info.append(
            {
                "packet_num": frame_no,
                "frame_no": frame_no,
                "length": len(payload),
                "protocol": result.get("protocol", "OTHER"),
                "full_hex": " ".join(f"{b:02x}" for b in payload),
                "kw_detected": result.get("kw_detected", False),
                "wl_matched": result.get("wl_matched", False),
                "skipped_reason": result.get("skipped_reason", None),
            }
        )

    return dedup_rules(rules), payload_info


def dedup_rules(rules: List[str]) -> List[str]:
    seen = set()
    out = []
    for r in rules:
        if r not in seen:
            seen.add(r)
            out.append(r)
    return out


def pick_et_like_baselines(cached: Dict[str, list]) -> Dict[str, list]:
    """
    캐시된 룰셋 중 Snort/Suricata/ET 관련 라벨을 우선 선택.
    없으면 전체 캐시를 사용.
    """
    picked = {}
    for label, rules in cached.items():
        l = label.lower()
        if any(k in l for k in ["snort", "suricata", "et_", "et-open", "et open", "emerging"]):
            picked[label] = rules
    return picked if picked else cached


def write_result_csv(results: Dict[str, object], out_csv: Path):
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(
            [
                "method",
                "rule_count",
                "alert_count",
                "precision",
                "recall",
                "f1",
                "fpr",
                "tp",
                "fp",
                "tn",
                "fn",
                "specificity",
            ]
        )
        for label, r in results.items():
            w.writerow(
                [
                    label,
                    getattr(r, "rule_count", 0),
                    getattr(r, "alert_count", 0),
                    getattr(r, "precision", 0.0),
                    getattr(r, "recall", 0.0),
                    getattr(r, "f1", 0.0),
                    getattr(r, "fpr", 0.0),
                    getattr(r, "tp", 0),
                    getattr(r, "fp", 0),
                    getattr(r, "tn", 0),
                    getattr(r, "fn", 0),
                    getattr(r, "specificity", 0.0),
                ]
            )


def main():
    ap = argparse.ArgumentParser(description="Paper1: Auto Learning vs ET baselines")
    ap.add_argument("--pcap", required=True, help="e.g. ./pcap_data/Thursday.pcap")
    ap.add_argument("--out", default="./results/paper1_result.csv")
    ap.add_argument(
        "--disable-auto-learn",
        action="store_true",
        help="Auto Learning 실행 없이 현재 키워드 상태로만 평가",
    )
    args = ap.parse_args()

    pcap_path = Path(args.pcap)
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP not found: {pcap_path}")

    packets = list(rdpcap(str(pcap_path)))
    print(f"[INFO] packets={len(packets)}")

    # 1-pass: 현재 상태 룰 생성 + payload_info 수집
    _, payload_info = generate_pcapaide_rules_and_payload_info(packets)

    # Auto Learning 수행 (keywords.yaml 갱신 가능)
    if not args.disable_auto_learn:
        learn_res = run_auto_learn(payload_info)
        print(f"[AutoLearn] {learn_res}")

        # 키워드 로더 재로드
        kw_engine.reload_keywords()

    # 2-pass: 업데이트된 키워드 기준으로 최종 룰 생성
    pcapaide_rules, _ = generate_pcapaide_rules_and_payload_info(packets)
    pcapaide_parsed = parse_rules_from_text("\n".join(pcapaide_rules), "PCAP-AIDE-AutoLearn")

    cached = get_cached_baselines()
    if not cached:
        raise RuntimeError(
            "No baseline rules found in ./baselines.\n"
            "먼저 baseline_compare 기능으로 ET 룰을 받아두거나 baselines 폴더를 채워주세요."
        )

    baselines = pick_et_like_baselines(cached)
    print(f"[INFO] selected_baselines={list(baselines.keys())}")

    results = run_evaluation(pcapaide_parsed, baselines, packets)
    write_result_csv(results, Path(args.out))
    print(f"[DONE] wrote: {args.out}")


if __name__ == "__main__":
    main()