#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import csv
from contextlib import contextmanager
from pathlib import Path
from typing import Dict, List

from scapy.all import rdpcap  # type: ignore

import protocol_rule_engine as pre
from baseline_comparator import (
    parse_rules_from_text,
    simulate_alerts,
    build_malicious_idx,
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


@contextmanager
def toggle_engines(*, noise_on: bool, whitelist_on: bool):
    """
    protocol_rule_engine 내부 함수 monkey patch로
    Noise / Whitelist ON-OFF를 제어.
    """
    orig_is_noise = pre.is_noise
    orig_wl = pre.check_global_whitelist
    orig_dns_wl = pre._dns_wl_check

    try:
        if not noise_on:
            pre.is_noise = lambda payload, protocol="": {"noise": False, "reason": ""}

        if not whitelist_on:
            pre.check_global_whitelist = (
                lambda payload, protocol, icmp_type=-1, icmp_code=-1: {
                    "matched": False,
                    "reason": "whitelist disabled",
                    "entry": None,
                }
            )
            pre._dns_wl_check = lambda qname: None

        yield
    finally:
        pre.is_noise = orig_is_noise
        pre.check_global_whitelist = orig_wl
        pre._dns_wl_check = orig_dns_wl


def generate_rules_for_case(packets, case_name: str) -> List[str]:
    if case_name == "Baseline":
        noise_on, wl_on = False, False
    elif case_name == "Noise Filter only":
        noise_on, wl_on = True, False
    elif case_name == "Whitelist only":
        noise_on, wl_on = False, True
    elif case_name == "Noise -> Whitelist (Proposed)":
        noise_on, wl_on = True, True
    else:
        raise ValueError(f"Unknown case: {case_name}")

    rules: List[str] = []
    rule_id = 1000001

    with toggle_engines(noise_on=noise_on, whitelist_on=wl_on):
        for i, pkt in enumerate(packets):
            payload = extract_payload(pkt)
            if not payload:
                continue
            out = pre.generate_rules_for_packet(pkt, payload, rule_id, i + 1)
            rule_id = out.get("next_rule_id", rule_id)
            rules.extend(out.get("rules", []))

    return dedup_rules(rules)


def dedup_rules(rules: List[str]) -> List[str]:
    seen = set()
    out = []
    for r in rules:
        if r not in seen:
            seen.add(r)
            out.append(r)
    return out


def to_parsed(rule_texts: List[str], label: str):
    return parse_rules_from_text("\n".join(rule_texts), label)


def evaluate_ablation(case_rules: Dict[str, List[str]], packets):
    parsed_map = {k: to_parsed(v, k) for k, v in case_rules.items()}

    # pseudo GT: 모든 케이스 룰 합집합 기반
    union_rules = []
    for rules in parsed_map.values():
        union_rules.extend(rules)
    malicious_idx = build_malicious_idx(union_rules, packets)

    rows = []
    for case, parsed in parsed_map.items():
        res = simulate_alerts(parsed, packets, malicious_idx, case)
        rows.append(
            {
                "case": case,
                "precision": res.precision,
                "recall": res.recall,
                "f1": res.f1,
                "fpr": res.fpr,
                "alert": res.alert_count,
                "tp": res.tp,
                "fp": res.fp,
                "tn": res.tn,
                "fn": res.fn,
            }
        )

    # baseline 대비 alert 감소율 계산
    base_alert = next(r["alert"] for r in rows if r["case"] == "Baseline")
    for r in rows:
        if r["case"] == "Baseline":
            r["alert_reduction_pct"] = 0.0
        else:
            r["alert_reduction_pct"] = round((base_alert - r["alert"]) / max(base_alert, 1) * 100, 2)

    return rows


def write_csv(rows: List[dict], out_csv: Path):
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(
            [
                "case",
                "precision",
                "recall",
                "f1",
                "fpr",
                "alert",
                "alert_reduction_pct",
                "tp",
                "fp",
                "tn",
                "fn",
            ]
        )
        for r in rows:
            w.writerow(
                [
                    r["case"],
                    r["precision"],
                    r["recall"],
                    r["f1"],
                    r["fpr"],
                    r["alert"],
                    r["alert_reduction_pct"],
                    r["tp"],
                    r["fp"],
                    r["tn"],
                    r["fn"],
                ]
            )


def main():
    ap = argparse.ArgumentParser(description="Paper2: Noise/Whitelist ablation")
    ap.add_argument("--pcap", required=True, help="e.g. ./pcap_data/Thursday.pcap")
    ap.add_argument("--out", default="./results/paper2_result.csv")
    args = ap.parse_args()

    pcap_path = Path(args.pcap)
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP not found: {pcap_path}")

    packets = list(rdpcap(str(pcap_path)))
    print(f"[INFO] packets={len(packets)}")

    cases = [
        "Baseline",
        "Noise Filter only",
        "Whitelist only",
        "Noise -> Whitelist (Proposed)",
    ]

    case_rules: Dict[str, List[str]] = {}
    for c in cases:
        case_rules[c] = generate_rules_for_case(packets, c)
        print(f"[CASE] {c}: rules={len(case_rules[c])}")

    rows = evaluate_ablation(case_rules, packets)
    write_csv(rows, Path(args.out))
    print(f"[DONE] wrote: {args.out}")


if __name__ == "__main__":
    main()