# experiment_paper3.py
# -*- coding: utf-8 -*-
"""
Paper 3 (Hybrid IDS) reproducible experiment skeleton for PCAP-AIDE.

- Cases:
  1) Keyword only
  2) Protocol only
  3) DNS Reputation only (rule subset extraction)
  4) Keyword + Protocol
  5) All 6 Engines (Proposed)

주의:
- CIC-IDS2018의 정식 라벨(csv)이 없으면 TP/FP/FPR은 "Pseudo GT" 기준입니다.
- 기본은 Proposed(All6) alert index를 GT로 사용합니다.
"""

from __future__ import annotations

import argparse
import contextlib
import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List

from scapy.all import rdpcap  # type: ignore

import protocol_rule_engine as pre
import keyword_rule_engine as kre
from baseline_comparator import (
    parse_rules_from_text,
    simulate_alerts,
    build_malicious_idx,
)


@dataclass
class CaseResult:
    case: str
    precision: float
    recall: float
    f1: float
    fpr: float
    alert_count: int
    tp: int
    fp: int
    tn: int
    fn: int


def extract_payload(pkt):
    # baseline_comparator._extract_pkt_payload()와 유사
    try:
        from scapy.all import Raw, UDP, TCP, DNS  # type: ignore
        if Raw in pkt:
            return bytes(pkt[Raw].load)
        if DNS in pkt:
            return bytes(pkt[DNS])
        if UDP in pkt and pkt[UDP].payload:
            return bytes(pkt[UDP].payload)
        if TCP in pkt and pkt[TCP].payload:
            return bytes(pkt[TCP].payload)
    except Exception:
        pass
    return b""


@contextlib.contextmanager
def patch_protocol_engine(
    *,
    disable_noise: bool = False,
    disable_whitelist: bool = False,
    disable_keyword: bool = False,
    disable_dns_rep: bool = False,
):
    """protocol_rule_engine 내부 의존 함수 monkey patch."""
    orig_is_noise = pre.is_noise
    orig_wl = pre.check_global_whitelist
    orig_kw = pre._kw_detect
    orig_dns_rep = pre._dns_rep_check
    orig_dns_wl = pre._dns_wl_check

    try:
        if disable_noise:
            pre.is_noise = lambda payload, protocol="": {"noise": False, "reason": ""}

        if disable_whitelist:
            pre.check_global_whitelist = lambda payload, protocol, icmp_type=-1, icmp_code=-1: {
                "matched": False, "reason": "disabled", "entry": None
            }
            pre._dns_wl_check = lambda qname: None

        if disable_keyword:
            pre._kw_detect = lambda payload, protocol, dst_port, frame_no: {
                "matched_keywords": [],
                "matched_categories": [],
                "severity_max": "LOW",
                "rules": [],
                "matches": [],
            }

        if disable_dns_rep:
            pre._dns_rep_check = lambda domain: {
                "verdict": "UNKNOWN",
                "score": 0,
                "reason": "dns reputation disabled",
            }

        yield
    finally:
        pre.is_noise = orig_is_noise
        pre.check_global_whitelist = orig_wl
        pre._kw_detect = orig_kw
        pre._dns_rep_check = orig_dns_rep
        pre._dns_wl_check = orig_dns_wl


def run_case_rules(packets, case_name: str) -> List[str]:
    rules: List[str] = []
    rule_id = 1000001

    if case_name == "keyword_only":
        for i, pkt in enumerate(packets):
            payload = extract_payload(pkt)
            if not payload:
                continue
            proto = pre.detect_protocol(pkt, payload)
            hdr = pre.extract_header_features(pkt)
            dst_port = hdr.get("dst_port", "any")
            kw = kre.detect_and_build_rules(payload, proto, dst_port, i + 1)
            rules.extend(kw["rules"])
        return dedup_rules(rules)

    if case_name == "protocol_only":
        with patch_protocol_engine(
            disable_noise=True,
            disable_whitelist=True,
            disable_keyword=True,
            disable_dns_rep=True,
        ):
            return run_generate_rules_loop(packets)

    if case_name == "dns_reputation_only":
        # DNS Reputation 엔진만 깔끔하게 단독 룰 생성하는 공개 API가 없어,
        # protocol 결과에서 DNS 관련 룰만 추출하는 방식으로 구성.
        with patch_protocol_engine(
            disable_noise=True,
            disable_whitelist=True,
            disable_keyword=True,
            disable_dns_rep=False,
        ):
            base_rules = run_generate_rules_loop(packets)
        dns_rules = [r for r in base_rules if ("DNS" in r.upper() or "domain" in r.lower())]
        return dedup_rules(dns_rules)

    if case_name == "keyword_protocol":
        with patch_protocol_engine(
            disable_noise=True,
            disable_whitelist=True,
            disable_keyword=False,
            disable_dns_rep=True,
        ):
            return run_generate_rules_loop(packets)

    if case_name == "all6_proposed":
        # 기본 파이프라인(Noise + Whitelist + Keyword + Protocol + DNS Rep)
        # Auto Learning은 런타임 키워드 파일 변형 가능성이 있어 본 스크립트에서는 제외.
        return run_generate_rules_loop(packets)

    raise ValueError(f"Unknown case: {case_name}")


def run_generate_rules_loop(packets) -> List[str]:
    rules: List[str] = []
    rule_id = 1000001
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


def rules_to_parsed(rules: List[str], label: str):
    text = "\n".join(rules)
    return parse_rules_from_text(text, source_label=label)


def evaluate_cases(packets, case_rules: Dict[str, List[str]], gt_case: str = "all6_proposed"):
    gt_rules = rules_to_parsed(case_rules[gt_case], gt_case)
    malicious_idx = build_malicious_idx(gt_rules, packets)  # pseudo GT

    rows: List[CaseResult] = []
    for case, rules in case_rules.items():
        parsed = rules_to_parsed(rules, case)
        res = simulate_alerts(parsed, packets, malicious_idx, case)
        rows.append(
            CaseResult(
                case=case,
                precision=res.precision,
                recall=res.recall,
                f1=res.f1,
                fpr=res.fpr,
                alert_count=res.alert_count,
                tp=res.tp,
                fp=res.fp,
                tn=res.tn,
                fn=res.fn,
            )
        )
    return rows


def write_csv(rows: List[CaseResult], out_csv: Path):
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["case", "precision", "recall", "f1", "fpr", "alert_count", "tp", "fp", "tn", "fn"])
        for r in rows:
            w.writerow([r.case, r.precision, r.recall, r.f1, r.fpr, r.alert_count, r.tp, r.fp, r.tn, r.fn])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", required=True, help="PCAP path (e.g., ./pcap_data/Thursday.pcap)")
    ap.add_argument("--out", default="./results/paper3_metrics.csv", help="output csv path")
    args = ap.parse_args()

    pcap_path = Path(args.pcap)
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP not found: {pcap_path}")

    packets = rdpcap(str(pcap_path))
    cases = ["keyword_only", "protocol_only", "dns_reputation_only", "keyword_protocol", "all6_proposed"]

    case_rules: Dict[str, List[str]] = {}
    for c in cases:
        case_rules[c] = run_case_rules(packets, c)
        print(f"[{c}] rules={len(case_rules[c])}")

    rows = evaluate_cases(packets, case_rules, gt_case="all6_proposed")
    write_csv(rows, Path(args.out))
    print(f"[done] wrote: {args.out}")


if __name__ == "__main__":
    main()