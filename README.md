# PCAP-AIDE (Pruned Version)

<!-- LATEST_CHANGES_START -->
## What's New in PCAP-AIDE (Compared to PCAP-Analyzer)

PCAP-AIDE is a **pruned and research-optimized** version of PCAP-Analyzer, specifically prepared for academic paper writing and SCIE/KCI journal submissions.

### Key Improvements & New Features

- **Clean & Pruned Codebase**: Removed unnecessary commit history and experimental code for better readability and reproducibility.
- **Baseline Comparator Engine** (`baseline_comparator.py`):  
  Newly added core module that automatically compares AI-generated Snort rules with official baselines (Snort Community Rules and Emerging Threats Open rules).  
  Provides comprehensive quantitative metrics (Precision, Recall, F1-Score, FPR, Jaccard Similarity, etc.) ideal for Evaluation sections in SCIE papers.
- **Paper-specific Experiment Scripts**:  
  `experiment_paper1.py`, `experiment_paper2.py`, `experiment_paper3.py` — Ready-to-run scripts for the three planned papers.
- **Enhanced Rule Management**: Automatic download and parsing of public rule sets (Emerging Threats, Snort Community) with local caching.
- **New Engine**: `file_reputation_engine.py` for file extraction and reputation analysis.
- **Improved Modular Architecture**: All detection engines are highly modularized for easier extension and ablation studies.
- **Research Focus**: Optimized for academic use with better documentation, experiment reproducibility, and evaluation capabilities.

### Core Features (Updated)
- Automated Snort/Suricata signature generation using multi-LLM consensus and rule engines
- Multiple detection engines (Noise Filter, Auto-Learn, Keyword, Protocol, DNS Reputation, Whitelist, **Baseline Comparator**)
- Advanced multi-LLM integration (Claude, GPT, Grok, etc.)
- Web-based UI with single/multi-file analysis modes
- Comprehensive evaluation framework for academic papers
<!-- LATEST_CHANGES_END -->

**AI-Driven IDS Signature Generation and Evaluation System**

This repository is a **pruned (cleaned)** version created specifically for academic paper writing and further research.

### Purpose of This Repository
The newly uploaded repository was created to utilize the source code for **research paper writing**:

→ **[https://github.com/SungjunCho/PCAP-AIDE](https://github.com/SungjunCho/PCAP-AIDE)**

It is a **pruned version** of the original repository:

→ **[https://github.com/SungjunCho/PCAP-Analyzer](https://github.com/SungjunCho/PCAP-Analyzer)**

Unnecessary commit history has been completely removed to provide a cleaner, lighter, and more maintainable codebase.

## Key Improvements Compared to PCAP-Analyzer

| Feature                        | PCAP-Analyzer (Original)          | PCAP-AIDE (New)                          | Improvement |
|-------------------------------|-----------------------------------|-------------------------------------------|-----------|
| Project Focus                 | General PCAP Analysis Tool       | **AI-Driven IDS Signature Generation**   | More research-oriented |
| AI Integration                | Basic AI support                 | **Enhanced multi-LLM provider support**  | More flexible AI usage |
| Codebase                      | Full history + experimental code | **Clean & pruned structure**             | Better readability & maintenance |
| Purpose                       | General use                      | **Academic research & paper writing**    | Optimized for publication |
| Engine Modularization         | Good                             | **Highly modularized engines**           | Easier to extend and experiment |
| Documentation & Cleanliness   | Standard                         | **Significantly improved**               | Suitable for research sharing |

## About This Project

PCAP-AIDE is an **AI-powered Intrusion Detection System (IDS) signature generation and evaluation framework**. It automatically analyzes PCAP files and generates high-quality detection signatures by combining traditional rule-based engines with modern AI/LLM capabilities.

### Core Features

- **Automated Signature Generation** from PCAP traffic
- **Multiple Detection Engines**:
  - Auto Learning Engine (`auto_learn_engine.py`)
  - Keyword Rule Engine (`keyword_rule_engine.py`)
  - Protocol Rule Engine (`protocol_rule_engine.py`)
  - DNS Reputation Engine (`dns_reputation_engine.py`) with VirusTotal support
  - Noise Filter & Whitelist Engine (`noise_filter_engine.py`, `whitelist_engine.py`)
  - Baseline Comparator (`baseline_comparator.py`)
- **Advanced AI Integration** (`ai_providers.py`) — Supports multiple LLM providers
- **Web-based User Interface** (Flask)
- **Single-packet** and **Multi-packet** analysis modes
- Clean modular architecture optimized for research experiments

## Quick Start & Usage

```bash
# 1. Clone the repository
git clone https://github.com/SungjunCho/PCAP-AIDE.git
cd PCAP-AIDE

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run the application

# Option A: Multi-packet analysis mode (Recommended)
python app_multi.py

# Option B: Single-packet analysis mode
python app_single.py
