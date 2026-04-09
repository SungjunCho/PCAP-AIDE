# PCAP-AIDE (Pruned Version)

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
