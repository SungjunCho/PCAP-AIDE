# PCAP-AIDE (Pruned Version)

**AI-Driven IDS Signature Generation and Evaluation System**

This repository is a **pruned (cleaned)** version created specifically for writing a research paper.

### Purpose of This Repository
The newly uploaded repository below was created to utilize the source code for **academic paper writing**:

→ [https://github.com/SungjunCho/PCAP-AIDE](https://github.com/SungjunCho/PCAP-AIDE)

It is a **pruned version** of the following original repository:

→ [https://github.com/SungjunCho/PCAP-Analyzer](https://github.com/SungjunCho/PCAP-Analyzer)

Unnecessary commit history has been completely removed to provide a cleaner and more lightweight codebase suitable for research and publication.

## About This Project

PCAP-AIDE is an **AI-powered system** designed to automatically generate and evaluate **Intrusion Detection System (IDS)** signatures from PCAP files.  

It assists security researchers and analysts in creating effective detection rules by combining traditional rule-based engines with modern AI capabilities.

### Key Features
- Automated signature generation from PCAP traffic
- Multiple detection engines (Auto Learning, Keyword, Protocol, DNS Reputation, Noise Filter, etc.)
- AI integration with multiple LLM providers
- Web-based user interface
- Support for both single-packet and multi-packet analysis

### Technologies
- Python (backend)
- HTML + CSS (frontend)
- AI models for intelligent rule generation

## Original Repository
For the full commit history and previous development versions, please refer to the **[original PCAP-Analyzer repository](https://github.com/SungjunCho/PCAP-Analyzer)**.

## Quick Start

```bash
git clone https://github.com/SungjunCho/PCAP-AIDE.git
cd PCAP-AIDE

pip install -r requirements.txt

python app_multi.py     # Recommended: Multi-packet analysis
# or
python app_single.py    # Single-packet analysis
