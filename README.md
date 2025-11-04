# SOC-CTF Log Analysis Platform (Final Project)

This is a complete, two-part system that simulates a real-world cybersecurity analysis workflow.

1.  **CTF Platform (`server/`):** A Flask-based web application that hosts a "capture the flag" competition.
2.  **SOC Analysis Tool (`tool/`):** A professional, interactive SOC Dashboard built in Streamlit.

## Features
* **Universal Log Parsing:** Auto-detects and parses multiple log formats (JSON, Apache, or generic text).
* **Live CTI Enrichment:** Enriches every IP against VirusTotal and AbuseIPDB.
* **Threat Geolocation:** Plots suspicious IPs on an interactive world map.
* **SIEM-style Filtering:** A robust "Log Explorer" tab for universal searching.
* **Automated Risk Scoring:** Classifies threats as Critical, High, or Medium.

---

## How to Run This Project

This project requires running **two separate servers** simultaneously.

### 1. Install Dependencies
```bash
git clone [https://github.com/gularmirzayeva23-cell/my-soc-project-CTF-Challenge-log-analyzer.git](https://github.com/gularmirzayeva23-cell/my-soc-project-CTF-Challenge-log-analyzer.git)
cd my-soc-project-CTF-Challenge-log-analyzer
pip install -r requirements.txt
