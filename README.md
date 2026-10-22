# CyberShield: Suspicious Login Detection System

A modern, interactive Cybersecurity Dashboard built with **Python**, **Streamlit**, **Pandas**, and **Plotly** to analyze authentication logs, detect credential attacks, identify abnormal access patterns, and generate actionable security incident alerts.

---

## 🌟 Key Features

1. **Executive Security Dashboard**:
   - Total auth requests scanned, successful vs. failed logins, failure rate percentage.
   - High, Medium, and Low risk alert metric cards.
   - 15-minute interval authentication activity timeline chart (Success vs. Failure).
   - Donut chart showing alert severity breakdown.
   - Detected threat categories breakdown and Top 5 targeted users and offending IPs.

2. **6 Rule-Based Cyber Threat Detection Engine**:
   - **Rule 1: Repeated Failed Logins (Brute Force)**: Flags any account or source IP exceeding $N$ failed attempts within $M$ minutes (default: 5 attempts in 10 minutes).
   - **Rule 2: Unusual Login Times**: Flags authentications occurring outside configurable business hours (default: 08:00–19:00) or on weekends.
   - **Rule 3: Successful Login After Repeated Failures**: Flags successful logins immediately preceded by $\ge 3$ failed attempts (strong indicator of credential compromise or brute force breach).
   - **Rule 4: Unfamiliar / Untrusted IP Addresses**: Cross-references source IPs against a configurable trusted corporate whitelist.
   - **Rule 5: Multiple-User Targeting (Password Spraying)**: Detects a single IP attempting logins across $\ge 3$ distinct accounts within a sliding window.
   - **Rule 6: Unusual Access Patterns (Velocity / Impossible Travel)**: Detects impossible geographic relocation between logins (e.g. New York to Tokyo within minutes) or rapid infrastructure hopping.

3. **Interactive Alert Management & SOC Triage**:
   - Severity badges (🔴 High, 🟠 Medium, 🔵 Low).
   - Real-time multi-criteria filtering by Risk Level, Threat Rule, Username, and IP.
   - Expandable incident cards showing exact evidence count, full technical explanation, recommended mitigation actions, and correlated raw logs.
   - One-click **Export Filtered Alerts to CSV**.

4. **Deep-Dive Threat Analytics**:
   - Hourly authentication heatmap showing business vs. non-business hours.
   - Geographic origin distribution of login attempts.
   - Client device and User-Agent breakdown.
   - IP vs. User attack concentration scatter matrix.

5. **Flexible Data Ingestion**:
   - Built-in multi-scenario fictional attack generator (Mixed Attacks, Brute Force Spike, Credential Guessing Breach, Stealth Password Spraying).
   - Custom CSV file upload with strict validation and helpful error feedback.
   - One-click downloadable sample CSV template.

6. **Cybersecurity Defense Playbook & SIEM Architecture**:
   - Practical hardening guide (FIDO2 MFA, rate limiting, conditional access, password hygiene).
   - Step-by-step SOC incident response checklist.
   - Educational comparison between heuristic detection and enterprise SIEM/UEBA architectures.

---

## 📋 Requirements

- **Python**: Version 3.9 or higher (tested on Python 3.13)
- **Dependencies**: Listed in `requirements.txt`:
  - `streamlit>=1.30.0`
  - `pandas>=2.0.0`
  - `plotly>=5.18.0`
  - `numpy>=1.24.0`

---
