<div align="center">
  <br />
  <img src="assets/logo.png" alt="LeakRadar Logo" width="140" />
  <h1>LeakRadar</h1>
  <p><strong>Open-Core API Security Engine for Automated BOLA & IDOR Vulnerability Scanning</strong></p>

  [![CI Pipeline](https://github.com/Ajmax76/leakradar/actions/workflows/ci.yml/badge.svg)](https://github.com/Ajmax76/leakradar/actions)
  [![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
  [![License](https://img.shields.io/badge/license-PolyForm%20Noncommercial-green.svg)](LICENSE)
  <br /><br />
</div>

---

## ⚡ Overview

**LeakRadar** is an open-core DAST scanner designed specifically for REST APIs. It detects **Broken Object Level Authorization (BOLA / IDOR)** defects, token privilege escalation, and exposed secrets with near-zero false positives using a cross-token pairwise heuristic matrix algorithm.

```text
                        LeakRadar Vulnerability Summary                        
+-----------------------------------------------------------------------------+
| Endpoint             | Params               | Status | Overlap | Confidence |
|----------------------+----------------------+--------+---------+------------|
| /api/v1/patients/{p} | {"patient_id":       |  200   |  100.0% |    HIGH    |
|                      | "REC-9901"}          |        |         |            |
+-----------------------------------------------------------------------------+
[3/3] Generating redacted proof-of-concept reports...
Saved Markdown PoC: demo_findings/bola_api_v1_patients_patient_id_records.md
+--------- Scan Finished ---------+
| Scan Completed Successfully!    |
| Total Findings: 1               |
+---------------------------------+
```

---

## 🌟 Key Features

* **3-Baseline Volatility Diffing:** Prunes volatile fields (timestamps, nonces, session IDs) across triple User A baselines before cross-token evaluation.
* **JWT Claim Harvesting:** Automatically parses bearer token claims (`sub`, `user_id`, `email`) to seed parameterized endpoints (`/api/v1/patients/{patient_id}`).
* **Cross-Token Replay Matrix:** Replays harvested endpoints using User B's identity, evaluating leaf-level scalar field overlap, ID echoing, and ownership matches.
* **Payload Secret Scanner:** Integrated Shannon entropy analysis ($\ge 4.5$) and regex rules for AWS keys, Stripe tokens, private keys, and API credentials.
* **Redacted PoC Deliverables:** Exports Markdown & Executive PDF reports with auto-redacted authorization tokens and proof steps.

---

## 🚀 Quick Start

### Installation

```bash
git clone https://github.com/Ajmax76/leakradar.git
cd leakradar
pip install -e .
```

### Run BOLA Vulnerability Scan

```bash
leakradar scan \
  --base-url "http://127.0.0.1:8000" \
  --spec "http://127.0.0.1:8000/openapi.json" \
  --token-a "<VICTIM_USER_JWT>" \
  --token-b "<ATTACKER_USER_JWT>" \
  --output "./findings"
```

---

## 📊 Feature Matrix (Community vs Pro Auditor)

| Feature | Community Edition (Free) | Pro Auditor ($30/mo) |
| :--- | :---: | :---: |
| **BOLA / IDOR Detection Engine** | ✅ Full Engine | ✅ Full Engine |
| **Redacted Markdown PoC Export** | ✅ Included | ✅ Included |
| **Scan Speed Mode** | ⏱️ 1.5s Throttled | ⚡ **Maximum Speed (0s delay)** |
| **Executive PDF Reports** | ❌ Locked | 📄 **Full Executive PDF Deliverables** |
| **Custom White-Label Branding** | ❌ Locked | 🏢 **Custom Logo & Company** |

---

## 🧪 Local Demo Target

A vulnerable BOLA REST API testbed is provided in `demo_target/app.py`:

```bash
python demo_target/app.py
```

---

## 📄 License

Governed by the **PolyForm Noncommercial License 1.0.0**. Free for security researchers, academic research, and non-commercial open-source vulnerability testing.
