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
  --token-a "Bearer eyJhbGci..." \
  --token-b "Bearer eyJhbGci..." \
  --output "./findings"
```

---

## 📖 Step-by-Step Usage Guide

### Step 1: Obtain 2 User Tokens
To detect BOLA / IDOR defects, LeakRadar tests if one user can access another user's private data. You need two authorization tokens:
* **Token A (`--token-a`) [VICTIM]**: The Bearer token for User A (e.g. Dr. Sarah Jenkins). LeakRadar uses this token to fetch baseline responses and discover resource IDs (like `patient_id: REC-9901`).
* **Token B (`--token-b`) [ATTACKER]**: The Bearer token for User B (e.g. Alex Miller). LeakRadar replays User A's requests using User B's token to check if User B is improperly granted access.

### Step 2: Run the Scan Command
Execute `leakradar scan` against your target API server and OpenAPI specification.

---

## 🛠️ Command Parameter Breakdown

| Parameter | Required / Optional | Description | Example |
| :--- | :---: | :--- | :--- |
| `--base-url` | **Required** | The root HTTP/HTTPS address of your target API server. | `http://127.0.0.1:8000` |
| `--spec` | **Required** | The URL or local file path to the target's **OpenAPI 3.0 specification** (`openapi.json` or `swagger.json`). LeakRadar uses this to map all endpoints and parameter schemas. | `http://127.0.0.1:8000/openapi.json` |
| `--token-a` | **Required** | Authorization Bearer token for **User A (Victim)**. Used to establish legitimate baseline responses and harvest valid resource identifiers. | `"Bearer eyJhbGci..."` |
| `--token-b` | **Required** | Authorization Bearer token for **User B (Attacker)**. Replays requests against User A's resources to verify authorization checks. | `"Bearer eyJhbGci..."` |
| `--output` | Optional | Directory path where vulnerability reports and cURL PoC files will be saved. Default is `./findings`. | `./findings` |
| `--allow-internal-spec` | Optional | Flag to allow scanning target specs hosted on internal/local IP addresses (`127.0.0.1`, `localhost`). | `--allow-internal-spec` |
| `--allow-destructive` | Optional | Enables testing of state-changing HTTP methods (`POST`, `PUT`, `DELETE`). By default, LeakRadar runs in Safe Mode (`GET`/`HEAD` only). | `--allow-destructive` |
| `--format` | Optional | Report export format (`markdown`, `pdf`, `all`). Default is `markdown`. | `--format markdown` |

---

## 📊 Feature Matrix (Community vs Pro Auditor vs Enterprise)

| Feature | Community Edition (Free) | Pro Auditor ($30/mo) | Enterprise / Custom |
| :--- | :---: | :---: | :---: |
| **BOLA / IDOR Detection Engine** | ✅ Full Engine | ✅ Full Engine | ✅ Full Engine |
| **Redacted Markdown PoC Export** | ✅ Included | ✅ Included | ✅ Included |
| **Scan Speed Mode** | ⏱️ 1.5s Throttled | ⚡ **Maximum Speed (0s delay)** | ⚡ **Unlimited Parallel Threads** |
| **Executive PDF Reports** | ❌ Locked | 📄 **Full PDF Deliverables** | 📄 **Full PDF Deliverables** |
| **Custom White-Label Branding** | ❌ Locked | 🏢 **Custom Logo & Company** | 🏢 **Custom Logo & Company** |
| **Commercial Audit Rights** | Non-Commercial Only | ✅ Solo Security Auditors | 🏢 **Organization-Wide License** |

---

## 🧪 Local Demo Target

A vulnerable BOLA REST API testbed is provided in `demo_target/app.py`:

```bash
python demo_target/app.py
```

---

## 📄 License

Governed by the **PolyForm Noncommercial License 1.0.0**. Free for security researchers, academic research, and non-commercial open-source vulnerability testing.
