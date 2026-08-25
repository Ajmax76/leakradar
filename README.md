<div align="center">
  <br />
  <img src="assets/logo.png" alt="LeakRadar Logo" width="140" />
  <h1>LeakRadar</h1>
  <p><strong>Open-Core API Security Engine for Automated BOLA & IDOR Vulnerability Scanning</strong></p>

  [![PyPI Version](https://img.shields.io/pypi/v/leakradar-cli.svg?color=blue)](https://pypi.org/project/leakradar-cli/)
  [![CI Pipeline](https://github.com/Ajmax76/leakradar/actions/workflows/ci.yml/badge.svg)](https://github.com/Ajmax76/leakradar/actions)
  [![Python Version](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
  [![License](https://img.shields.io/badge/license-PolyForm%20Noncommercial-green.svg)](LICENSE)
  <br /><br />
</div>

---

> ℹ️ **Open-Core Repository Note**: This public repository contains the free open-core CLI framework. Premium Pro Auditor features (Executive PDF Deliverables, Custom Agency Logo Branding, and Unthrottled Scanning) are exclusive to the standalone obfuscated executable binaries downloadable from [GitHub Releases](https://github.com/Ajmax76/leakradar/releases) or activated via Pro license keys at [ajmax76.github.io/leakradar](https://ajmax76.github.io/leakradar).

---

## Overview

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

## Key Features

* **3-Baseline Volatility Diffing:** Prunes volatile fields (timestamps, nonces, session IDs) across triple User A baselines before cross-token evaluation.
* **Automated Code Remediation Engine:** Automatically generates framework-specific code fixes (FastAPI, Django, Express, Spring Boot) for detected BOLA flaws with pay-as-you-go token billing or local models.
* **JWT Claim Harvesting:** Automatically parses bearer token claims (`sub`, `user_id`, `email`) to seed parameterized endpoints (`/api/v1/patients/{patient_id}`).
* **Cross-Token Replay Matrix:** Replays harvested endpoints using User B's identity, evaluating leaf-level scalar field overlap, ID echoing, and ownership matches.
* **Payload Secret Scanner:** Integrated Shannon entropy analysis ($\ge 4.5$) and regex rules for AWS keys, Stripe tokens, private keys, and API credentials.
* **Redacted PoC Deliverables:** Exports Markdown & Executive PDF reports with auto-redacted authorization tokens and proof steps.

---

## Quick Start

### Option 1: Install Open-Source Edition from PyPI (Recommended)

```bash
pip install leakradar-cli
```
*Note: The PyPI package delivers the 100% free open-core BOLA scanning engine and Markdown PoC exporter.*

### Option 2: Pro Auditor Edition Executables (Includes PDF Reports & White-Labeling)

Download compiled Pro executables directly for Windows, Linux, or macOS:
* **Windows (x64)**: `leakradar.exe` (PyArmor Obfuscated Binary)
* **Linux (x64)**: `leakradar-linux-x86_64`
* **macOS (ARM64)**: `leakradar-macos-arm64`

*Purchased Pro Auditor licenses ($30/mo) activate directly inside the compiled `leakradar.exe` binary via `leakradar auth --key <KEY>`.*

### Option 3: Install from Source

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

## Step-by-Step Usage Guide

### Step 1: Obtain 2 User Tokens
To detect BOLA / IDOR defects, LeakRadar tests if one user can access another user's private data. You need two authorization tokens:
* **Token A (`--token-a`) [VICTIM]**: The Bearer token for User A (e.g. Dr. Sarah Jenkins). LeakRadar uses this token to fetch baseline responses and discover resource IDs (like `patient_id: REC-9901`).
* **Token B (`--token-b`) [ATTACKER]**: The Bearer token for User B (e.g. Alex Miller). LeakRadar replays User A's requests using User B's token to check if User B is improperly granted access.

### Step 2: Run the Scan Command
Execute `leakradar scan` against your target API server and OpenAPI specification.

---

## Command Parameter Breakdown

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

## Feature Matrix (Community vs Pro Auditor vs Enterprise)

| Feature | Community (Free) | Pro Auditor (Tier 1) | Agency Suite (Tier 2) | Enterprise (Tier 3) |
| :--- | :---: | :---: | :---: | :---: |
| **BOLA / IDOR Detection Engine** | Included | Included | Included | Included |
| **Redacted Markdown PoC Export** | Included | Included | Included | Included |
| **Scan Speed Mode** | Throttled (1.5s delay) | **Maximum Speed (0s delay)** | **Maximum Speed (0s delay)** | **Unlimited Parallel Threads** |
| **Executive PDF Audit Reports** | Disabled | **Enabled (`--pdf`)** | **Enabled (`--pdf`)** | **Enabled (`--pdf`)** |
| **Custom Agency Logo & White-Labeling** | Disabled | Disabled | **Enabled (`--logo`, `--company`)** | **Enabled (`--logo`, `--company`)** |
| **Terminal Device Activations** | 1 Machine | 1 Machine | **3 Machines** | **10 Machines** |
| **Automated Code Remediation Engine** | Disabled | **Enabled** | **Enabled** | **Enabled / Air-Gapped** |
| **Commercial Audit Rights** | Non-Commercial Only | Freelancer / Pen-Tester | **Agency / MSSP** | **Organization-Wide** |

---

### Enterprise & Custom Engineering

Need custom capabilities, tailored AI models, or white-glove CI/CD integration for your organization? We offer dedicated engineering support for security agencies and enterprise dev teams:

*  **Air-Gapped Code Remediation**: Custom AI patch models (Ollama / Llama 3) for automated framework-specific fixes (FastAPI, Django, Express, Spring Boot).
*  **Custom Auth Adapters**: Integration with proprietary authentication systems (Okta, SAML, mTLS, dynamic CSRF nonces, custom token exchange).
*  **White-Label PDF Reports**: Custom executive PDF and HTML audit reports branded with your agency or client logo.
*  **Bespoke Integration Engineering**: We build custom integrations, internal CI/CD runners, and reporting frameworks tailored to your organization's exact tech stack.

Contact our team directly at **[https://ajmax76.github.io/leakradar](https://ajmax76.github.io/leakradar)** or via GitHub Private Security Advisories.

---

## Local Demo Target

A vulnerable BOLA REST API testbed is provided in [`demo_target/app.py`](demo_target/app.py). It includes:
* **Authentication Endpoint (`/api/v1/auth/login`)**: Issues standard 3-part Bearer JWT tokens for two distinct users (`user_101` and `user_102`).
* **Two Vulnerable BOLA Endpoints**: `GET /api/v1/patients/{patient_id}/records` and `GET /api/v1/users/{user_id}/profile` (both handlers decode the caller's JWT identity, but fail to verify resource ownership).
* **One Secured Control Endpoint**: `GET /api/v1/users/{user_id}/billing` (decodes caller identity AND enforces ownership checks, returning `403 Forbidden` on mismatch to verify false positive suppression).

```bash
# Start the demo target REST API
python demo_target/app.py
```

---

## License & Commercial Terms

The core open-source codebase is licensed under the verbatim **[PolyForm Noncommercial License 1.0.0](LICENSE)**.

* **Non-Commercial Use**: Free for security researchers, academic evaluation, and non-commercial vulnerability testing.
* **Commercial Use**: Using LeakRadar for paid client security audits, managed security services (MSSP), or commercial products is governed by our **[Commercial Terms](COMMERCIAL-TERMS.md)**.

> *Note: Organizations deploying LeakRadar commercially should conduct formal legal review of commercial licensing agreements.*

