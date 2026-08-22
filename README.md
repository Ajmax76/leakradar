# ⚡ LeakRadar

[![CI Pipeline](https://github.com/ajmax76/leakradar/actions/workflows/ci.yml/badge.svg)](https://github.com/ajmax76/leakradar/actions)
[![Python Versions](https://img.shields.io/pypi/pyversions/leakradar.svg)](https://pypi.org/project/leakradar/)

**LeakRadar** is an automated API security reconnaissance engine designed to detect **Broken Object Level Authorization (BOLA / IDOR)** vulnerabilities and exposed secrets across REST endpoints with near-zero false positives.

---

## 🌟 Key Features

* **3-Baseline Volatility Diffing:** Executes triple User A baselines to prune volatile fields (timestamps, nonces, session tokens) before cross-token evaluation.
* **JWT Claim Harvesting:** Automatically parses bearer token claims (`sub`, `user_id`, `email`) to discover seed values for parameterized routes (`/api/users/{user_id}`).
* **Cross-Token Replay Matrix:** Replays candidate endpoints using User B's authentication identity and measures leaf-level scalar field overlap, ID echoing, and ownership matches.
* **Payload Secret Scanner:** Built-in Shannon entropy filter ($\ge 4.5$) and targeted regex rules for AWS keys, Stripe tokens, private keys, and API tokens.
* **Double-Click Standalone Executable:** Includes a zero-dependency interactive terminal menu for double-click execution on Windows (`.exe`), Linux, and macOS.
* **Bundled Benchmark Spec Suites:** Includes standard & enterprise multi-service OpenAPI specs out-of-the-box for instant benchmark scanning.

---

## 🚀 Download & Execution Options

### Option A: Standalone Double-Click Executable (Recommended)

1. Download **`leakradar.exe`** (Windows) or native binary from the **GitHub Releases** page.
2. Double-click **`leakradar.exe`** to open the interactive terminal dashboard:

```text
╭───────────────────── Welcome to LeakRadar ─────────────────────╮
│ LeakRadar API Security Scanner v0.1.0                          │
│ Autonomous BOLA / IDOR Vulnerability Detection Engine          │
│ License Status: COMMUNITY EDITION (FREE)                       │
╰────────────────────────────────────────────────────────────────╯

Select an action:
  1 Run BOLA Vulnerability Scan
  2 Activate License Key (auth)
  3 View Command Help
  4 Exit
```

---

### Option B: Command Line Interface (CLI)

```bash
# Activate Paid Pro License
leakradar auth --key "lr_live_..."

# Run API Vulnerability Scan
leakradar scan \
  --base-url "https://api.example.com" \
  --spec "https://api.example.com/openapi.json" \
  --token-a "JWT_TOKEN_VICTIM" \
  --token-b "JWT_TOKEN_ATTACKER" \
  --output "./findings" \
  --format all
```

---

## 📊 Tier Comparison (Community vs. Pro Auditor)

| Feature | Community Edition (Free) | Pro Auditor Edition ($30/mo) |
| :--- | :---: | :---: |
| **BOLA / IDOR Detection Engine** | ✅ Full Engine | ✅ Full Engine |
| **Redacted Markdown PoC Reports** | ✅ Included | ✅ Included |
| **Bundled Benchmark Specs** | Standard Spec | **30+ Endpoint Enterprise Suite** |
| **Scan Speed Mode** | ⏱️ 1.5s Throttled | ⚡ **Maximum Speed (0.0s delay)** |
| **Executive PDF Reports** | ❌ Locked | 📄 **Full Executive PDF Deliverables** |
| **White-Label Branding** | ❌ Locked | 🏢 **Custom Logo & Company (`--company`, `--logo`)** |

---

## 🛠 Local Development & Testing

1. Clone repository:
```bash
git clone https://github.com/ajmax76/leakradar.git
cd leakradar
```

2. Set up virtual environment:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

3. Run automated unit test suite:
```bash
pytest tests/test_unit_matrix.py -v
```

---

## 📄 License & Distribution

LeakRadar is governed by the **PolyForm Noncommercial License 1.0.0**.

- **Non-Commercial Use**: Free for individual security researchers, academic research, and non-commercial open-source vulnerability testing.
- **Commercial & Revenue Use**: Using LeakRadar to offer paid client audits, managed security services, or commercial software products strictly requires a **Pro Auditor** or **Enterprise** commercial license key via Dodo Payments.

