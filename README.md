# ⚡ LeakRadar

[![CI Pipeline](https://github.com/ajmax76/leakradar/actions/workflows/ci.yml/badge.svg)](https://github.com/ajmax76/leakradar/actions)
[![PyPI version](https://img.shields.io/pypi/v/leakradar.svg)](https://pypi.org/project/leakradar/)
[![Python Versions](https://img.shields.io/pypi/pyversions/leakradar.svg)](https://pypi.org/project/leakradar/)
[![License: PolyForm Noncommercial](https://img.shields.io/badge/license-PolyForm%20Noncommercial-blue.svg)](https://polyformproject.org/)

**LeakRadar** is an automated API security reconnaissance engine designed to detect **Broken Object Level Authorization (BOLA / IDOR)** and exposed secrets across REST endpoints with near-zero false positives.

---

## 🌟 Key Architecture & Capabilities

* **3-Baseline Volatility Diffing:** Executes triple User A baselines to identify and prune volatile fields (timestamps, nonces, session tokens) before cross-token evaluation.
* **JWT Claim Harvesting:** Automatically parses bearer token claims (`sub`, `user_id`, `email`) to discover seed values for parameterized routes (`/api/users/{user_id}`).
* **Cross-Token Replay Matrix:** Replays candidate endpoints using User B's authentication identity and measures leaf-level scalar field overlap, ID echoing, and ownership matches.
* **Payload Secret Scanner:** Built-in Shannon entropy filter ($\ge 4.5$) and targeted regex rules for AWS keys, Stripe tokens, private keys, and API tokens.
* **Dual-Format Reporting:** Exports publication-ready HackerOne/Bugcrowd Markdown PoCs and executive ReportLab PDF deliverables with automatic credential redaction.

---

## 🚀 Quickstart

### 1. Installation
```bash
pip install leakradar
```

### 2. Run a Reconnaissance Scan

```bash
leakradar scan \
  --base-url "https://staging-api.example.com" \
  --spec "https://staging-api.example.com/openapi.json" \
  --token-a "JWT_TOKEN_VICTIM" \
  --token-b "JWT_TOKEN_ATTACKER" \
  --output "./findings" \
  --format all \
  --verbose
```

### 3. Activate Pro License (Optional)

```bash
leakradar auth --key "lr_live_..."
```

---

## 🛠 Local Development & Testing

1. Clone repository:
```bash
git clone https://github.com/ajmax76/leakradar.git
cd leakradar
```

2. Set up virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

3. Run automated test suite against local VAmPI container:
```bash
docker compose up -d
pytest tests/test_vampi_e2e.py -v
```

---

## 📄 License & Distribution

LeakRadar is distributed under the PolyForm Noncommercial License 1.0.0 for security researchers and community use. Commercial audits and team tiers require a Pro License via [ajmax76](https://ajmax76.github.io/leakradar/).
