<div align="center">

# 🛡️ Midins Decryptor

### Offline OSINT Triage Console for Blue-Team Analysts & Malware Investigators

[![License: CC BY-SA 4.0](https://img.shields.io/badge/License-CC%20BY--SA%204.0-8A2BE2.svg?style=for-the-badge)](https://creativecommons.org/licenses/by-sa/4.0/)
[![ISO/IEC 27701](https://img.shields.io/badge/ISO%2FIEC-27701-5B189A?style=for-the-badge&logo=iso&logoColor=white)](https://www.iso.org/standard/71670.html)
[![ISO/IEC 25010](https://img.shields.io/badge/ISO%2FIEC-25010-5B189A?style=for-the-badge&logo=iso&logoColor=white)](https://iso25000.com/index.php/en/iso-25000-standards/iso-25010)
[![OWASP](https://img.shields.io/badge/OWASP-API%20Top%2010-8A2BE2?style=for-the-badge&logo=owasp&logoColor=white)](https://owasp.org/API-Security/)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-1E293B?style=for-the-badge&logo=python&logoColor=8A2BE2)](https://www.python.org/)
[![Flask 3.0](https://img.shields.io/badge/Flask-3.0-1E293B?style=for-the-badge&logo=flask&logoColor=8A2BE2)](https://flask.palletsprojects.com/)
[![Offline First](https://img.shields.io/badge/Network-ZERO%20EGRESS-22c55e?style=for-the-badge)]()

**A 100% local-first, browser-based forensic decoder & artifact harvester. Built for analysts who refuse to leak investigations into third-party CyberChef clones.**

</div>

---

## 🎯 Architecture & Purpose

During OSINT investigations and malware triage, security analysts constantly encounter:

- Obfuscated phishing kits with nested base64/url-encoded payloads
- JavaScript trackers hiding C2 endpoints behind multi-layer encoding
- Ransom notes / leaked credential dumps with embedded JWTs and AWS keys
- Suspicious scripts pulled from a sandbox that must be decoded **without** exposing the target infrastructure to the public internet

The de-facto industry tools (CyberChef clones, online base64 converters, JWT debuggers) are **public web services**. Pasting a leaked Bearer token, an internal corporate FQDN, or a victim's email into one of these tools **immediately leaks that artifact** to logs, CDNs, or worse — an attacker-controlled clone. This is a textbook **OpSec compliance failure** under **ISO/IEC 27701** privacy boundaries.

**Midins Decryptor** solves this by providing the same processing power as enterprise SOC tooling, but enforces a **strict local-first execution boundary**:

- 🚫 No external API calls
- 🚫 No analytics, no telemetry, no CDN font tracking
- 🚫 No backend database — history lives only in `LocalStorage`
- ✅ Cascading recursive decoder with forensic timeline
- ✅ Shannon entropy classification for encrypted-payload detection
- ✅ Regex-hardened artifact harvesting (IPs, URLs, emails, secrets)
- ✅ Live category badge pills with real-time artifact counts
- ✅ Plaintext gate — printable-ASCII ratio check stops false-positive chains

---

## ⚡ Advanced Capabilities Matrix

| Capability | Description | Standard |
|---|---|---|
| 🔁 **Recursive Cascade Decoder** | Multi-layer pipeline (depth-limited to 5) auto-chains base64 → hex → url → html → unicode escape → rot13 detection | ISO/IEC 25010 — Functional Suitability |
| 🧬 **Shannon Entropy Engine** | Mathematical H(x) calculation flagging `>4.5` (hex) or `>5.0` (base64) as encrypted/key material | Cryptographic Forensics |
| ⏱ **Chronological Forensic Timeline** | Every layer recorded with timestamp (ms), input/output lengths, byte delta, entropy evolution, and before/after preview diffs | Audit Trail / NIST SP 800-92 |
| 🛑 **Plaintext Gate (Anti-FP)** | Printable-ASCII ratio computed after each layer — if output is ≥90% readable text + contains known command keywords, cascade halts immediately to prevent false-positive decode chains | Cascade Integrity |
| 🔴 **Live Category Badges** | Colored notification pills auto-appear on each tab (IPs / URLs / Emails / Secrets) showing exact artifact count as soon as the cascade resolves | UX / Triage Speed |
| 🛡 **ReDoS-Safe Regex Module** | All extraction patterns pre-compiled at module level with bounded quantifiers | OWASP API Top 10 |
| 💾 **LocalStorage Session Memory** | Last 25 investigations cached client-side — zero backend persistence | ISO/IEC 27701 — PII Boundary |
| 🔐 **Secret Harvester** | Detects AWS keys, GCP API tokens, Slack tokens, GitHub PATs, Stripe keys, JWTs, PEM private key blocks, Bearer tokens | Blue-Team Triage |
| 🌐 **IP / FQDN / Email Extraction** | Differentiates RFC1918 private ranges from public C2 candidates | Threat Intelligence |
| 🪟 **Liquid-Glass Dashboard UI** | Cyberpunk aesthetic — Deep Charcoal (`#0F172A`) + Electric Violet (`#8A2BE2`) | UX / Brand System |
| 🚫 **Zero Egress Header** | CSP locks `connect-src` to `'self'` | Defense-in-Depth |

---

## 🚀 Installation

### 🐧 Linux / macOS

```bash
git clone https://github.com/Med0/midins-decryptor.git
cd midins-decryptor

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
python3 app.py
```

> 🐠 **fish shell?** Use `source .venv/bin/activate.fish` instead.

| Shell | Activation command |
|---|---|
| bash / zsh | `source .venv/bin/activate` |
| fish | `source .venv/bin/activate.fish` |
| csh / tcsh | `source .venv/bin/activate.csh` |

Open → `http://127.0.0.1:5000`

---

### 🪟 Windows (PowerShell)

```powershell
git clone https://github.com/Med0/midins-decryptor.git
cd midins-decryptor

python -m venv .venv
.\.venv\Scripts\Activate.ps1

pip install -r requirements.txt
python app.py
```

Open → `http://127.0.0.1:5000`

---

### 🐳 Docker (hardened deployment)

```bash
docker build -t midins-decryptor:1.4 .
docker run --rm -p 127.0.0.1:5000:5000 --network=none midins-decryptor:1.4
```

> ⚠️ `--network=none` enforced — mathematically guarantees zero egress at kernel level after build.

---

## 🧪 Operational Workflow

1. **Paste** your raw, obfuscated, or suspicious payload into the input pane
2. Press **`EXECUTE CASCADE`** (or **Ctrl + Enter**)
3. Review the **Decoding Timeline** — every transformation layer is fully auditable
4. Watch **badge pills** populate in real-time on each artifact tab
5. Switch tabs to inspect extracted **IPs / URLs / Emails / Secrets**
6. The investigation is auto-saved to **LocalStorage** — reload from the **Session History** drawer at any time
7. **Purge** the entire local cache with one click when the engagement is closed

---

## 🧠 Threat Model & Boundaries

| Threat | Mitigation |
|---|---|
| Payload size DoS | Hard `MAX_PAYLOAD_BYTES = 2_500_000` ceiling enforced server-side |
| ReDoS via crafted regex input | All patterns use bounded quantifiers, pre-compiled once at module load |
| Decoding infinite-loop oscillation | Fingerprint set (hash dedupe) + depth cap (5) |
| False-positive | May get some false positve, but keep an eye on the timeline ! |
| Browser exfiltration via 3rd-party script | Strict CSP locks `connect-src 'self'`, no analytics |
| Cross-tab session leak | LocalStorage scoped to origin, manual purge button always visible |
| Server-side crash exposing stack | Global exception handler returns structured JSON, never HTML traces |

---

## 📂 Project Structure

```
midins-decryptor/
├── app.py                # Flask entrypoint + hardened headers + global error handler
├── requirements.txt      # Pinned dependencies
├── README.md             # This document
├── .gitignore            # Excludes __pycache__, .env, .venv, *.pyc, .DS_Store
├── core/
│   ├── __init__.py       # Package surface
│   ├── detector.py       # Cascade decoder + Shannon entropy + plaintext gate + timeline engine
│   └── extractors.py     # OSINT artifact harvester (regex-compiled module-level)
└── templates/
    └── index.html        # Liquid-glass dashboard — live badge pills, session history drawer
```

---

## 📜 License & Attribution

This project is released under **Creative Commons Attribution-ShareAlike 4.0 International (CC BY-SA 4.0)**.

> Copyright © **Med0**  
> You are free to share and adapt this work under the same license, with attribution.

[![CC BY-SA 4.0](https://licensebuttons.net/l/by-sa/4.0/88x31.png)](https://creativecommons.org/licenses/by-sa/4.0/)

---

## 🤝 Author

Crafted by **Med0** — for analysts who treat their OpSec as seriously as their adversaries do.

> *"Your evidence should never leave your machine. Period."*

