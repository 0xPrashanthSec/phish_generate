# ECI Phishing Simulation Lab
### Qevlar SOC POC — Defensive Testing Infrastructure

**Purpose:** Generate realistic, fully benign phishing artifacts for validating Qevlar's autonomous triage, enrichment, and response capabilities — without using real client data or live phishing infrastructure.

> All artifacts are non-malicious. No credentials are captured. No external network traffic is generated. For internal ECI SOC use only.

---

## Contents

| File | Description |
|------|-------------|
| `generate_phishing_artifacts.py` | Primary artifact generator (Python) — all 8 phishing types |
| `Generate-PhishingArtifacts.ps1` | Windows PowerShell equivalent — 6 phishing types |
| `inject_emails.py` | Sends generated EMLs to MailHog via SMTP |
| `docker-compose.yml` | Isolated lab stack — MailHog + landing server + nginx |
| `landing_server.py` | Click-logger for test URLs — safe page, zero data capture |
| `qevlar_test_scenarios.md` | 12 structured test scenarios + POC scorecard |

---

## Prerequisites

**Python generator:**
```bash
python 3.8+
pip install qrcode[pil] Pillow   # QR code generation (optional — fallback to placeholder if absent)
```

**Lab stack:**
```
Docker 20.10+
Docker Compose v2
```

**PowerShell generator:**
```
PowerShell 5.1+ (Windows) or PowerShell 7+ (cross-platform)
```

**DNS (required for click tracking):**
Add to `/etc/hosts` (or internal DNS) on any machine running the lab:
```
127.0.0.1  phishtest.internal
```

---

## Quick Start

### Option A — Python (recommended)

```bash
# Install deps
pip install qrcode[pil] Pillow

# Generate 3 samples per category (24 total artifacts)
python generate_phishing_artifacts.py

# Generate 5 samples per category with custom URL and domain
python generate_phishing_artifacts.py \
  --count 5 \
  --url http://phishtest.internal \
  --domain eci.com \
  --output ./phishing_artifacts
```

### Option B — PowerShell (Windows SOC)

```powershell
# Unblock if needed
Unblock-File .\Generate-PhishingArtifacts.ps1

# Generate with defaults
.\Generate-PhishingArtifacts.ps1

# Generate with custom params
.\Generate-PhishingArtifacts.ps1 `
  -OutputDir ".\phishing_artifacts" `
  -TestBaseUrl "http://phishtest.internal" `
  -TargetDomain "eci.com" `
  -CountPerType 5
```

### Option C — Docker (fully isolated)

```bash
# Start lab services
docker-compose up -d mailhog landing-server nginx

# Generate artifacts (writes to shared volume)
docker-compose run --rm artifact-gen --count 5

# Inject EMLs into MailHog
docker-compose run --rm eml-injector

# View captured emails
open http://localhost:8025
```

---

## Generated Output Structure

```
phishing_artifacts/
│
├── emails/                        # EML files — one folder per category
│   ├── clickfix/                  # ClickFix lure (Win+R / MSHTA payload URL)
│   ├── credential_harvest/        # Microsoft account security alert + HTML attachment
│   ├── quishing/                  # QR code phishing — inline PNG + URL
│   ├── html_attachment/           # DocuSign lure with fake login HTML attachment
│   ├── bec/                       # Executive wire transfer request
│   ├── invoice/                   # Overdue invoice with payment URL
│   ├── delivery/                  # FedEx/DHL/UPS customs fee lure
│   └── mfa_reset/                 # MFA settings changed — urgency lure + attachment
│
├── qr_codes/                      # PNG QR images pointing to phishtest.internal
│
├── html_attachments/              # Standalone fake login HTML pages
│
├── siem_alerts/
│   ├── elastic/                   # Kibana Security alert JSON (one per EML)
│   └── sentinel/                  # Microsoft Sentinel SecurityAlert table JSON
│
├── qevlar_payloads/               # Normalized Qevlar-compatible alert JSON
│
└── reports/
    └── manifest.json              # Full artifact index with IOCs and metadata
```

---

## Phishing Categories

| # | Type | MITRE | Default Severity | Attachment |
|---|------|-------|-----------------|------------|
| 1 | ClickFix lure | T1566.001 | High | None (URL in body) |
| 2 | Credential harvest | T1566.002 | High | `SecureDocument.html` |
| 3 | Quishing (QR phishing) | T1566.001 | Medium | Inline QR PNG |
| 4 | HTML attachment | T1566.001 | High | `DocuSign_*.html` |
| 5 | BEC — wire transfer | T1566.002 | Critical | None |
| 6 | Invoice / payment | T1566.001 | Medium | None |
| 7 | Delivery / shipping | T1566.001 | Low | None |
| 8 | MFA reset | T1566.002 | High | `MFA_Verification.html` |

---

## Lab Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    ISOLATED LAB NETWORK                     │
│                    172.28.0.0/24                            │
│                                                             │
│  ┌──────────────────┐     ┌──────────────────────────────┐  │
│  │ Artifact Generator│────▶│   phishing_artifacts/        │  │
│  │ (Python / PS1)    │     │   (shared volume)            │  │
│  └──────────────────┘     └────────────┬─────────────────┘  │
│                                        │                    │
│                              inject_emails.py               │
│                                        │                    │
│                                        ▼                    │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  MailHog  :1025 (SMTP)  |  :8025 (Web UI)           │   │
│  │  Captures all inbound email — nothing delivered      │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌────────────────────┐  ┌──────────────────────────────┐   │
│  │  Landing Server    │  │  Nginx                       │   │
│  │  :8080             │  │  :80 (reverse proxy + logs)  │   │
│  │  Logs click events │  │  Generates access log IOCs   │   │
│  │  Returns safe page │  └──────────────────────────────┘   │
│  └────────────────────┘                                     │
└─────────────────────────────────────────────────────────────┘
                              │
               ┌──────────────┴──────────────┐
               ▼                             ▼
      Elastic SIEM                  Microsoft Sentinel
      (bulk-load JSON)              (DCR / HTTP Collector)
               │                             │
               └──────────────┬──────────────┘
                              ▼
                         [ Qevlar ]
                    Autonomous triage,
                    enrichment, response
```

---

## Qevlar Integration

### Path 1 — Direct JSON ingest (fastest for POC)

If Qevlar accepts a REST ingest endpoint or file drop, use the pre-built payloads:

```bash
# Each file in qevlar_payloads/ is a normalized alert envelope
ls phishing_artifacts/qevlar_payloads/

# Sample structure per payload:
{
  "alert_id":          "uuid",
  "severity":          "high | critical | medium | low",
  "title":             "Business Email Compromise Pattern Detected",
  "phishing_category": "bec",
  "email_metadata":    { sender, subject, eml_file },
  "iocs":              { url, sender_domain, amount, tracking, ... },
  "mitre_mapping":     { tactic, technique },
  "enrichment_context":{ spf_pass, dkim_pass, dmarc_pass, domain_age_days, ... },
  "recommended_actions": [ ... ]
}
```

### Path 2 — Elastic SIEM ingest

Bulk-load synthetic Elastic Security alerts:

```bash
for f in phishing_artifacts/siem_alerts/elastic/*.json; do
  curl -s -X POST "http://localhost:9200/phishing-poc-simulation/_doc" \
    -H "Content-Type: application/json" \
    -d @"$f" | python3 -m json.tool | grep '"result"'
done
```

Kibana index pattern: `phishing-poc-simulation-*`

### Path 3 — Microsoft Sentinel ingest

Load into a custom log table via the HTTP Data Collector API:

```bash
WORKSPACE_ID="your-workspace-id"
SHARED_KEY="your-shared-key"

for f in phishing_artifacts/siem_alerts/sentinel/*.json; do
  python3 sentinel_ingest.py \
    --workspace-id "$WORKSPACE_ID" \
    --key "$SHARED_KEY" \
    --log-type "PhishingSimulation" \
    --file "$f"
done
```

### Filtering simulation alerts from production

All EML files contain a custom header:
```
X-Simulation-Type: PHISHING-POC-BENIGN-ECI
X-SOC-Test-ID: QEVLAR-POC-<uuid>
```

All Elastic alert JSONs contain:
```json
"labels": { "simulation": "true", "poc": "qevlar" }
```

Use these to exclude from production detection rules or create a dedicated Qevlar POC workspace.

---

## Injecting Emails into MailHog

```bash
# Default — sends all EMLs to localhost:1025
python inject_emails.py

# Custom SMTP target and delay
python inject_emails.py \
  --smtp localhost:1025 \
  --artifacts ./phishing_artifacts \
  --delay 0.5

# View in MailHog web UI
open http://localhost:8025
```

`inject_emails.py` reads the `From:` and `To:` headers from each EML and uses them as SMTP envelope sender/recipient. MailHog captures everything — no email is forwarded externally.

---

## Landing Server

Handles all `http://phishtest.internal/*` requests generated by the test artifacts.

**What it does:**
- Logs each click: timestamp, path, query params, remote IP, user-agent
- Returns a safe informational page ("You clicked a simulated phishing link")
- Writes a running click log to `/tmp/phish_clicks.json`

**What it does NOT do:**
- Does not capture form input
- Does not store credentials
- Does not make external requests

```bash
# Run standalone
python landing_server.py

# Click log location
cat /tmp/phish_clicks.json
```

---

## CLI Reference

### generate_phishing_artifacts.py

```
usage: generate_phishing_artifacts.py [options]

options:
  --output  DIR    Output directory (default: ./phishing_artifacts)
  --count   INT    Samples per category (default: 3)
  --url     URL    Test base URL for links and QR codes (default: http://phishtest.internal)
  --domain  STR    Target company email domain (default: eci.com)
```

### Generate-PhishingArtifacts.ps1

```powershell
param(
  [string] $OutputDir     = ".\phishing_artifacts"
  [string] $TestBaseUrl   = "http://phishtest.internal"
  [string] $TargetDomain  = "eci.com"
  [int]    $CountPerType  = 3
)
```

### inject_emails.py

```
usage: inject_emails.py [options]

options:
  --smtp       HOST:PORT  SMTP target (default: localhost:1025)
  --artifacts  DIR        Artifact root directory (default: ./phishing_artifacts)
  --delay      FLOAT      Seconds between sends (default: 0.5)
```

---

## Test Scenarios — Summary

Full details, validation checklists, and metric targets in `qevlar_test_scenarios.md`.

| # | Scenario | Validates |
|---|----------|-----------|
| 1 | ClickFix detection | URL IOC extraction, sender domain age |
| 2 | Credential harvest + HTML attachment | Attachment type detection, display-name spoofing |
| 3 | Quishing | Image-in-email handling, QR URL decode (if supported) |
| 4 | BEC wire transfer | Executive impersonation, no-URL phishing classification |
| 5 | Invoice phishing | Urgency-language detection, vendor allow-list check |
| 6 | Delivery notification | Low-severity auto-triage, bulk volume handling |
| 7 | MFA reset | MFA keyword detection, token extraction |
| 8 | Mixed campaign | Cross-alert campaign correlation, severity promotion |
| 9 | High-volume stress (160 alerts) | Alert fatigue reduction, P3 auto-resolution rate |
| 10 | Enrichment depth | WHOIS, VT/OTX, SPF/DKIM/DMARC, mailbox search |
| 11 | Automated response accuracy | Action appropriateness per severity, BEC escalation |
| 12 | False positive check | Benign email pass-through, over-detection rate |

**POC metric targets:**

| Metric | Target |
|--------|--------|
| MTTT P1/P2 | < 2 min |
| MTTT P3 (auto) | < 5 min |
| P3 auto-resolution rate | > 80% |
| False positive rate | < 5% |
| Campaign correlation accuracy | > 90% |
| Analyst touchpoints per 100 alerts | < 20 |
| Dropped / missed alerts | 0 |
| BEC auto-escalation accuracy | 100% |

---

## manifest.json

Every generator run produces `reports/manifest.json` — a full artifact index containing:

```json
{
  "generated_at": "2026-06-02T13:21:04Z",
  "total_artifacts": 24,
  "categories": ["bec", "clickfix", "credential_harvest", ...],
  "config": { "output_dir", "test_base_url", "target_domain" },
  "artifacts": [
    {
      "type": "bec",
      "file": "emails/bec/bec_a1b2c3d4.eml",
      "subject": "Urgent: Wire Transfer — Confidential",
      "sender": "James Wilson — CEO <james.wilson82@mfa-verify.org>",
      "date": "2026-05-14T09:26:04+00:00",
      "ioc": { "amount": "$78,000", "bank": "Citibank N.A.", "sender_domain": "mfa-verify.org" },
      "qevlar_alert_id": "910afad4b49d42c6bb470cf09d72d2ae"
    },
    ...
  ]
}
```

Use the manifest to cross-reference EML files against Qevlar alert IDs during validation.

---

## Docker Services Reference

| Service | Port | Purpose |
|---------|------|---------|
| `mailhog` | 1025 (SMTP), 8025 (UI) | Captures all inbound test email |
| `landing-server` | 8080 | Logs URL clicks, returns safe page |
| `nginx` | 80 | Reverse proxy + access log |
| `artifact-gen` | — | One-shot generator (profile: `generate`) |
| `eml-injector` | — | One-shot injector (profile: `inject`) |

```bash
# Start core services
docker-compose up -d mailhog landing-server nginx

# Run generator (one-shot)
docker-compose run --rm artifact-gen

# Run injector (one-shot)
docker-compose run --rm eml-injector

# Tail landing server click log
docker-compose logs -f landing-server

# Stop everything
docker-compose down
```

---

## Security Notes

- No artifact contains shellcode, macros, exploit code, or live malware
- All URLs in artifacts resolve to `phishtest.internal` — a non-routable internal hostname
- HTML attachment pages contain client-side only markup; no form submissions are processed server-side
- The landing server discards all POST body data
- MailHog does not relay email; it is a capture-only SMTP sink
- The `X-Simulation-Type: PHISHING-POC-BENIGN-ECI` header is present on every EML for identification and exclusion from production rules
- Recommended: run the lab on an isolated VLAN or VM with no internet access; not required, but enforces hygiene

---

*ECI SOC — Qevlar POC | Defensive Testing Infrastructure*
