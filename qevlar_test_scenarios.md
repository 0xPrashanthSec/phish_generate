# Qevlar SOC POC — Phishing Test Scenarios
**ECI SOC Team | Defensive Testing | Qevlar Evaluation**

---

## Lab Architecture

```
[Artifact Generator]
        │
        ▼
[phishing_artifacts/]
    ├── emails/         ← EML files (8 categories)
    ├── qr_codes/       ← PNG QR images
    ├── html_attachments/
    ├── siem_alerts/
    │   ├── elastic/    ← Kibana alert JSON
    │   └── sentinel/   ← SecurityAlert table JSON
    └── qevlar_payloads/ ← Normalized Qevlar input JSON

        │
        ▼ (inject_emails.py)
[MailHog :1025/:8025]   ← SMTP capture + web UI

        │
        ▼ (Elastic Filebeat / connector)
[Elastic SIEM]          ← alert fires

        │
        ▼
[Qevlar]                ← picks up alert, investigates autonomously
```

**Isolated network:** All test URLs resolve to `phishtest.internal` → landing server (port 8080). No external traffic.

---

## Setup Checklist

```bash
# 1. Start lab
cd lab_setup
docker-compose up -d mailhog landing-server nginx

# 2. Generate artifacts
docker-compose run --rm artifact-gen --count 5

# 3. Install Python deps (if running locally)
pip install qrcode[pil] Pillow

# 4. Generate locally
python scripts/generate_phishing_artifacts.py \
  --count 5 \
  --url http://phishtest.internal \
  --domain eci.com

# 5. Inject into MailHog
python scripts/inject_emails.py \
  --smtp localhost:1025 \
  --artifacts ./phishing_artifacts

# 6. Verify in MailHog
open http://localhost:8025
```

---

## Test Scenario Matrix

### Scenario 1 — ClickFix Detection & Triage

**Category:** ClickFix lure  
**MITRE:** T1566.001  
**Severity:** High

**Setup:**
- Inject `emails/clickfix/*.eml` into MailHog
- Load `siem_alerts/elastic/clickfix_*.json` into Elastic
- OR use `qevlar_payloads/clickfix_*.json` directly if Qevlar accepts raw JSON

**What Qevlar should do:**
- Detect PowerShell/MSHTA URL in email body
- Extract URL IOC (`/clickfix?id=...`)
- Correlate sender domain (newly registered, no SPF/DKIM/DMARC)
- Produce verdict: malicious
- Recommend: quarantine + block sender domain + search for similar subjects

**Validation checks:**
- [ ] Qevlar auto-triaged without analyst intervention
- [ ] URL extracted and flagged
- [ ] Sender domain flagged as suspicious (age < 30 days)
- [ ] MITRE T1566.001 tag applied
- [ ] Recommended actions include inbox search across all recipients

**Edge case:** Run two ClickFix emails with identical sender domains — verify Qevlar correlates them as a campaign.

---

### Scenario 2 — Credential Harvest with HTML Attachment

**Category:** Credential harvesting + HTML attachment  
**MITRE:** T1566.001 / T1056.003  
**Severity:** High

**Setup:**
- Inject `emails/credential_harvest/*.eml`
- HTML attachment `SecureDocument.html` is base64-encoded in the EML

**What Qevlar should do:**
- Detect HTML attachment type
- Identify embedded link to credential page in body
- Flag SPF/DKIM fail
- Detect sender domain mismatch (claim: Microsoft; actual: `microsoft-security.com`)
- Produce verdict: credential phishing

**Validation checks:**
- [ ] HTML attachment type flagged
- [ ] Sender spoofing detected (display name vs envelope mismatch)
- [ ] Link IOC extracted from both body AND attachment
- [ ] Recommended action includes notifying potential victims

**Edge case:** Send three credential_harvest emails with slight subject variations to same recipient. Verify Qevlar groups them as a campaign rather than treating as isolated alerts.

---

### Scenario 3 — Quishing (QR Code Phishing)

**Category:** Quishing  
**MITRE:** T1566.001  
**Severity:** Medium

**Setup:**
- Inject `emails/quishing/*.eml` (QR code embedded as inline image)
- QR codes in `qr_codes/` point to `http://phishtest.internal/qr?...`

**What Qevlar should do:**
- Detect inline image in email (Content-ID embedded)
- If QR scanning is in enrichment chain — decode QR URL
- Correlate QR URL with phishing indicator
- Flag sender domain age and email auth failures

**Validation checks:**
- [ ] Image attachment detected in email body
- [ ] If Qevlar has QR decode capability → URL extracted from QR
- [ ] If not → alert escalated for analyst review (not auto-closed)
- [ ] No false negative (Qevlar does not pass as benign)

**Note:** Quishing is specifically designed to bypass URL-scanning email gateways. Key test: verify Qevlar flags the alert even without a URL in the text body. This validates detection depth beyond gateway-relay alerts.

---

### Scenario 4 — BEC Wire Transfer

**Category:** BEC — executive impersonation  
**MITRE:** T1566.002  
**Severity:** Critical

**Setup:**
- Inject `emails/bec/*.eml` (from address mimics exec, sent to finance@)
- No URL in email — pure social engineering

**What Qevlar should do:**
- Detect executive display name in From field
- Identify envelope vs display-name mismatch
- Detect wire transfer keywords (`wire`, `transfer`, `urgent`, `confidential`)
- Flag: no link/attachment, but high-risk content + sender spoofing
- Verdict: BEC / social engineering
- Escalate to human analyst (do NOT auto-remediate)

**Validation checks:**
- [ ] Executive impersonation detected via display name analysis
- [ ] Wire transfer keyword detection triggered
- [ ] No URL present — Qevlar still classifies as phishing (not benign)
- [ ] Escalation to human analyst vs auto-close
- [ ] Recommended action: verify with exec via separate channel

**Critical test:** Auto-response behavior. Qevlar should NOT auto-send a reply or take financial action. Verify it produces a recommendation and waits for approval.

---

### Scenario 5 — Invoice Phishing with Urgency

**Category:** Invoice/payment phishing  
**MITRE:** T1566.002  
**Severity:** Medium

**Setup:**
- Inject `emails/invoice/*.eml`
- Payment URL in body (`/invoice?inv=INV-XXXXX`)

**What Qevlar should do:**
- Extract invoice number and URL
- Detect urgency language (`overdue`, `48 hours`, `pay now`)
- Check sender domain — not a known vendor
- Produce verdict: invoice phishing
- Recommended action: verify invoice with finance team via known channel

**Validation checks:**
- [ ] URL extracted and categorized
- [ ] Urgency-language detection triggered
- [ ] Sender domain not in approved vendor list (if Qevlar supports allow-list)
- [ ] Triage time recorded for SLA measurement

---

### Scenario 6 — Delivery Notification Phishing

**Category:** Delivery / shipping  
**MITRE:** T1566.001  
**Severity:** Low

**Setup:**
- Inject `emails/delivery/*.eml`

**What Qevlar should do:**
- Detect parcel/customs fee language
- Extract tracking number and payment URL
- Sender domain does not match claimed carrier (FedEx, DHL)
- Verdict: delivery phishing
- Severity: Low (no credential/financial risk at attachment stage)

**Validation checks:**
- [ ] Correctly classified as phishing, not as junk/spam
- [ ] Severity assigned as Low (not over-escalated)
- [ ] Auto-quarantine triggered without analyst
- [ ] Triage completed within SLA

**Note:** Delivery phishing volume is high. Key metric: can Qevlar handle 50+ of these without alert fatigue? Test with `--count 20` to generate bulk volume.

---

### Scenario 7 — MFA Reset / Account Verification

**Category:** MFA reset phishing  
**MITRE:** T1566.002 / T1111  
**Severity:** High

**Setup:**
- Inject `emails/mfa_reset/*.eml`
- Contains HTML attachment (`MFA_Verification.html`) + body link
- Urgency markers: "expires in 15 minutes"

**What Qevlar should do:**
- Detect MFA reset language + HTML attachment
- Extract verification URL + token parameter
- Flag: sender domain is not internal IT domain
- Flag: token-based URL with expiry pressure
- Verdict: MFA phishing — high confidence

**Validation checks:**
- [ ] MFA/authentication keywords detected
- [ ] HTML attachment type identified
- [ ] Token extracted from URL IOC
- [ ] Sender domain flagged as external (not `eci.com` or known IT vendor)
- [ ] Alert auto-escalated — not silently dropped

---

### Scenario 8 — Mixed Campaign Detection

**Category:** Multi-type campaign correlation  
**MITRE:** TA0001 (campaign)  
**Severity:** Critical (campaign-level)

**Setup:**
- Inject 3 emails across different types but sharing the same sender domain:
  - `clickfix_*.eml`
  - `credential_harvest_*.eml`  
  - `mfa_reset_*.eml`
- All use the same sender domain from `SenderDomains[]`

**What Qevlar should do:**
- Identify shared sender domain across all three alerts
- Group into a coordinated campaign
- Escalate campaign-level severity even if individual alerts are Medium
- Search for additional emails from that domain across all mailboxes
- Produce campaign IOC package: domain, URLs, subjects

**Validation checks:**
- [ ] Campaign grouping triggered
- [ ] Severity promoted from Medium → Critical at campaign level
- [ ] Mailbox-wide search initiated
- [ ] Single analyst notification (not 3 separate tickets)
- [ ] IOC package exportable

---

### Scenario 9 — High Volume / Alert Fatigue Validation

**Category:** Volume stress test  
**Severity:** P3 bulk (low/medium)

**Setup:**
```bash
python generate_phishing_artifacts.py --count 20
python inject_emails.py --smtp localhost:1025 --delay 0.1
```
- Injects ~160 phishing emails across 8 categories in under 2 minutes
- Mix of Low (delivery), Medium (invoice, quishing), High (credential, MFA)

**What Qevlar should do:**
- Auto-triage Low severity without human queue
- Batch similar alerts (same type, same sender domain) into groups
- Surface only High/Critical to analyst dashboard
- P3 (Low/Medium) tickets auto-resolved or auto-queued

**Validation checks:**
- [ ] P3 volume processed without analyst intervention
- [ ] High/Critical still escalated correctly in high-volume conditions
- [ ] No dropped alerts (all 160 accounted for in Qevlar)
- [ ] Triage time per alert — measure against baseline
- [ ] Compare analyst ticket load: before Qevlar vs with Qevlar

**Metric target:**
- Mean time to triage (MTTT) < 2 min for P1/P2
- P3 auto-resolution rate > 80%
- False positive rate < 5%

---

### Scenario 10 — Enrichment Depth Validation

**Category:** Enrichment quality  
**Purpose:** Validate Qevlar's external enrichment chain

**For each phishing type, verify Qevlar pulls:**

| Enrichment Source      | Expected Output                          |
|------------------------|------------------------------------------|
| Domain WHOIS           | Sender domain registration date          |
| VirusTotal / OTX       | URL/domain reputation                    |
| SPF/DKIM/DMARC check   | Authentication failures                  |
| Sender history         | First-seen in tenant                     |
| Similar subjects       | Prior 30-day mailbox search              |
| Attachment hash        | HTML file hash checked against intel     |
| MITRE mapping          | Correct technique applied per type       |

**Validation:**
- [ ] Enrichment present for all alert types
- [ ] Enrichment does not add > 5 min latency
- [ ] Missing enrichment sources are flagged (not silently skipped)

---

### Scenario 11 — Automated Response Validation

**Category:** Response action accuracy  
**Purpose:** Validate Qevlar doesn't over-respond or under-respond

| Phishing Type        | Expected Automated Action         | Should Require Approval? |
|----------------------|-----------------------------------|--------------------------|
| Delivery (Low)       | Quarantine + block domain         | No                       |
| Invoice (Medium)     | Quarantine + notify finance       | No                       |
| Credential (High)    | Quarantine + force PW reset       | Yes (PW reset)           |
| BEC (Critical)       | Quarantine + human escalation     | Yes (always)             |
| MFA Reset (High)     | Quarantine + disable MFA change   | Yes                      |
| ClickFix (High)      | Quarantine + endpoint IOC push    | Depends on config        |

**Validation:**
- [ ] Low/Medium severity: auto-remediated without analyst
- [ ] High severity: recommended but awaiting approval
- [ ] Critical (BEC): never auto-remediated — always escalated
- [ ] Response actions are reversible (soft-quarantine, not permanent delete)

---

### Scenario 12 — False Positive Check

**Category:** Benign email handling  
**Purpose:** Verify Qevlar does not flag legitimate email patterns

**Test emails to send (manually craft):**
1. Legitimate DocuSign notification from `docusign.com` (real domain) about a contract
2. Internal IT password reset from `eci.com` domain
3. Vendor invoice from a known/allowlisted vendor domain
4. FedEx tracking from `fedex.com` (real domain, real tracking format)

**Validation:**
- [ ] None of the above trigger phishing alerts
- [ ] If any trigger, review detection logic for over-broad patterns
- [ ] Measure false positive rate against Scenario 9 volume

---

## Metrics Dashboard — POC Scorecard

| Metric                              | Target         | Measured |
|-------------------------------------|----------------|----------|
| Mean Time to Triage (MTTT) P1/P2    | < 2 min        |          |
| Mean Time to Triage P3              | < 5 min (auto) |          |
| P3 Auto-Resolution Rate             | > 80%          |          |
| False Positive Rate                 | < 5%           |          |
| Campaign Correlation Accuracy       | > 90%          |          |
| Enrichment Coverage (sources hit)   | > 5 per alert  |          |
| Analyst Touchpoints per 100 alerts  | < 20           |          |
| Alert Dropped / Missed              | 0              |          |
| BEC Auto-Escalation Accuracy        | 100%           |          |

---

## Elastic Index Mapping for Qevlar Integration

If ingesting from Elastic, use this index pattern for synthetic alerts:

```
Index: phishing-poc-simulation-*
Pipeline: ingest_phishing_poc
```

Kibana import command for synthetic alerts:
```bash
# Bulk-import Elastic alert JSONs
for f in phishing_artifacts/siem_alerts/elastic/*.json; do
  curl -X POST "localhost:9200/phishing-poc-simulation/_doc" \
    -H "Content-Type: application/json" \
    -d @"$f"
done
```

Sentinel: import JSONs into a custom `SecurityAlerts_Simulation_CL` custom log table via Data Collection Rule (DCR) or Log Analytics HTTP Data Collector API.

---

## Notes

- All EML files contain `X-Simulation-Type: PHISHING-POC-BENIGN-ECI` header — use this to filter in Qevlar or exclude from production alert rules
- All URLs resolve to `phishtest.internal` — this hostname must resolve to `127.0.0.1` or lab landing server IP in your `/etc/hosts` or internal DNS
- Add `127.0.0.1 phishtest.internal` to `/etc/hosts` on any machine that will click test links
- None of the HTML attachment pages capture or exfiltrate any data
