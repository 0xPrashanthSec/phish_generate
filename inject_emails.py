#!/usr/bin/env python3
"""
EML Injector — sends generated phishing simulations to MailHog
ECI SOC Team — Qevlar POC
"""
import os
import smtplib
import argparse
import glob
import time
from email import message_from_string

def inject_emls(smtp_host: str, smtp_port: int, artifacts_dir: str, delay: float):
    eml_files = sorted(glob.glob(os.path.join(artifacts_dir, "emails/**/*.eml"), recursive=True))
    if not eml_files:
        print(f"[!] No EML files found under {artifacts_dir}/emails/")
        return

    print(f"[+] Connecting to {smtp_host}:{smtp_port}")
    print(f"[+] Found {len(eml_files)} EML files\n")

    success = fail = 0
    with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as smtp:
        for fpath in eml_files:
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    raw = f.read()
                msg = message_from_string(raw)
                sender = msg["From"].split("<")[-1].rstrip(">").strip()
                recipient = msg["To"].split("<")[-1].rstrip(">").strip()
                smtp.sendmail(sender, recipient, raw)
                print(f"  [+] SENT  {os.path.basename(fpath)}")
                success += 1
                time.sleep(delay)
            except Exception as e:
                print(f"  [!] FAIL  {os.path.basename(fpath)}: {e}")
                fail += 1

    print(f"\n[+] Injected: {success} | Failed: {fail}")
    print(f"[+] View emails: http://localhost:8025")

if __name__ == "__main__":
    p = argparse.ArgumentParser(description="EML Injector — ECI Qevlar POC")
    p.add_argument("--smtp", default="localhost:1025")
    p.add_argument("--artifacts", default="./phishing_artifacts")
    p.add_argument("--delay", type=float, default=0.5, help="Seconds between sends")
    args = p.parse_args()
    host, port = args.smtp.rsplit(":", 1)
    inject_emls(host, int(port), args.artifacts, args.delay)
