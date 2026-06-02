#!/usr/bin/env python3
"""
Phishing Simulation Landing Server
Internal SOC Team — Phishing Simulation Lab
Logs click events. Does NOT capture or store any credentials.
"""
import json
import logging
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import os

LOG_FILE = os.environ.get("CLICK_LOG", "/tmp/phish_clicks.json")
PORT     = int(os.environ.get("PORT", 8080))
clicks   = []

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(message)s")


SAFE_RESPONSE = """<!DOCTYPE html>
<html><head><title>Phishing Simulation — Test Complete</title>
<style>body{font-family:Arial;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;background:#f0fdf4}
.card{background:#fff;padding:40px;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,.1);max-width:480px;text-align:center}
h2{color:#16a34a}p{color:#374151;font-size:14px}</style></head>
<body><div class="card">
<h2>&#x2705; You clicked a simulated phishing link</h2>
<p>This was a <strong>controlled SOC test</strong> run by the internal security team as part of a phishing simulation exercise.</p>
<p>No credentials were captured. No data was transmitted. This click event has been logged for SOC analysis.</p>
<p style="font-size:12px;color:#6b7280;margin-top:16px;">Ref: {ref}</p>
</div></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # suppress default httpd log

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "path": parsed.path,
            "params": {k: v[0] if len(v)==1 else v for k,v in params.items()},
            "remote_addr": self.client_address[0],
            "user_agent": self.headers.get("User-Agent", ""),
            "simulation_type": params.get("t", [params.get("type", ["unknown"])[0]])[0],
        }

        clicks.append(event)
        with open(LOG_FILE, "w") as f:
            json.dump(clicks, f, indent=2)

        logging.info(f"CLICK: {event['simulation_type']} | {event['remote_addr']} | {parsed.path}")

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        ref = params.get("tid", params.get("inv", params.get("track", ["SIM"])))
        ref = ref[0] if isinstance(ref, list) else ref
        self.wfile.write(SAFE_RESPONSE.format(ref=ref).encode())

    def do_POST(self):
        # Same safe response for POST submissions — no data stored
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(SAFE_RESPONSE.format(ref="FORM-SUBMIT-SIM").encode())


if __name__ == "__main__":
    logging.info(f"Landing server on :{PORT} | Click log: {LOG_FILE}")
    HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
