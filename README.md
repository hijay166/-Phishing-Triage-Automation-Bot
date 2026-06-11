# -Phishing-Triage-Automation-Bot

# 🤖 Phishing Triage Automation Bot

> A Python-based SOC automation tool that analyses suspicious emails, extracts URLs and attachments, queries threat intelligence APIs, and produces an automated risk score with recommended action — reducing analyst triage time from minutes to seconds.

---

## ✨ Features

- 📧 Parses `.eml` email files (headers, body, attachments)
- 🔗 Extracts and deobfuscates URLs (handles redirects, URL shorteners)
- 🦠 Checks URLs and file hashes against VirusTotal API
- 🌐 Performs WHOIS lookups on sender domains
- 🧠 Calculates composite risk score (0–100)
- 📋 Outputs structured triage report
- 💾 Logs all results to JSON for SIEM ingestion

---

## 🚀 Quick Start

```bash
# Clone and install
git clone https://github.com/hijay166/phishing-triage-bot
cd phishing-triage-bot
pip install -r requirements.txt

# Analyse an email
python3 triage.py --email samples/suspicious.eml --vt-key YOUR_VT_API_KEY

# Batch mode (folder of .eml files)
python3 triage.py --folder samples/ --vt-key YOUR_VT_API_KEY --output results.json
```

---

## 📊 Sample Output

```
============================================================
  PHISHING TRIAGE REPORT
  Email: IT-Security-Alert.eml
  Analysed: 2025-06-01 14:23:11
============================================================

[SENDER]
  From       : security-noreply@micros0ft-alert.com
  Reply-To   : harvester@evil.ru
  SPF        : FAIL
  DKIM       : FAIL
  DMARC      : FAIL
  Domain Age : 2 days (SUSPICIOUS)

[URLS FOUND] — 2
  [1] http://micros0ft-alert.com/login
      VirusTotal : 14/86 engines flagged MALICIOUS
      Redirects  : → http://185.220.x.x/harvest.php
      Risk       : 🔴 HIGH

  [2] https://bit.ly/3xK9mPq
      Resolved   : http://192.168.phishing.xyz/form
      VirusTotal : 8/86 flagged
      Risk       : 🔴 HIGH

[ATTACHMENTS] — 1
  [1] Invoice_March_2025.doc
      SHA256     : a3f5b8...
      VirusTotal : 22/72 flagged — Trojan.Emotet
      Risk       : 🔴 CRITICAL

[RISK SCORE]  92/100 — 🔴 CRITICAL

[RECOMMENDED ACTION]
  ✅ BLOCK sender domain on email gateway
  ✅ QUARANTINE email from all mailboxes
  ✅ BLOCK URLs on web proxy
  ✅ ALERT affected users
  ✅ ESCALATE to Tier 2 — possible Emotet dropper

============================================================
```

---

## 📁 Repository Structure

```
phishing-triage-bot/
├── README.md
├── requirements.txt
├── triage.py              ← Main entry point
├── modules/
│   ├── email_parser.py    ← .eml parsing
│   ├── url_analyser.py    ← URL extraction & VT check
│   ├── hash_checker.py    ← File hash lookup
│   ├── whois_lookup.py    ← Domain age/registration
│   ├── risk_scorer.py     ← Composite risk calculation
│   └── reporter.py        ← Report generation
├── samples/               ← Sample phishing emails (sanitised)
└── results/               ← JSON output logs
```

---

## 🛠️ Requirements

```
python3 >= 3.9
requests
python-whois
dnspython
beautifulsoup4
```

---

## 🔑 API Keys Required

| API | Free Tier | Purpose |
|-----|-----------|---------|
| [VirusTotal](https://www.virustotal.com/gui/join-us) | 4 req/min | URL + hash reputation |

---

## 📌 Connect

- GitHub: [github.com/hijay166](https://github.com/hijay166)
- LinkedIn: [linkedin.com/in/tobi-bolaji-0861b218b](https://linkedin.com/in/tobi-bolaji-0861b218b/)
