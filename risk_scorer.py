"""
modules/risk_scorer.py — Composite Risk Scoring
Author: Tobi Bolaji (@hijay166)
"""


class RiskScorer:
    """
    Calculates a 0–100 composite risk score based on email, URL,
    attachment, and WHOIS signals.
    """

    def calculate(self, email_data: dict, url_results: list,
                  hash_results: list, whois_result: dict) -> dict:
        score = 0
        factors = []

        # ── Email Header Signals ──────────────────────────────────────
        if email_data.get("spf") in ("FAIL", "SOFTFAIL"):
            score += 15
            factors.append(f"SPF {email_data['spf']} (-15 pts)")
        if email_data.get("dkim") == "FAIL":
            score += 10
            factors.append("DKIM FAIL (-10 pts)")
        if email_data.get("dmarc") == "FAIL":
            score += 10
            factors.append("DMARC FAIL (-10 pts)")
        if email_data.get("reply_to_mismatch"):
            score += 15
            factors.append("Reply-To domain mismatch — possible BEC (-15 pts)")

        # ── WHOIS / Domain Age ────────────────────────────────────────
        domain_age_days = whois_result.get("domain_age_days", 9999)
        if domain_age_days < 7:
            score += 20
            factors.append(f"Sender domain only {domain_age_days} days old (-20 pts)")
        elif domain_age_days < 30:
            score += 10
            factors.append(f"Sender domain only {domain_age_days} days old (-10 pts)")

        # ── URL Signals ───────────────────────────────────────────────
        for url_result in url_results:
            level = url_result.get("risk_level", "CLEAN")
            if level == "CRITICAL":
                score += 25
                factors.append(f"URL flagged CRITICAL: {url_result['url'][:60]}")
            elif level == "HIGH":
                score += 15
                factors.append(f"URL flagged HIGH risk: {url_result['url'][:60]}")
            elif level == "MEDIUM":
                score += 8
                factors.append(f"URL flagged MEDIUM risk")

        # ── Attachment Signals ────────────────────────────────────────
        for hash_result in hash_results:
            malicious = hash_result.get("vt_result", {}).get("malicious", 0)
            if malicious > 5:
                score += 30
                factors.append(f"Attachment MALWARE detected: {hash_result['filename']} ({malicious} engines)")
            elif malicious > 0:
                score += 20
                factors.append(f"Attachment suspicious: {hash_result['filename']} ({malicious} engines)")
            elif hash_result.get("suspicious_extension"):
                score += 10
                factors.append(f"Attachment has suspicious extension: {hash_result['filename']}")

        # Cap at 100
        score = min(score, 100)

        # Determine level
        if score >= 70:
            level = "CRITICAL"
            emoji = "🔴"
        elif score >= 45:
            level = "HIGH"
            emoji = "🟠"
        elif score >= 20:
            level = "MEDIUM"
            emoji = "🟡"
        else:
            level = "LOW"
            emoji = "🟢"

        # Recommended actions
        actions = []
        if score >= 70:
            actions = [
                "BLOCK sender domain on email gateway",
                "QUARANTINE email from all mailboxes",
                "BLOCK malicious URLs on web proxy",
                "ALERT affected users immediately",
                "ESCALATE to Tier 2 SOC analyst",
                "Preserve email as evidence",
            ]
        elif score >= 45:
            actions = [
                "QUARANTINE suspicious email",
                "BLOCK sender domain",
                "WARN affected users",
                "Review for similar emails in last 30 days",
            ]
        elif score >= 20:
            actions = [
                "Monitor sender domain",
                "WARN user who received the email",
                "Add sender to watchlist",
            ]
        else:
            actions = ["Log and monitor — no immediate action required"]

        return {
            "score": score,
            "level": level,
            "emoji": emoji,
            "factors": factors,
            "recommended_actions": actions,
        }


# ─────────────────────────────────────────────────────────────────────────────


"""
modules/reporter.py — Report Generator
Author: Tobi Bolaji (@hijay166)
"""

from datetime import datetime
from pathlib import Path


class Reporter:
    def generate(self, email_path, email_data, url_results,
                 hash_results, whois_result, risk) -> dict:
        return {
            "generated": datetime.now().isoformat(),
            "email_file": Path(email_path).name,
            "email_data": email_data,
            "url_results": url_results,
            "hash_results": hash_results,
            "whois": whois_result,
            "risk": risk,
        }

    def print_report(self, report: dict):
        email = report["email_data"]
        risk = report["risk"]

        print("\n" + "=" * 62)
        print("  PHISHING TRIAGE REPORT")
        print(f"  Email    : {report['email_file']}")
        print(f"  Analysed : {report['generated'][:19]}")
        print("=" * 62)

        print("\n[SENDER]")
        print(f"  From        : {email.get('sender', 'N/A')}")
        if email.get("reply_to"):
            mismatch = " ⚠️ MISMATCH" if email.get("reply_to_mismatch") else ""
            print(f"  Reply-To    : {email['reply_to']}{mismatch}")
        print(f"  Subject     : {email.get('subject', 'N/A')}")
        print(f"  SPF         : {email.get('spf', 'N/A')}")
        print(f"  DKIM        : {email.get('dkim', 'N/A')}")
        print(f"  DMARC       : {email.get('dmarc', 'N/A')}")

        domain_age = report["whois"].get("domain_age_days")
        if domain_age is not None:
            flag = " ⚠️ SUSPICIOUS" if domain_age < 30 else ""
            print(f"  Domain Age  : {domain_age} days{flag}")

        # URLs
        url_results = report["url_results"]
        print(f"\n[URLS] — {len(url_results)} found")
        for i, u in enumerate(url_results, 1):
            level = u.get("risk_level", "CLEAN")
            emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟡", "CLEAN": "🟢"}.get(level, "⚪")
            print(f"  [{i}] {u['url'][:70]}")
            vt = u.get("vt_result", {})
            if vt.get("malicious", 0) > 0:
                print(f"      VirusTotal : {vt['malicious']}/{vt.get('total', '?')} MALICIOUS")
            if u.get("is_shortener") and u["final_url"] != u["url"]:
                print(f"      Resolves → : {u['final_url'][:70]}")
            print(f"      Risk       : {emoji} {level}")

        # Attachments
        hash_results = report["hash_results"]
        if hash_results:
            print(f"\n[ATTACHMENTS] — {len(hash_results)} found")
            for i, h in enumerate(hash_results, 1):
                vt = h.get("vt_result", {})
                mal = vt.get("malicious", 0)
                emoji = "🔴" if mal > 5 else ("🟠" if mal > 0 else "🟢")
                print(f"  [{i}] {h['filename']}")
                print(f"      SHA256 : {h.get('sha256', 'N/A')[:20]}...")
                if mal > 0:
                    print(f"      VT     : {emoji} {mal}/{vt.get('total', '?')} engines flagged")

        # Risk score
        print(f"\n[RISK SCORE]  {risk['score']}/100 — {risk['emoji']} {risk['level']}")

        if risk["factors"]:
            print("\n[RISK FACTORS]")
            for f in risk["factors"]:
                print(f"  • {f}")

        print("\n[RECOMMENDED ACTIONS]")
        for action in risk["recommended_actions"]:
            print(f"  ✅ {action}")

        print("\n" + "=" * 62)
