#!/usr/bin/env python3
"""
triage.py — Phishing Email Triage Automation Bot
Author: Tobi Bolaji (@hijay166)

Analyses suspicious emails and produces risk-scored triage reports.

Usage:
    python3 triage.py --email suspicious.eml --vt-key YOUR_KEY
    python3 triage.py --folder ./inbox/ --vt-key YOUR_KEY --output results.json
"""

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

from modules.email_parser import EmailParser
from modules.url_analyser import URLAnalyser
from modules.hash_checker import HashChecker
from modules.whois_lookup import WhoisLookup
from modules.risk_scorer import RiskScorer
from modules.reporter import Reporter


def analyse_email(eml_path: str, vt_key: str = None) -> dict:
    """Analyse a single .eml file and return structured results."""

    print(f"\n[*] Analysing: {Path(eml_path).name}")

    # 1. Parse email
    parser = EmailParser(eml_path)
    email_data = parser.parse()

    # 2. Analyse URLs
    url_results = []
    analyser = URLAnalyser(vt_key=vt_key)
    for url in email_data.get("urls", []):
        result = analyser.analyse(url)
        url_results.append(result)

    # 3. Check attachment hashes
    hash_results = []
    checker = HashChecker(vt_key=vt_key)
    for attachment in email_data.get("attachments", []):
        result = checker.check(attachment["filename"], attachment["data"])
        hash_results.append(result)

    # 4. WHOIS on sender domain
    whois_result = {}
    if email_data.get("sender_domain"):
        whois = WhoisLookup()
        whois_result = whois.lookup(email_data["sender_domain"])

    # 5. Calculate risk score
    scorer = RiskScorer()
    risk = scorer.calculate(
        email_data=email_data,
        url_results=url_results,
        hash_results=hash_results,
        whois_result=whois_result,
    )

    # 6. Generate report
    reporter = Reporter()
    report = reporter.generate(
        email_path=eml_path,
        email_data=email_data,
        url_results=url_results,
        hash_results=hash_results,
        whois_result=whois_result,
        risk=risk,
    )

    reporter.print_report(report)

    return report


def main():
    parser = argparse.ArgumentParser(
        description="Phishing Email Triage Bot",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 triage.py --email suspicious.eml
  python3 triage.py --email suspicious.eml --vt-key abc123
  python3 triage.py --folder ./inbox/ --vt-key abc123 --output batch_results.json
        """
    )
    parser.add_argument("--email", help="Path to single .eml file")
    parser.add_argument("--folder", help="Path to folder of .eml files (batch mode)")
    parser.add_argument("--vt-key", help="VirusTotal API key (optional but recommended)")
    parser.add_argument("--output", help="Save results to JSON file")
    parser.add_argument("--min-score", type=int, default=0,
                        help="Only report emails with risk score >= this value")

    args = parser.parse_args()

    if not args.email and not args.folder:
        parser.print_help()
        sys.exit(1)

    results = []

    if args.email:
        if not os.path.exists(args.email):
            print(f"[!] File not found: {args.email}")
            sys.exit(1)
        result = analyse_email(args.email, vt_key=args.vt_key)
        results.append(result)

    elif args.folder:
        eml_files = list(Path(args.folder).glob("*.eml"))
        if not eml_files:
            print(f"[!] No .eml files found in: {args.folder}")
            sys.exit(1)

        print(f"[*] Found {len(eml_files)} emails to analyse")

        for eml_path in eml_files:
            try:
                result = analyse_email(str(eml_path), vt_key=args.vt_key)
                if result.get("risk", {}).get("score", 0) >= args.min_score:
                    results.append(result)
            except Exception as e:
                print(f"[!] Error analysing {eml_path.name}: {e}")

    # Summary
    if len(results) > 1:
        print(f"\n{'='*60}")
        print(f"  BATCH SUMMARY — {len(results)} emails analysed")
        print(f"{'='*60}")
        critical = sum(1 for r in results if r.get("risk", {}).get("level") == "CRITICAL")
        high = sum(1 for r in results if r.get("risk", {}).get("level") == "HIGH")
        medium = sum(1 for r in results if r.get("risk", {}).get("level") == "MEDIUM")
        low = sum(1 for r in results if r.get("risk", {}).get("level") == "LOW")
        print(f"  🔴 Critical : {critical}")
        print(f"  🟠 High     : {high}")
        print(f"  🟡 Medium   : {medium}")
        print(f"  🟢 Low      : {low}")

    # Save output
    if args.output:
        output = {
            "generated": datetime.now().isoformat(),
            "total_emails": len(results),
            "results": results,
        }
        with open(args.output, "w") as f:
            json.dump(output, f, indent=2, default=str)
        print(f"\n[+] Results saved to: {args.output}")


if __name__ == "__main__":
    main()
