"""
modules/url_analyser.py — URL Analysis Module
Author: Tobi Bolaji (@hijay166)
"""

import re
import time
from urllib.parse import urlparse

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


SUSPICIOUS_EXTENSIONS = [".exe", ".dll", ".bat", ".ps1", ".vbs", ".hta", ".msi", ".scr"]
URL_SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "ow.ly", "goo.gl", "is.gd", "buff.ly"]


class URLAnalyser:
    def __init__(self, vt_key: str = None):
        self.vt_key = vt_key
        self._vt_cache = {}

    def _check_virustotal(self, url: str) -> dict:
        if not HAS_REQUESTS or not self.vt_key:
            return {}
        if url in self._vt_cache:
            return self._vt_cache[url]

        try:
            import base64
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            resp = requests.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers={"x-apikey": self.vt_key},
                timeout=15
            )
            if resp.status_code == 200:
                data = resp.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                result = {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "total": sum(stats.values()),
                }
                self._vt_cache[url] = result
                time.sleep(15)  # VT free tier rate limit
                return result
        except Exception as e:
            pass
        return {}

    def _resolve_redirect(self, url: str) -> str:
        if not HAS_REQUESTS:
            return url
        try:
            resp = requests.head(url, allow_redirects=True, timeout=10, verify=False)
            return resp.url
        except Exception:
            return url

    def analyse(self, url: str) -> dict:
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path

        is_shortener = any(s in domain for s in URL_SHORTENERS)
        suspicious_ext = any(path.lower().endswith(ext) for ext in SUSPICIOUS_EXTENSIONS)

        # Resolve redirects
        final_url = url
        if is_shortener:
            final_url = self._resolve_redirect(url)

        vt_result = self._check_virustotal(final_url)

        # Risk assessment
        risk_factors = []
        if vt_result.get("malicious", 0) > 0:
            risk_factors.append(f"VirusTotal: {vt_result['malicious']}/{vt_result.get('total', '?')} flagged MALICIOUS")
        if is_shortener:
            risk_factors.append("URL shortener used (obfuscation)")
        if suspicious_ext:
            risk_factors.append(f"Suspicious file extension in URL")
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
            risk_factors.append("IP address used instead of domain (suspicious)")

        # Risk level
        malicious_count = vt_result.get("malicious", 0)
        if malicious_count > 10 or (suspicious_ext and malicious_count > 0):
            risk_level = "CRITICAL"
        elif malicious_count > 3 or (is_shortener and malicious_count > 0):
            risk_level = "HIGH"
        elif malicious_count > 0 or len(risk_factors) >= 2:
            risk_level = "MEDIUM"
        elif risk_factors:
            risk_level = "LOW"
        else:
            risk_level = "CLEAN"

        return {
            "url": url,
            "final_url": final_url,
            "domain": domain,
            "is_shortener": is_shortener,
            "suspicious_extension": suspicious_ext,
            "vt_result": vt_result,
            "risk_factors": risk_factors,
            "risk_level": risk_level,
        }
