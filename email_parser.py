"""
modules/email_parser.py — Email Parser Module
Author: Tobi Bolaji (@hijay166)

Parses .eml files to extract headers, body, URLs, and attachments.
"""

import email
import email.policy
import hashlib
import re
from email.header import decode_header
from urllib.parse import urlparse


class EmailParser:
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.msg = None

    def _load(self):
        with open(self.filepath, "rb") as f:
            self.msg = email.message_from_bytes(f.read(), policy=email.policy.default)

    def _decode_header_value(self, value: str) -> str:
        if not value:
            return ""
        decoded_parts = decode_header(value)
        result = []
        for part, charset in decoded_parts:
            if isinstance(part, bytes):
                try:
                    result.append(part.decode(charset or "utf-8", errors="ignore"))
                except Exception:
                    result.append(part.decode("utf-8", errors="ignore"))
            else:
                result.append(str(part))
        return " ".join(result)

    def _extract_urls(self, text: str) -> list:
        url_pattern = re.compile(
            r'https?://[^\s<>"\')\]]+|'
            r'http?://[^\s<>"\')\]]+'
        )
        urls = list(set(url_pattern.findall(text)))
        # Clean trailing punctuation
        urls = [re.sub(r'[.,;:!?\'")\]>]+$', '', url) for url in urls]
        return [u for u in urls if len(u) > 10]

    def _get_body(self) -> str:
        body = ""
        if self.msg.is_multipart():
            for part in self.msg.walk():
                content_type = part.get_content_type()
                if content_type in ("text/plain", "text/html"):
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            body += payload.decode("utf-8", errors="ignore")
                    except Exception:
                        pass
        else:
            payload = self.msg.get_payload(decode=True)
            if payload:
                body = payload.decode("utf-8", errors="ignore")
        return body

    def _get_attachments(self) -> list:
        attachments = []
        for part in self.msg.walk():
            if part.get_content_disposition() == "attachment":
                filename = part.get_filename() or "unknown"
                data = part.get_payload(decode=True) or b""
                sha256 = hashlib.sha256(data).hexdigest()
                md5 = hashlib.md5(data).hexdigest()
                attachments.append({
                    "filename": filename,
                    "size_bytes": len(data),
                    "sha256": sha256,
                    "md5": md5,
                    "data": data,
                    "content_type": part.get_content_type(),
                })
        return attachments

    def _extract_domain(self, email_addr: str) -> str:
        match = re.search(r"@([\w.\-]+)", email_addr)
        return match.group(1) if match else ""

    def _check_spf_dkim_dmarc(self) -> dict:
        auth_results = self.msg.get("Authentication-Results", "")
        received_spf = self.msg.get("Received-SPF", "")

        def find_result(text, keyword):
            pattern = rf'{keyword}=(\w+)'
            match = re.search(pattern, text, re.IGNORECASE)
            return match.group(1).upper() if match else "NOT FOUND"

        combined = auth_results + " " + received_spf
        return {
            "spf": find_result(combined, "spf"),
            "dkim": find_result(combined, "dkim"),
            "dmarc": find_result(combined, "dmarc"),
        }

    def parse(self) -> dict:
        self._load()

        sender = self._decode_header_value(self.msg.get("From", ""))
        reply_to = self._decode_header_value(self.msg.get("Reply-To", ""))
        to = self._decode_header_value(self.msg.get("To", ""))
        subject = self._decode_header_value(self.msg.get("Subject", ""))
        date = self.msg.get("Date", "")
        message_id = self.msg.get("Message-ID", "")

        sender_domain = self._extract_domain(sender)
        reply_to_domain = self._extract_domain(reply_to) if reply_to else ""

        body = self._get_body()
        urls = self._extract_urls(body)
        attachments = self._get_attachments()
        auth = self._check_spf_dkim_dmarc()

        # Check for reply-to mismatch (common in BEC/phishing)
        reply_mismatch = (
            reply_to_domain and
            reply_to_domain != sender_domain and
            bool(reply_to)
        )

        return {
            "filepath": self.filepath,
            "sender": sender,
            "sender_domain": sender_domain,
            "reply_to": reply_to,
            "reply_to_domain": reply_to_domain,
            "reply_to_mismatch": reply_mismatch,
            "to": to,
            "subject": subject,
            "date": date,
            "message_id": message_id,
            "body_length": len(body),
            "urls": urls,
            "url_count": len(urls),
            "attachments": attachments,
            "attachment_count": len(attachments),
            "spf": auth["spf"],
            "dkim": auth["dkim"],
            "dmarc": auth["dmarc"],
        }
