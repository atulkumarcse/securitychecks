import re
from plugins.base import OWASPPlugin

class A01AccessControlPlugin(OWASPPlugin):
    id = "A01"
    name = "Broken Access Control"

    ID_PATTERN = re.compile(r"[?&](id|user|account|order)=\d+", re.IGNORECASE)

    def scan(self, url, response, soup):
        findings = []

        if self.ID_PATTERN.search(url):
            auth_headers = ["Authorization", "Cookie"]
            has_auth = any(h in response.request.headers for h in auth_headers)

            if not has_auth:
                findings.append({
                    "severity": "High",
                    "id": self.id,
                    "title": "Potential IDOR Detected",
                    "description": "Numeric object identifier found in URL without authentication indicators.",
                    "fix": "Enforce authorization checks on object-level access."
                })

        return findings
