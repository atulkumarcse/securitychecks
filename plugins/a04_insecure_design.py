from plugins.base import OWASPPlugin

class A04InsecureDesignPlugin(OWASPPlugin):
    id = "A04"
    name = "Insecure Design"

    RATE_LIMIT_HEADERS = [
        "X-RateLimit-Limit",
        "X-RateLimit-Remaining",
        "Retry-After"
    ]

    def scan(self, url, response, soup):
        findings = []

        if any(keyword in url.lower() for keyword in ["login", "auth", "signin"]):
            missing = [h for h in self.RATE_LIMIT_HEADERS if h not in response.headers]

            if missing:
                findings.append({
                    "severity": "Medium",
                    "id": self.id,
                    "title": "Missing Rate Limiting Indicators",
                    "description": "Authentication endpoint lacks rate-limiting headers.",
                    "fix": "Implement rate limiting to prevent brute-force attacks."
                })

        return findings
