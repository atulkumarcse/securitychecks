from plugins.base import OWASPPlugin

class A05MisconfigPlugin(OWASPPlugin):
    id = "A05"
    name = "Security Misconfiguration"

    SECURITY_HEADERS = [
        "Content-Security-Policy",
        "X-Frame-Options",
        "Strict-Transport-Security",
        "X-Content-Type-Options"
    ]

    def scan(self, url, response, soup):
        findings = []
        missing = [h for h in self.SECURITY_HEADERS if h not in response.headers]

        if missing:
            findings.append({
                "severity": "Medium",
                "id": self.id,
                "title": "Missing Security Headers",
                "description": f"Missing headers: {', '.join(missing)}",
                "fix": "Configure security headers in web server."
            })

        server = response.headers.get("Server")
        if server:
            findings.append({
                "severity": "Low",
                "id": self.id,
                "title": "Server Header Disclosure",
                "description": f"Server header exposed: {server}",
                "fix": "Disable server version disclosure."
            })

        return findings
