from plugins.base import OWASPPlugin

class A02CryptoPlugin(OWASPPlugin):
    id = "A02"
    name = "Cryptographic Failures"

    def scan(self, url, response, soup):
        findings = []

        if not url.startswith("https://"):
            findings.append({
                "severity": "High",
                "id": self.id,
                "title": "HTTPS Not Enabled",
                "description": "Application does not enforce encrypted communication.",
                "fix": "Enable HTTPS using TLS certificates."
            })

        return findings
