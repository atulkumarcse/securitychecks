from plugins.base import OWASPPlugin

class A10OpenRedirectPlugin(OWASPPlugin):
    id = "A10"
    name = "Open Redirect Indicator"

    def scan(self, url, response, soup):
        if any(p in url.lower() for p in ["redirect=", "return=", "next="]):
            return [{
                "severity": "Medium",
                "id": self.id,
                "title": "Potential Open Redirect Parameter",
                "description": "URL contains parameters commonly used for open redirect attacks.",
                "fix": "Validate and allowlist redirect destinations."
            }]
        return []
