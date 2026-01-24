from plugins.base import OWASPPlugin

class A06ComponentPlugin(OWASPPlugin):
    id = "A06"
    name = "Vulnerable Components"

    def scan(self, url, response, soup):
        findings = []
        scripts = [s.get("src") for s in soup.find_all("script") if s.get("src")]

        if len(scripts) > 5:
            findings.append({
                "severity": "Low",
                "id": self.id,
                "title": "Multiple Third-Party Scripts",
                "description": f"{len(scripts)} external scripts detected.",
                "fix": "Audit dependencies and apply SRI hashes."
            })

        return findings
