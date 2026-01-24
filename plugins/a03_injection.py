from plugins.base import OWASPPlugin

class A03InjectionPlugin(OWASPPlugin):
    id = "A03"
    name = "Injection"

    def scan(self, url, response, soup):
        findings = []
        forms = soup.find_all("form")

        if forms:
            findings.append({
                "severity": "Medium",
                "id": self.id,
                "title": "Potential Injection Points",
                "description": f"{len(forms)} HTML form(s) detected.",
                "fix": "Validate inputs and use parameterized queries."
            })

        return findings
