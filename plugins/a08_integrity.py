from plugins.base import OWASPPlugin

class A08IntegrityPlugin(OWASPPlugin):
    id = "A08"
    name = "Software and Data Integrity Failures"

    def scan(self, url, response, soup):
        findings = []

        external_scripts = soup.find_all("script", src=True)

        for script in external_scripts:
            src = script.get("src")
            integrity = script.get("integrity")

            if src.startswith("http") and not integrity:
                findings.append({
                    "severity": "Low",
                    "id": self.id,
                    "title": "Missing Subresource Integrity (SRI)",
                    "description": f"External script loaded without integrity attribute: {src}",
                    "fix": "Add integrity and crossorigin attributes to external scripts."
                })
                break

        return findings
