from plugins.base import OWASPPlugin

class A07CookieFlagsPlugin(OWASPPlugin):
    id = "A07"
    name = "Authentication Failures (Cookie Flags)"

    def scan(self, url, response, soup):
        results = []
        cookies = response.headers.get("Set-Cookie", "").lower()

        if cookies:
            if "httponly" not in cookies:
                results.append({
                    "severity": "Medium",
                    "id": self.id,
                    "title": "Cookie Missing HttpOnly",
                    "description": "Session cookie does not use HttpOnly flag.",
                    "fix": "Set HttpOnly on all session cookies."
                })

            if response.url.startswith("https://") and "secure" not in cookies:
                results.append({
                    "severity": "Medium",
                    "id": self.id,
                    "title": "Cookie Missing Secure Flag",
                    "description": "Cookie transmitted over HTTPS without Secure flag.",
                    "fix": "Set Secure flag for cookies over HTTPS."
                })

        return results
