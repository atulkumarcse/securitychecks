from plugins.base import OWASPPlugin

class A05MisconfigPlugin(OWASPPlugin):
    # Standardizing ID and naming according to OWASP Top 10 (2021+)
    id = "A05:2021" 
    name = "Security Misconfiguration"

    SECURITY_HEADERS = [
        "Content-Security-Policy",
        "X-Frame-Options",
        "Strict-Transport-Security",
        "X-Content-Type-Options"
    ]

    def scan(self, url, response, soup):
        findings = []

        # 1. Check for Missing Security Headers
        # Case-insensitive check is safer for HTTP headers
        current_headers = [h.lower() for h in response.headers.keys()]
        missing = [h for h in self.SECURITY_HEADERS if h.lower() not in current_headers]

        if missing:
            findings.append({
                "severity": "Medium",
                "id": self.id,
                "title": "Missing Security Headers",
                "description": f"The following security headers are missing: {', '.join(missing)}",
                "fix": "Implement the missing security headers in your web server configuration (Nginx, Apache, or App middleware)."
            })

        # 2. Check for Server Information Disclosure
        server = response.headers.get("Server")
        if server:
            findings.append({
                "severity": "Low",
                "id": self.id,
                "title": "Server Header Disclosure",
                "description": f"The 'Server' header exposes specific software/version: {server}",
                "fix": "Configure the server to suppress the 'Server' header or return a generic value (e.g., 'Server: webserver')."
            })

        # 3. Check for Directory Listing (Combined here for efficiency)
        # We look for common patterns like "Index of /" or "Directory Listing For"
        directory_indicators = ["<title>index of /", "directory listing for /", "last modified</a>"]
        response_text_lower = response.text.lower()
        
        if any(indicator in response_text_lower for indicator in directory_indicators):
            findings.append({
                "severity": "High",
                "id": self.id,
                "title": "Directory Listing Enabled",
                "description": "The web server is configured to list the contents of directories, which can leak sensitive files.",
                "fix": "Disable directory indexing (e.g., 'Options -Indexes' in Apache or 'autoindex off;' in Nginx)."
            })

        return findings