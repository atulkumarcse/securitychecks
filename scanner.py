import requests
from bs4 import BeautifulSoup

def perform_scan(url):
    results = []
    try:
        if not url.startswith('http'):
            url = 'http://' + url
            
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')

        # --- A02: Cryptographic Failures ---
        if not url.startswith('https://'):
            results.append({
                "severity": "High",
                "id": "A02",
                "title": "Cryptographic Failure (No HTTPS)",
                "description": "Website does not use HTTPS. Data in transit is unencrypted and can be intercepted by Man-in-the-Middle attacks.",
                "fix": "Install an SSL/TLS certificate (e.g., Let's Encrypt)."
            })
        else:
            results.append({
                "severity": "Safe",
                "id": "A02",
                "title": "Secure Connection",
                "description": "Connection is encrypted using HTTPS.",
                "fix": "N/A"
            })

        # --- A03: Injection ---
        forms = soup.find_all('form')
        if forms:
            results.append({
                "severity": "Medium",
                "id": "A03",
                "title": "Potential Injection Points",
                "description": f"Found {len(forms)} HTML form(s).",
                "fix": "Ensure all inputs are sanitized and use parameterized queries to prevent SQLi and XSS."
            })

        # --- A05: Security Misconfiguration ---
        security_headers = {
            'Content-Security-Policy': 'Prevents XSS',
            'X-Frame-Options': 'Prevents Clickjacking',
            'Strict-Transport-Security': 'Enforces HTTPS',
            'X-Content-Type-Options': 'Prevents MIME-sniffing'
        }
        missing = [h for h in security_headers if h not in response.headers]
        
        if missing:
            results.append({
                "severity": "Medium",
                "id": "A05",
                "title": "Security Misconfiguration",
                "description": f"Missing {len(missing)} critical security headers: {', '.join(missing)}.",
                "fix": "Configure your web server (Nginx/Apache) to send these headers with every response."
            })
        
        server = response.headers.get('Server')
        if server:
            results.append({
                "severity": "Low",
                "id": "A05",
                "title": "Information Leakage",
                "description": f"Server header leaked: {server}.",
                "fix": "Disable 'Server' tokens in your configuration to hide version numbers from attackers."
            })

        # --- A06: Vulnerable Components ---
        scripts = [script.get('src') for script in soup.find_all('script') if script.get('src')]
        if len(scripts) > 5:
            results.append({
                "severity": "Low",
                "id": "A06",
                "title": "Third-Party Components",
                "description": f"Detected {len(scripts)} external scripts.",
                "fix": "Audit these libraries for known CVEs and use Subresource Integrity (SRI) hashes."
            })

        return results
    except Exception as e:
        return [{"severity": "Error", "title": "Scan Failed", "description": str(e), "fix": "Check URL"}]