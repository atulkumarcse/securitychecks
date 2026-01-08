from flask import Flask, render_template, request, jsonify
import requests
from bs4 import BeautifulSoup

app = Flask(__name__)

def perform_scan(url):
    results = []
    try:
        # Basic URL formatting
        if not url.startswith('http'):
            url = 'http://' + url
            
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')

        # 1. Check HTTPS
        if not url.startswith('https://'):
            results.append("⚠️ Warning: Website does not use HTTPS.")
        else:
            results.append("✅ Connection is secure (HTTPS).")

        # 2. Check Security Headers
        security_headers = ['Content-Security-Policy', 'X-Frame-Options', 'Strict-Transport-Security']
        found_headers = [h for h in security_headers if h in response.headers]
        results.append(f"🛡️ Security Headers found: {len(found_headers)}/{len(security_headers)}")

        # 3. Check Forms
        forms = soup.find_all('form')
        results.append(f"📝 Found {len(forms)} form(s) to review.")

        return results
    except Exception as e:
        return [f"❌ Error: {str(e)}"]

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    target_url = request.json.get('url')
    scan_output = perform_scan(target_url)
    return jsonify({"results": scan_output})

if __name__ == '__main__':
    app.run(debug=False, port=80)