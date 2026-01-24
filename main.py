from flask import Flask, request, jsonify, send_from_directory, render_template
import time
import requests
from utils.pdf_report import generate_pdf_report
from bs4 import BeautifulSoup


from plugins.a10_open_redirect import A10OpenRedirectPlugin
from plugins.a02_crypto import A02CryptoPlugin
from plugins.a03_injection import A03InjectionPlugin
from plugins.a05_misconfig import A05MisconfigPlugin
from plugins.a06_components import A06ComponentPlugin
from plugins.a01_access_control import A01AccessControlPlugin
from plugins.a04_insecure_design import A04InsecureDesignPlugin
from plugins.a08_integrity import A08IntegrityPlugin
from plugins.a07_cookie_flags import A07CookieFlagsPlugin

app = Flask(__name__)

ENABLED_PLUGINS = {

    "A01": True,
    "A02": True,
    "A03": True,
    "A04": True,
    "A05": True,
    "A06": True,
    "A07": True,
    "A08": True,
    "A10": True
}

def load_plugins():
    plugins = []
    if ENABLED_PLUGINS.get("A01"):
        plugins.append(A01AccessControlPlugin())
    if ENABLED_PLUGINS.get("A04"):
        plugins.append(A04InsecureDesignPlugin())
    if ENABLED_PLUGINS.get("A08"):
        plugins.append(A08IntegrityPlugin())
    if ENABLED_PLUGINS.get("A02"):
        plugins.append(A02CryptoPlugin())
    if ENABLED_PLUGINS.get("A03"):
        plugins.append(A03InjectionPlugin())
    if ENABLED_PLUGINS.get("A05"):
        plugins.append(A05MisconfigPlugin())
    if ENABLED_PLUGINS.get("A06"):
        plugins.append(A06ComponentPlugin())
    if ENABLED_PLUGINS.get("A07"):
        plugins.append(A07CookieFlagsPlugin())
    if ENABLED_PLUGINS.get("A10"):
        plugins.append(A10OpenRedirectPlugin())
    return plugins

def perform_scan(url):
    results = []

    if not url.startswith("http"):
        url = "http://" + url

    response = requests.get(url, timeout=10)
    soup = BeautifulSoup(response.text, "html.parser")

    for plugin in load_plugins():
        start = time.time()
        try:
            findings = plugin.scan(url, response, soup)
            for f in findings:
                f["plugin"] = plugin.id
                f["execution_ms"] = int((time.time() - start) * 1000)
                results.append(f)
        except Exception as e:
            results.append({
                "severity": "Error",
                "id": plugin.id,
                "title": "Plugin Failed",
                "description": str(e),
                "fix": "Fix plugin implementation"
            })

    return results

# 🔹 Serve UI
@app.route("/")
def home():
    return render_template("index.html")

# 🔹 Scan API
@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    url = data.get("url")

    if not url:
        return jsonify({"results": []})

    results = perform_scan(url)
    return jsonify({"results": results})
@app.route("/export/pdf", methods=["POST"])
def export_pdf():
    data = request.get_json()
    url = data.get("url")

    if not url:
        return jsonify({"error": "URL missing"}), 400

    results = perform_scan(url)
    filename = "dast_scan_report.pdf"

    generate_pdf_report(filename, url, results)

    return jsonify({
        "message": "PDF report generated",
        "file": filename
    })

if __name__ == "__main__":
    app.run(debug=True)
