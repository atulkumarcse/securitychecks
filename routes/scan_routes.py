from flask import Blueprint, request, render_template, current_app
from main import perform_scan
from scan_summary import generate_scan_summary

scan_bp = Blueprint("scan", __name__)

@scan_bp.route("/scan", methods=["POST"])
def scan():
    url = request.form.get("url")

    if not url:
        return render_template(
            "index.html",
            results=[],
            error="URL is required"
        )

    # Run scan
    findings = perform_scan(url)

    # Generate summary
    summary = generate_scan_summary(findings)

    # Store results for summary page
    current_app.config["LAST_RESULTS"] = findings
    current_app.config["LAST_SUMMARY"] = summary
    current_app.config["LAST_TARGET"] = url

    return render_template(
        "index.html",
        results=findings,
        scan_completed=True
    )


@scan_bp.route("/summary")
def summary_page():
    return render_template(
        "summary.html",
        summary=current_app.config.get("LAST_SUMMARY"),
        target=current_app.config.get("LAST_TARGET")
    )
