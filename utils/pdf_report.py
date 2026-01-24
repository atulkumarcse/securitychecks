# utils/pdf_report.py
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import A4

def generate_pdf_report(filename, target_url, results):
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(filename, pagesize=A4)

    elements = []
    elements.append(Paragraph("<b>DAST Scan Report</b>", styles["Title"]))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph(f"<b>Target:</b> {target_url}", styles["Normal"]))
    elements.append(Spacer(1, 12))

    table_data = [["Severity", "OWASP ID", "Title", "Description"]]

    for r in results:
        table_data.append([
            r.get("severity"),
            r.get("id"),
            r.get("title"),
            r.get("description")
        ])

    table = Table(table_data, repeatRows=1)
    elements.append(table)

    doc.build(elements)
