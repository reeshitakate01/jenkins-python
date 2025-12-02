import json
import sys
from pathlib import Path
from html import escape

def main(json_path, html_path):
    data = json.loads(Path(json_path).read_text(encoding="utf-8"))

    vulns = []
    for result in data.get("Results", []):
        for v in result.get("Vulnerabilities", []):
            vulns.append({
                "id": v.get("VulnerabilityID", ""),
                "pkg": v.get("PkgName", ""),
                "installed": v.get("InstalledVersion", ""),
                "severity": v.get("Severity", ""),
                "title": v.get("Title", ""),
            })

    html_rows = ""
    for v in vulns:
        html_rows += (
            "<tr>"
            f"<td>{escape(v['id'])}</td>"
            f"<td>{escape(v['pkg'])}</td>"
            f"<td>{escape(v['installed'])}</td>"
            f"<td>{escape(v['severity'])}</td>"
            f"<td>{escape(v['title'])}</td>"
            "</tr>\n"
        )

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>Trivy Vulnerability Scan Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; }}
            table {{ border-collapse: collapse; width: 100%; }}
            th, td {{ border: 1px solid #ccc; padding: 8px; font-size: 13px; }}
            th {{ background-color: #f2f2f2; }}
            .HIGH {{ background-color: #ffcccc; }}
            .CRITICAL {{ background-color: #ff9999; }}
        </style>
    </head>
    <body>
        <h2>Trivy Vulnerability Scan Report</h2>
        <p>Total vulnerabilities: {len(vulns)}</p>
        <table>
            <tr>
                <th>ID</th>
                <th>Package</th>
                <th>Installed Version</th>
                <th>Severity</th>
                <th>Title</th>
            </tr>
            {html_rows}
        </table>
    </body>
    </html>
    """

    Path(html_path).write_text(html, encoding="utf-8")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python trivy_to_html.py <input.json> <output.html>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])
