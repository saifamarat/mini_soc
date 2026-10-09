from collections import Counter
from datetime import datetime
from html import escape

from config import REPORT_FILE


SEVERITY_COLORS = {
    "CRITICAL": "#7f1d1d",
    "HIGH": "#dc2626",
    "MEDIUM": "#d97706",
    "LOW": "#16a34a",
    "INFO": "#0284c7",
    "UNKNOWN": "#64748b",
}


def create_html_report(events, alerts, output_file=REPORT_FILE):
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    event_counts = Counter(
        event.get("event_type", "unknown")
        for event in events
    )

    severity_counts = Counter(
        alert.get("severity", "UNKNOWN").upper()
        for alert in alerts
    )

    high_count = (
        severity_counts.get("HIGH", 0)
        + severity_counts.get("CRITICAL", 0)
    )

    event_rows = []

    for event in events:
        event_rows.append(
            "<tr>"
            f"<td>{escape(str(event.get('event_type') or '-'))}</td>"
            f"<td>{escape(str(event.get('username') or '-'))}</td>"
            f"<td>{escape(str(event.get('source_ip') or '-'))}</td>"
            f"<td class='raw'>{escape(str(event.get('raw') or '-'))}</td>"
            "</tr>"
        )

    alert_rows = []

    for alert in alerts:
        severity = str(alert.get("severity", "UNKNOWN")).upper()
        color = SEVERITY_COLORS.get(
            severity,
            SEVERITY_COLORS["UNKNOWN"]
        )

        alert_rows.append(
            "<tr>"
            f"<td><span class='badge' style='background:{color}'>"
            f"{escape(severity)}</span></td>"
            f"<td>{escape(str(alert.get('type') or '-'))}</td>"
            f"<td>{escape(str(alert.get('message') or '-'))}</td>"
            f"<td>{escape(str(alert.get('source_ip') or '-'))}</td>"
            f"<td>{escape(str(alert.get('username') or '-'))}</td>"
            "</tr>"
        )

    if not event_rows:
        event_rows.append(
            "<tr><td colspan='4'>No security events detected.</td></tr>"
        )

    if not alert_rows:
        alert_rows.append(
            "<tr><td colspan='5'>No alerts generated.</td></tr>"
        )

    event_summary = "".join(
        f"<li>{escape(str(name))}: {count}</li>"
        for name, count in sorted(event_counts.items())
    ) or "<li>No events detected.</li>"

    severity_summary = "".join(
        f"<li>{escape(str(name))}: {count}</li>"
        for name, count in sorted(severity_counts.items())
    ) or "<li>No alerts generated.</li>"

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Mini SOC V3 - Security Report</title>
<style>
* {{ box-sizing: border-box; }}
body {{
    margin: 0;
    padding: 28px;
    background: #0f172a;
    color: #e2e8f0;
    font-family: Arial, Helvetica, sans-serif;
}}
.container {{ max-width: 1250px; margin: auto; }}
header {{
    background: #1e293b;
    border: 1px solid #334155;
    border-left: 5px solid #38bdf8;
    border-radius: 14px;
    padding: 25px;
}}
h1 {{ color: #38bdf8; margin-top: 0; }}
h2 {{ color: #7dd3fc; margin-top: 32px; }}
.muted {{ color: #94a3b8; }}
.cards {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
    gap: 15px;
    margin: 22px 0;
}}
.card {{
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 12px;
    padding: 20px;
}}
.number {{ font-size: 34px; font-weight: bold; margin-top: 10px; }}
.panel {{
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 12px;
    padding: 18px;
    overflow-x: auto;
}}
table {{ width: 100%; border-collapse: collapse; min-width: 650px; }}
th, td {{
    padding: 12px;
    text-align: left;
    border-bottom: 1px solid #334155;
    vertical-align: top;
    overflow-wrap: anywhere;
}}
th {{ background: #334155; }}
.raw {{ max-width: 450px; }}
.badge {{
    display: inline-block;
    padding: 5px 9px;
    color: white;
    border-radius: 6px;
    font-weight: bold;
    font-size: 12px;
}}
li {{ margin: 8px 0; }}
footer {{ margin-top: 30px; color: #94a3b8; font-size: 13px; }}
@media (max-width: 600px) {{
    body {{ padding: 12px; }}
    header {{ padding: 17px; }}
    .number {{ font-size: 27px; }}
}}
</style>
</head>
<body>
<div class="container">

<header>
    <h1>Mini SOC V3</h1>
    <p>Security Monitoring & Detection Report</p>
    <p class="muted">Generated: {escape(generated_at)}</p>
</header>

<div class="cards">
    <div class="card">Security Events<div class="number">{len(events)}</div></div>
    <div class="card">Alerts Generated<div class="number">{len(alerts)}</div></div>
    <div class="card">High / Critical Alerts<div class="number">{high_count}</div></div>
    <div class="card">Medium Alerts<div class="number">{severity_counts.get("MEDIUM", 0)}</div></div>
</div>

<h2>Event Summary</h2>
<div class="panel"><ul>{event_summary}</ul></div>

<h2>Alert Severity Summary</h2>
<div class="panel"><ul>{severity_summary}</ul></div>

<h2>Security Alerts</h2>
<div class="panel">
<table>
<thead>
<tr><th>Severity</th><th>Type</th><th>Message</th><th>Source IP</th><th>Username</th></tr>
</thead>
<tbody>
{"".join(alert_rows)}
</tbody>
</table>
</div>

<h2>Detected Events</h2>
<div class="panel">
<table>
<thead>
<tr><th>Event Type</th><th>Username</th><th>Source IP</th><th>Raw Log</th></tr>
</thead>
<tbody>
{"".join(event_rows)}
</tbody>
</table>
</div>

<footer>
Mini SOC V3 | Generated locally | Authorized security monitoring
</footer>

</div>
</body>
</html>
"""

    with open(output_file, "w", encoding="utf-8") as file:
        file.write(html_content)

    print(f"[+] HTML report generated: {output_file}")
