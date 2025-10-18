from flask import Flask, render_template, request, send_file
from io import StringIO
import csv
from cspcheck.web.db import init_db, list_findings

app = Flask(__name__)

# Initialize database immediately on startup (Flask 3.x safe)
init_db()

def _filter_rows(rows, severity=None, resource_type=None, q=None):
    out = []
    for r in rows:
        if severity and r.severity.lower() != severity.lower():
            continue
        if resource_type and r.resource_type.lower() != resource_type.lower():
            continue
        if q:
            hay = " ".join([r.title or "", r.description or "", r.resource_id or "", r.account or ""]).lower()
            if q.lower() not in hay:
                continue
        out.append(r)
    return out

@app.route("/")
def index():
    severity = request.args.get("severity")
    resource_type = request.args.get("service")
    q = request.args.get("q")
    rows = list_findings(limit=2000)
    rows = _filter_rows(rows, severity=severity, resource_type=resource_type, q=q)
    totals = {"ALL": len(rows)}
    for r in rows:
        totals[r.severity] = totals.get(r.severity, 0) + 1
    return render_template("index.html", rows=rows, totals=totals, severity=severity or "", service=resource_type or "", q=q or "")

@app.route("/download.csv")
def download_csv():
    rows = list_findings(limit=100000)
    si = StringIO()
    w = csv.writer(si)
    w.writerow(["ts","provider","account","resource_type","resource_id","title","severity","description","remediation","meta_json","id"])
    for r in rows:
        w.writerow([r.ts, r.provider, r.account, r.resource_type, r.resource_id, r.title, r.severity, r.description, r.remediation, r.meta_json, r.id])
    si.seek(0)
    return send_file(
        path_or_file=StringIO(si.getvalue()),
        mimetype="text/csv",
        as_attachment=True,
        download_name="findings.csv",
    )

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=True)
