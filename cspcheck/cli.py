import typer
from cspcheck.core.aws_client import aws_session
from cspcheck.checks.aws.s3_public import s3_public_findings
from cspcheck.checks.aws.sg_open_ports import sg_open_findings
from cspcheck.checks.aws.iam_mfa import iam_mfa_key_findings
from cspcheck.reporters.csv_reporter import write_csv
from cspcheck.web.db import init_db, save_findings

app = typer.Typer(help="CSP-Check: Cloud Security Posture Scanner (AWS MVP)")

@app.command()
def scan(
    profile: str = typer.Option(..., "--profile", help="AWS named profile to use"),
    out: str = typer.Option("./reports", "--out", help="Output directory for the CSV report"),
):
    """
    Run all AWS posture checks and write a CSV report + persist to SQLite.
    Exit codes: 0 = no findings, 2 = findings present.
    """
    typer.echo("[+] Initializing database…")
    init_db()

    typer.echo("[+] Creating AWS session…")
    sess = aws_session(profile=profile)

    all_findings = []

    typer.echo("[+] Scanning S3 public access…")
    all_findings.extend(s3_public_findings(sess))

    typer.echo("[+] Scanning Security Groups for open ports…")
    all_findings.extend(sg_open_findings(sess))

    typer.echo("[+] Scanning IAM for MFA and key age…")
    all_findings.extend(iam_mfa_key_findings(sess, max_age_days=90))

    typer.echo(f"[+] Total Findings: {len(all_findings)}")
    report_path = write_csv(all_findings, out_dir=out)
    typer.echo(f"[+] CSV report written: {report_path}")

    # persist to DB
    rows = [f.to_dict() for f in all_findings]
    save_findings(rows)
    typer.echo("[+] Findings saved to SQLite (cspcheck.db)")

    raise typer.Exit(code=2 if all_findings else 0)

if __name__ == "__main__":
    app()
