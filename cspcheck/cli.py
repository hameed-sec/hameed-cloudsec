import typer
from cspcheck.core.aws_client import aws_session
from cspcheck.checks.aws.s3_public import s3_public_findings
from cspcheck.reporters.csv_reporter import write_csv

app = typer.Typer(help="CSP-Check: Cloud Security Posture Scanner (AWS MVP)")

@app.command("scan")
def scan(
    profile: str = typer.Option(..., "--profile", help="AWS named profile to use"),
    out: str = typer.Option("./reports", "--out", help="Output directory for the CSV report"),
):
    """
    Scan AWS S3 for public exposure risks and write a CSV report.
    Exit codes: 0 = no findings, 2 = findings present.
    """
    typer.echo("[+] Creating AWS session…")
    sess = aws_session(profile=profile)

    typer.echo("[+] Scanning S3 public access…")
    findings = s3_public_findings(sess)

    typer.echo(f"[+] Findings: {len(findings)}")
    report_path = write_csv(findings, out_dir=out)
    typer.echo(f"[+] CSV report written: {report_path}")

    raise typer.Exit(code=2 if findings else 0)

if __name__ == "__main__":
    app()
