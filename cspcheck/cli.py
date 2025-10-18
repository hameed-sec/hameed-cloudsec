import typer
from cspcheck.core.aws_client import aws_session
from cspcheck.checks.aws.s3_public import s3_public_findings
from cspcheck.checks.aws.sg_open_ports import sg_open_findings
from cspcheck.reporters.csv_reporter import write_csv

app = typer.Typer(help="CSP-Check: Cloud Security Posture Scanner (AWS MVP)")

@app.command()
def scan(
    profile: str = typer.Option(..., "--profile", help="AWS named profile to use"),
    out: str = typer.Option("./reports", "--out", help="Output directory for the CSV report"),
):
    """
    Run all AWS posture checks and write a CSV report.
    Exit codes: 0 = no findings, 2 = findings present.
    """
    typer.echo("[+] Creating AWS session…")
    sess = aws_session(profile=profile)

    all_findings = []

    typer.echo("[+] Scanning S3 public access…")
    all_findings.extend(s3_public_findings(sess))

    typer.echo("[+] Scanning Security Groups for open ports…")
    all_findings.extend(sg_open_findings(sess))

    typer.echo(f"[+] Total Findings: {len(all_findings)}")
    report_path = write_csv(all_findings, out_dir=out)
    typer.echo(f"[+] CSV report written: {report_path}")

    raise typer.Exit(code=2 if all_findings else 0)

if __name__ == "__main__":
    app()

