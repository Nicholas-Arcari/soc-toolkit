import asyncio
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from core.phishing.header_analyzer import analyze_headers
from core.phishing.url_checker import check_urls
from core.phishing.attachment_scanner import scan_attachment
from core.phishing.verdict_engine import generate_verdict
from core.logs.ssh_analyzer import analyze_ssh_logs
from core.logs.web_analyzer import analyze_web_logs
from core.ioc.text_extractor import extract_from_text
from core.ioc.pdf_extractor import extract_from_pdf

app = typer.Typer(
    name="soc-toolkit",
    help="Modular SOC analyst toolkit - Phishing, Logs, IOC analysis",
)
console = Console()


@app.command()
def phishing(file: Path = typer.Argument(..., help="Path to .eml email file")):
    """Analyze an email file for phishing indicators."""
    if not file.exists():
        console.print(f"[red]File not found: {file}[/red]")
        raise typer.Exit(1)

    raw_email = file.read_text(errors="replace")

    with console.status("Analyzing email headers..."):
        headers = analyze_headers(raw_email)

    with console.status("Checking URLs..."):
        urls = asyncio.run(check_urls(raw_email))

    with console.status("Scanning attachments..."):
        attachments = asyncio.run(scan_attachment(raw_email))

    result = generate_verdict(headers, urls, attachments)

    # Display verdict
    color = {"MALICIOUS": "red", "SUSPICIOUS": "yellow", "CAUTIOUS": "blue", "CLEAN": "green"}
    console.print(f"\n[bold {color.get(result['verdict'], 'white')}]"
                  f"Verdict: {result['verdict']} "
                  f"(Risk: {result['risk_score']}/100, "
                  f"Confidence: {result['confidence']})[/]")

    if result["indicators"]:
        console.print("\n[bold]Indicators:[/bold]")
        for ind in result["indicators"]:
            console.print(f"  - {ind}")

    if result["recommendations"]:
        console.print("\n[bold]Recommendations:[/bold]")
        for rec in result["recommendations"]:
            console.print(f"  - {rec}")


@app.command()
def logs(
    file: Path = typer.Argument(..., help="Path to log file"),
    log_type: str = typer.Option("auto", help="Log type: ssh, apache, nginx, windows, auto"),
):
    """Analyze a log file for suspicious activity."""
    if not file.exists():
        console.print(f"[red]File not found: {file}[/red]")
        raise typer.Exit(1)

    raw_logs = file.read_text(errors="replace")

    with console.status("Analyzing logs..."):
        if log_type in ("ssh", "auto"):
            analysis = analyze_ssh_logs(raw_logs)
        elif log_type in ("apache", "nginx"):
            analysis = analyze_web_logs(raw_logs)
        else:
            analysis = analyze_ssh_logs(raw_logs)

    console.print(f"\n[bold]{analysis['summary']}[/bold]")

    if analysis["top_ips"]:
        table = Table(title="Top Suspicious IPs")
        table.add_column("IP", style="cyan")
        table.add_column("Attempts", style="red")

        for ip_info in analysis["top_ips"][:10]:
            count = ip_info.get("attempts", ip_info.get("requests", 0))
            table.add_row(ip_info["ip"], str(count))

        console.print(table)


@app.command()
def ioc(file: Path = typer.Argument(..., help="Path to file (PDF, TXT, EML)")):
    """Extract IOCs from a file."""
    if not file.exists():
        console.print(f"[red]File not found: {file}[/red]")
        raise typer.Exit(1)

    with console.status("Extracting IOCs..."):
        if file.suffix == ".pdf":
            content = file.read_bytes()
            iocs = extract_from_pdf(content)
        else:
            text = file.read_text(errors="replace")
            iocs = extract_from_text(text)

    if not iocs:
        console.print("[yellow]No IOCs found.[/yellow]")
        raise typer.Exit(0)

    table = Table(title=f"IOCs Extracted from {file.name}")
    table.add_column("Type", style="cyan")
    table.add_column("Value", style="white")
    table.add_column("Context", style="dim")

    for item in iocs:
        table.add_row(
            item["type"].upper(),
            item["value"],
            (item.get("context", "") or "")[:60],
        )

    console.print(table)
    console.print(f"\n[bold green]Total: {len(iocs)} IOCs extracted[/bold green]")


if __name__ == "__main__":
    app()
