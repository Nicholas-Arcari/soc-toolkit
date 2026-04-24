import csv
import io


async def export_csv(data: dict, report_type: str) -> io.BytesIO:
    """Export analysis results as CSV."""
    output = io.StringIO()
    writer = csv.writer(output)

    if report_type == "phishing":
        writer.writerow(["Type", "Value", "Malicious", "Details"])
        for url in data.get("urls", []):
            writer.writerow([
                "URL", url.get("url", ""),
                url.get("malicious", False),
                "; ".join(url.get("suspicious_patterns", [])),
            ])
        for att in data.get("attachments", []):
            writer.writerow([
                "Attachment", att.get("filename", ""),
                att.get("malicious", False),
                att.get("hashes", {}).get("sha256", ""),
            ])

    elif report_type == "logs":
        writer.writerow(["Severity", "Message", "Source IP", "Country", "Count", "MITRE"])
        for alert in data.get("alerts", []):
            geo = alert.get("geo") or {}
            writer.writerow([
                alert.get("severity", ""),
                alert.get("message", ""),
                alert.get("source_ip", ""),
                geo.get("country", ""),
                alert.get("count", 1),
                alert.get("mitre_technique", ""),
            ])

    elif report_type == "ioc":
        writer.writerow(["Type", "Value", "Malicious", "Context"])
        for ioc in data.get("iocs", []):
            writer.writerow([
                ioc.get("type", ""),
                ioc.get("value", ""),
                ioc.get("malicious", ""),
                ioc.get("context", ""),
            ])

    content = output.getvalue()
    return io.BytesIO(content.encode("utf-8"))
