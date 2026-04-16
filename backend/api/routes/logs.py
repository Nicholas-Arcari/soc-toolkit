from fastapi import APIRouter, File, UploadFile
from pydantic import BaseModel

from core.logs.alert_engine import generate_alerts
from core.logs.ssh_analyzer import analyze_ssh_logs
from core.logs.web_analyzer import analyze_web_logs
from core.logs.windows_analyzer import analyze_windows_logs

router = APIRouter()


class LogAlert(BaseModel):
    severity: str
    message: str
    source_ip: str | None = None
    geo: dict | None = None
    count: int = 1
    mitre_technique: str | None = None


class LogAnalysisResult(BaseModel):
    log_type: str
    total_lines: int
    suspicious_entries: int
    alerts: list[LogAlert]
    top_ips: list[dict]
    timeline: list[dict]
    summary: str


@router.post("/analyze", response_model=LogAnalysisResult)
async def analyze_logs(
    file: UploadFile = File(...),
    log_type: str = "auto",
) -> LogAnalysisResult:
    """
    Analyze a log file for suspicious activity.

    Supported log types: ssh, apache, nginx, windows, auto (auto-detect).
    """
    content = await file.read()
    raw_logs = content.decode("utf-8", errors="replace")

    if log_type == "auto":
        log_type = detect_log_type(raw_logs)

    analyzers = {
        "ssh": analyze_ssh_logs,
        "apache": analyze_web_logs,
        "nginx": analyze_web_logs,
        "windows": analyze_windows_logs,
    }

    analyzer = analyzers.get(log_type, analyze_ssh_logs)
    analysis = analyzer(raw_logs)
    alerts = await generate_alerts(analysis)

    return LogAnalysisResult(
        log_type=log_type,
        total_lines=analysis["total_lines"],
        suspicious_entries=analysis["suspicious_entries"],
        alerts=[LogAlert(**a) for a in alerts],
        top_ips=analysis["top_ips"],
        timeline=analysis["timeline"],
        summary=analysis["summary"],
    )


def detect_log_type(raw_logs: str) -> str:
    first_lines = raw_logs[:2000].lower()
    if "sshd" in first_lines or "failed password" in first_lines:
        return "ssh"
    if "apache" in first_lines or "http/1" in first_lines:
        return "apache"
    if "nginx" in first_lines:
        return "nginx"
    if "eventid" in first_lines or "security" in first_lines:
        return "windows"
    return "ssh"
