"""YARA-X scanner module for local rule-based malware detection.

Runs before external threat intel API calls so a clear match can short-circuit
an analysis without burning free-tier quota (VirusTotal: 4 req/min).
"""
from core.yara.scanner import YaraScanner, get_scanner

__all__ = ["YaraScanner", "get_scanner"]
