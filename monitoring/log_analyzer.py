"""
Log Analyzer — Security Monitoring Tool

Analyzes application logs for suspicious patterns,
failed authentication attempts, and anomalous behavior.
"""

import logging
import re
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)


@dataclass
class AnalysisReport:
    """Security analysis report."""

    total_lines: int = 0
    error_count: int = 0
    warning_count: int = 0
    suspicious_ips: Counter = field(default_factory=Counter)
    failed_logins: int = 0
    sql_injection_attempts: int = 0
    path_traversal_attempts: int = 0
    alerts: list = field(default_factory=list)


# Suspicious patterns
PATTERNS = {
    "sql_injection": re.compile(
        r"(?i)(union\s+select|or\s+1\s*=\s*1|drop\s+table|;\s*delete|'\s*or\s*')"
    ),
    "path_traversal": re.compile(r"\.\./|\.\.\\|%2e%2e"),
    "failed_login": re.compile(r"(?i)(failed|invalid|unauthorized).*(login|auth|password)"),
    "suspicious_ip": re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"),
}


def analyze_log_file(filepath: Path) -> AnalysisReport:
    """Analyze a log file for security events."""
    report = AnalysisReport()

    try:
        lines = filepath.read_text(encoding="utf-8", errors="ignore").splitlines()
    except (OSError, PermissionError) as e:
        logger.error("Cannot read log file: %s", e)
        return report

    report.total_lines = len(lines)

    for line in lines:
        # Count severity levels
        if "[ERROR]" in line or "ERROR" in line:
            report.error_count += 1
        elif "[WARNING]" in line or "WARNING" in line:
            report.warning_count += 1

        # Check for SQL injection attempts
        if PATTERNS["sql_injection"].search(line):
            report.sql_injection_attempts += 1
            report.alerts.append(f"SQL Injection attempt: {line[:100]}")

        # Check for path traversal
        if PATTERNS["path_traversal"].search(line):
            report.path_traversal_attempts += 1
            report.alerts.append(f"Path traversal attempt: {line[:100]}")

        # Check for failed logins
        if PATTERNS["failed_login"].search(line):
            report.failed_logins += 1
            ip_match = PATTERNS["suspicious_ip"].search(line)
            if ip_match:
                report.suspicious_ips[ip_match.group(1)] += 1

    return report


def print_report(report: AnalysisReport) -> None:
    """Print the analysis report."""
    print("\n" + "=" * 60)
    print("  SECURITY LOG ANALYSIS REPORT")
    print("=" * 60)
    print(f"\n  Total lines analyzed: {report.total_lines}")
    print(f"  Errors: {report.error_count}")
    print(f"  Warnings: {report.warning_count}")
    print(f"\n  --- Threat Detection ---")
    print(f"  Failed login attempts: {report.failed_logins}")
    print(f"  SQL injection attempts: {report.sql_injection_attempts}")
    print(f"  Path traversal attempts: {report.path_traversal_attempts}")

    if report.suspicious_ips:
        print(f"\n  --- Suspicious IPs (by failed attempts) ---")
        for ip, count in report.suspicious_ips.most_common(10):
            print(f"    {ip}: {count} attempts")

    if report.alerts:
        print(f"\n  --- Alerts ({len(report.alerts)}) ---")
        for alert in report.alerts[:20]:
            print(f"    ! {alert}")

    severity = "LOW"
    if report.sql_injection_attempts > 0 or report.path_traversal_attempts > 0:
        severity = "HIGH"
    elif report.failed_logins > 10:
        severity = "MEDIUM"

    print(f"\n  Overall Threat Level: {severity}")
    print("=" * 60 + "\n")


def main():
    """Run the log analyzer."""
    if len(sys.argv) < 2:
        print("Usage: python log_analyzer.py <logfile>")
        sys.exit(1)

    filepath = Path(sys.argv[1])
    if not filepath.exists():
        logger.error("File not found: %s", filepath)
        sys.exit(1)

    logger.info("Analyzing: %s", filepath)
    report = analyze_log_file(filepath)
    print_report(report)

    # Exit with non-zero if threats detected
    if report.sql_injection_attempts > 0 or report.path_traversal_attempts > 0:
        sys.exit(2)


if __name__ == "__main__":
    main()
