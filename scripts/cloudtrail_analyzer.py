"""
CloudTrail Log Analyzer

Analyzes AWS CloudTrail logs for suspicious activity:
- Unauthorized API calls
- Root account usage
- Console logins from unusual locations
- Security group modifications
- IAM policy changes
- S3 bucket policy changes

Usage:
    python scripts/cloudtrail_analyzer.py [--file LOGFILE] [--demo]
"""

import json
import logging
import os
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


# High-risk API calls to monitor
HIGH_RISK_EVENTS = {
    "DeleteTrail": "CRITICAL",
    "StopLogging": "CRITICAL",
    "UpdateTrail": "HIGH",
    "CreateUser": "MEDIUM",
    "DeleteUser": "HIGH",
    "CreateAccessKey": "HIGH",
    "AttachUserPolicy": "HIGH",
    "AttachRolePolicy": "HIGH",
    "PutBucketPolicy": "HIGH",
    "DeleteBucketPolicy": "HIGH",
    "AuthorizeSecurityGroupIngress": "MEDIUM",
    "RevokeSecurityGroupIngress": "MEDIUM",
    "CreateSecurityGroup": "LOW",
    "DeleteSecurityGroup": "MEDIUM",
    "RunInstances": "LOW",
    "TerminateInstances": "MEDIUM",
    "ConsoleLogin": "INFO",
    "PutRolePolicy": "HIGH",
    "CreateRole": "MEDIUM",
    "DeleteRole": "HIGH",
    "CreatePolicy": "MEDIUM",
    "DeletePolicy": "HIGH",
}


@dataclass
class SecurityAlert:
    """A security alert from CloudTrail analysis."""

    severity: str
    event_name: str
    source_ip: str
    user_identity: str
    timestamp: str
    description: str
    region: str = "unknown"


@dataclass
class CloudTrailReport:
    """CloudTrail analysis report."""

    total_events: int = 0
    time_range_start: str = ""
    time_range_end: str = ""
    alerts: list = field(default_factory=list)
    event_counts: Counter = field(default_factory=Counter)
    source_ips: Counter = field(default_factory=Counter)
    user_activity: Counter = field(default_factory=Counter)
    failed_calls: int = 0
    root_activity: int = 0


def analyze_event(event: dict) -> list[SecurityAlert]:
    """Analyze a single CloudTrail event for suspicious activity."""
    alerts = []

    event_name = event.get("eventName", "")
    source_ip = event.get("sourceIPAddress", "unknown")
    user_identity = event.get("userIdentity", {})
    event_time = event.get("eventTime", "")
    region = event.get("awsRegion", "unknown")
    error_code = event.get("errorCode", "")

    # Determine user
    user_type = user_identity.get("type", "unknown")
    username = user_identity.get("userName", user_identity.get("arn", "unknown"))

    # Check for root account usage
    if user_type == "Root":
        alerts.append(SecurityAlert(
            severity="CRITICAL",
            event_name=event_name,
            source_ip=source_ip,
            user_identity="ROOT",
            timestamp=event_time,
            description=f"Root account used for: {event_name}",
            region=region,
        ))

    # Check for high-risk events
    if event_name in HIGH_RISK_EVENTS:
        severity = HIGH_RISK_EVENTS[event_name]
        alerts.append(SecurityAlert(
            severity=severity,
            event_name=event_name,
            source_ip=source_ip,
            user_identity=username,
            timestamp=event_time,
            description=f"High-risk API call: {event_name} by {username}",
            region=region,
        ))

    # Check for unauthorized access attempts
    if error_code in ("AccessDenied", "UnauthorizedOperation", "Client.UnauthorizedAccess"):
        alerts.append(SecurityAlert(
            severity="HIGH",
            event_name=event_name,
            source_ip=source_ip,
            user_identity=username,
            timestamp=event_time,
            description=f"Unauthorized attempt: {event_name} ({error_code})",
            region=region,
        ))

    # Check for console login failures
    if event_name == "ConsoleLogin":
        response = event.get("responseElements", {})
        if response.get("ConsoleLogin") == "Failure":
            alerts.append(SecurityAlert(
                severity="HIGH",
                event_name=event_name,
                source_ip=source_ip,
                user_identity=username,
                timestamp=event_time,
                description=f"Failed console login from {source_ip}",
                region=region,
            ))

    return alerts


def analyze_logs(events: list[dict]) -> CloudTrailReport:
    """Analyze a list of CloudTrail events."""
    report = CloudTrailReport(total_events=len(events))

    for event in events:
        event_name = event.get("eventName", "unknown")
        source_ip = event.get("sourceIPAddress", "unknown")
        user_identity = event.get("userIdentity", {})
        username = user_identity.get("userName", user_identity.get("arn", "unknown"))
        error_code = event.get("errorCode", "")

        # Track counts
        report.event_counts[event_name] += 1
        report.source_ips[source_ip] += 1
        report.user_activity[username] += 1

        if error_code:
            report.failed_calls += 1

        if user_identity.get("type") == "Root":
            report.root_activity += 1

        # Analyze for alerts
        alerts = analyze_event(event)
        report.alerts.extend(alerts)

    # Set time range
    if events:
        times = [e.get("eventTime", "") for e in events if e.get("eventTime")]
        if times:
            report.time_range_start = min(times)
            report.time_range_end = max(times)

    return report


def generate_demo_events() -> list[dict]:
    """Generate realistic demo CloudTrail events for testing."""
    return [
        {
            "eventName": "ConsoleLogin",
            "sourceIPAddress": "203.0.113.50",
            "userIdentity": {"type": "IAMUser", "userName": "admin-user"},
            "eventTime": "2026-05-13T08:00:00Z",
            "awsRegion": "us-east-1",
            "responseElements": {"ConsoleLogin": "Success"},
        },
        {
            "eventName": "ConsoleLogin",
            "sourceIPAddress": "198.51.100.23",
            "userIdentity": {"type": "IAMUser", "userName": "unknown-user"},
            "eventTime": "2026-05-13T08:15:00Z",
            "awsRegion": "us-east-1",
            "responseElements": {"ConsoleLogin": "Failure"},
            "errorCode": "AccessDenied",
        },
        {
            "eventName": "CreateAccessKey",
            "sourceIPAddress": "203.0.113.50",
            "userIdentity": {"type": "Root"},
            "eventTime": "2026-05-13T09:00:00Z",
            "awsRegion": "us-east-1",
        },
        {
            "eventName": "AuthorizeSecurityGroupIngress",
            "sourceIPAddress": "10.0.1.50",
            "userIdentity": {"type": "IAMUser", "userName": "developer-1"},
            "eventTime": "2026-05-13T10:30:00Z",
            "awsRegion": "us-west-2",
        },
        {
            "eventName": "StopLogging",
            "sourceIPAddress": "192.0.2.100",
            "userIdentity": {"type": "IAMUser", "userName": "compromised-user"},
            "eventTime": "2026-05-13T11:00:00Z",
            "awsRegion": "us-east-1",
        },
        {
            "eventName": "DeleteTrail",
            "sourceIPAddress": "192.0.2.100",
            "userIdentity": {"type": "IAMUser", "userName": "compromised-user"},
            "eventTime": "2026-05-13T11:01:00Z",
            "awsRegion": "us-east-1",
        },
        {
            "eventName": "PutBucketPolicy",
            "sourceIPAddress": "10.0.1.50",
            "userIdentity": {"type": "IAMUser", "userName": "developer-1"},
            "eventTime": "2026-05-13T12:00:00Z",
            "awsRegion": "us-east-1",
        },
        {
            "eventName": "RunInstances",
            "sourceIPAddress": "10.0.1.50",
            "userIdentity": {"type": "IAMUser", "userName": "developer-1"},
            "eventTime": "2026-05-13T13:00:00Z",
            "awsRegion": "eu-west-1",
        },
        {
            "eventName": "AttachUserPolicy",
            "sourceIPAddress": "192.0.2.100",
            "userIdentity": {"type": "IAMUser", "userName": "compromised-user"},
            "eventTime": "2026-05-13T11:05:00Z",
            "awsRegion": "us-east-1",
        },
        {
            "eventName": "TerminateInstances",
            "sourceIPAddress": "203.0.113.50",
            "userIdentity": {"type": "IAMUser", "userName": "admin-user"},
            "eventTime": "2026-05-13T14:00:00Z",
            "awsRegion": "us-east-1",
            "errorCode": "UnauthorizedOperation",
        },
    ]


def print_report(report: CloudTrailReport) -> None:
    """Print the CloudTrail analysis report."""
    print("\n" + "=" * 70)
    print("  AWS CLOUDTRAIL SECURITY ANALYSIS REPORT")
    print("=" * 70)
    print(f"\n  Events Analyzed: {report.total_events}")
    print(f"  Time Range: {report.time_range_start} → {report.time_range_end}")
    print(f"  Failed API Calls: {report.failed_calls}")
    print(f"  Root Account Activity: {report.root_activity}")
    print(f"  Total Alerts: {len(report.alerts)}")

    # Alert summary
    severity_counts = Counter(a.severity for a in report.alerts)
    print(f"\n  --- Alert Summary ---")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = severity_counts.get(sev, 0)
        if count > 0:
            print(f"    {sev}: {count}")

    # Top source IPs
    print(f"\n  --- Top Source IPs ---")
    for ip, count in report.source_ips.most_common(5):
        print(f"    {ip}: {count} events")

    # Top users
    print(f"\n  --- Most Active Users ---")
    for user, count in report.user_activity.most_common(5):
        print(f"    {user}: {count} events")

    # Detailed alerts
    if report.alerts:
        print(f"\n  --- Security Alerts ---")
        for i, alert in enumerate(report.alerts, 1):
            print(f"\n  [{i}] [{alert.severity}] {alert.event_name}")
            print(f"      Time: {alert.timestamp}")
            print(f"      User: {alert.user_identity}")
            print(f"      IP: {alert.source_ip}")
            print(f"      Region: {alert.region}")
            print(f"      Detail: {alert.description}")

    # Threat assessment
    critical = severity_counts.get("CRITICAL", 0)
    high = severity_counts.get("HIGH", 0)

    if critical >= 2:
        threat_level = "SEVERE — Possible active compromise"
    elif critical >= 1:
        threat_level = "HIGH — Immediate investigation required"
    elif high >= 3:
        threat_level = "ELEVATED — Review recommended"
    else:
        threat_level = "NORMAL — Routine activity"

    print(f"\n  Threat Level: {threat_level}")
    print("=" * 70 + "\n")


def main():
    """Run the CloudTrail analyzer."""
    import argparse

    parser = argparse.ArgumentParser(description="AWS CloudTrail Security Analyzer")
    parser.add_argument("--file", help="Path to CloudTrail JSON log file")
    parser.add_argument("--demo", action="store_true", help="Run with demo data")
    args = parser.parse_args()

    if args.file:
        try:
            with open(args.file, "r") as f:
                data = json.load(f)
                events = data.get("Records", data) if isinstance(data, dict) else data
        except (OSError, json.JSONDecodeError) as e:
            logger.error("Failed to read log file: %s", e)
            sys.exit(1)
    else:
        logger.info("Running in demo mode (use --file for real logs)")
        events = generate_demo_events()

    report = analyze_logs(events)
    print_report(report)

    # Exit code
    critical = sum(1 for a in report.alerts if a.severity == "CRITICAL")
    if critical > 0:
        sys.exit(2)
    elif report.alerts:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
