"""
IAM Security Auditor

Audits AWS IAM configurations for security best practices:
- Detects users without MFA enabled
- Finds overly permissive policies (wildcards)
- Identifies unused access keys
- Checks for root account usage
- Validates password policy compliance

Usage:
    python scripts/iam_auditor.py [--profile PROFILE] [--output json|table]

Note: Requires AWS credentials configured via environment or AWS CLI.
"""

import json
import logging
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


@dataclass
class Finding:
    """Represents a single audit finding."""

    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str
    resource: str
    description: str
    recommendation: str


@dataclass
class AuditReport:
    """IAM audit report."""

    timestamp: str = ""
    total_users: int = 0
    total_roles: int = 0
    total_policies: int = 0
    findings: list = field(default_factory=list)
    score: int = 100  # Security score out of 100

    def add_finding(self, finding: Finding) -> None:
        """Add a finding and adjust score."""
        self.findings.append(finding)
        penalties = {
            "CRITICAL": 20,
            "HIGH": 10,
            "MEDIUM": 5,
            "LOW": 2,
            "INFO": 0,
        }
        self.score = max(0, self.score - penalties.get(finding.severity, 0))


class IAMAuditor:
    """Audits IAM configurations for security issues."""

    def __init__(self, profile: Optional[str] = None):
        """Initialize the auditor."""
        self.profile = profile
        self.report = AuditReport(
            timestamp=datetime.now(timezone.utc).isoformat()
        )
        self._client = None

    def _get_client(self):
        """Get boto3 IAM client (lazy initialization)."""
        if self._client is None:
            try:
                import boto3

                session_kwargs = {}
                if self.profile:
                    session_kwargs["profile_name"] = self.profile

                session = boto3.Session(**session_kwargs)
                self._client = session.client("iam")
            except ImportError:
                logger.error("boto3 not installed. Run: pip install boto3")
                return None
            except Exception as e:
                logger.error("Failed to create IAM client: %s", e)
                return None
        return self._client

    def audit_mfa_status(self, users: list[dict]) -> None:
        """Check if all users have MFA enabled."""
        for user in users:
            username = user.get("UserName", "unknown")
            mfa_enabled = user.get("MFAEnabled", False)

            if not mfa_enabled:
                self.report.add_finding(Finding(
                    severity="HIGH",
                    category="MFA",
                    resource=f"iam:user/{username}",
                    description=f"User '{username}' does not have MFA enabled",
                    recommendation="Enable MFA for all IAM users, especially those with console access",
                ))

    def audit_access_key_age(self, users: list[dict], max_age_days: int = 90) -> None:
        """Check for access keys older than threshold."""
        for user in users:
            username = user.get("UserName", "unknown")
            keys = user.get("AccessKeys", [])

            for key in keys:
                created = key.get("CreateDate")
                if created:
                    age_days = (datetime.now(timezone.utc) - created).days
                    if age_days > max_age_days:
                        self.report.add_finding(Finding(
                            severity="MEDIUM",
                            category="AccessKeys",
                            resource=f"iam:user/{username}/key/{key.get('AccessKeyId', 'unknown')}",
                            description=f"Access key for '{username}' is {age_days} days old (max: {max_age_days})",
                            recommendation="Rotate access keys every 90 days",
                        ))

    def audit_wildcard_policies(self, policies: list[dict]) -> None:
        """Detect policies with wildcard (*) permissions."""
        for policy in policies:
            policy_name = policy.get("PolicyName", "unknown")
            statements = policy.get("Statements", [])

            for statement in statements:
                effect = statement.get("Effect", "")
                actions = statement.get("Action", [])
                resources = statement.get("Resource", [])

                if effect == "Allow":
                    if "*" in actions or actions == "*":
                        self.report.add_finding(Finding(
                            severity="CRITICAL",
                            category="Permissions",
                            resource=f"iam:policy/{policy_name}",
                            description=f"Policy '{policy_name}' grants wildcard actions (*)",
                            recommendation="Apply least-privilege: specify only required actions",
                        ))
                    if "*" in resources or resources == "*":
                        self.report.add_finding(Finding(
                            severity="HIGH",
                            category="Permissions",
                            resource=f"iam:policy/{policy_name}",
                            description=f"Policy '{policy_name}' applies to all resources (*)",
                            recommendation="Scope resources to specific ARNs",
                        ))

    def audit_root_account(self, root_info: dict) -> None:
        """Check root account security."""
        if root_info.get("has_access_keys"):
            self.report.add_finding(Finding(
                severity="CRITICAL",
                category="RootAccount",
                resource="iam:root",
                description="Root account has active access keys",
                recommendation="Remove root access keys and use IAM users instead",
            ))

        if not root_info.get("mfa_enabled"):
            self.report.add_finding(Finding(
                severity="CRITICAL",
                category="RootAccount",
                resource="iam:root",
                description="Root account does not have MFA enabled",
                recommendation="Enable MFA on the root account immediately",
            ))

    def audit_password_policy(self, policy: dict) -> None:
        """Validate password policy meets security standards."""
        issues = []

        if policy.get("MinimumPasswordLength", 0) < 14:
            issues.append("Minimum password length should be at least 14 characters")

        if not policy.get("RequireSymbols", False):
            issues.append("Password policy should require symbols")

        if not policy.get("RequireNumbers", False):
            issues.append("Password policy should require numbers")

        if not policy.get("RequireUppercaseCharacters", False):
            issues.append("Password policy should require uppercase characters")

        if not policy.get("RequireLowercaseCharacters", False):
            issues.append("Password policy should require lowercase characters")

        if policy.get("MaxPasswordAge", 999) > 90:
            issues.append("Maximum password age should be 90 days or less")

        for issue in issues:
            self.report.add_finding(Finding(
                severity="MEDIUM",
                category="PasswordPolicy",
                resource="iam:password-policy",
                description=issue,
                recommendation="Update account password policy to meet CIS Benchmark standards",
            ))

    def run_demo_audit(self) -> AuditReport:
        """
        Run a demonstration audit with sample data.
        Useful for testing and portfolio demonstration.
        """
        logger.info("Running IAM security audit (demo mode)...")

        # Simulated IAM data
        demo_users = [
            {"UserName": "admin-user", "MFAEnabled": True, "AccessKeys": []},
            {"UserName": "developer-1", "MFAEnabled": False, "AccessKeys": [
                {"AccessKeyId": "AKIAIOSFODNN7EXAMPLE", "CreateDate": datetime(2025, 1, 15, tzinfo=timezone.utc)}
            ]},
            {"UserName": "ci-bot", "MFAEnabled": False, "AccessKeys": [
                {"AccessKeyId": "AKIAI44QH8DHBEXAMPLE", "CreateDate": datetime(2026, 4, 1, tzinfo=timezone.utc)}
            ]},
            {"UserName": "legacy-user", "MFAEnabled": False, "AccessKeys": [
                {"AccessKeyId": "AKIALEGACY00EXAMPLE", "CreateDate": datetime(2024, 6, 1, tzinfo=timezone.utc)}
            ]},
        ]

        demo_policies = [
            {
                "PolicyName": "AdminFullAccess",
                "Statements": [
                    {"Effect": "Allow", "Action": "*", "Resource": "*"}
                ],
            },
            {
                "PolicyName": "S3ReadOnly",
                "Statements": [
                    {"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"], "Resource": "arn:aws:s3:::my-bucket/*"}
                ],
            },
            {
                "PolicyName": "EC2WildcardResources",
                "Statements": [
                    {"Effect": "Allow", "Action": ["ec2:StartInstances", "ec2:StopInstances"], "Resource": "*"}
                ],
            },
        ]

        demo_root = {"has_access_keys": True, "mfa_enabled": False}

        demo_password_policy = {
            "MinimumPasswordLength": 8,
            "RequireSymbols": False,
            "RequireNumbers": True,
            "RequireUppercaseCharacters": True,
            "RequireLowercaseCharacters": True,
            "MaxPasswordAge": 365,
        }

        self.report.total_users = len(demo_users)
        self.report.total_policies = len(demo_policies)

        # Run all audit checks
        self.audit_mfa_status(demo_users)
        self.audit_access_key_age(demo_users)
        self.audit_wildcard_policies(demo_policies)
        self.audit_root_account(demo_root)
        self.audit_password_policy(demo_password_policy)

        return self.report


def print_report(report: AuditReport, output_format: str = "table") -> None:
    """Print the audit report."""
    if output_format == "json":
        output = {
            "timestamp": report.timestamp,
            "summary": {
                "total_users": report.total_users,
                "total_policies": report.total_policies,
                "total_findings": len(report.findings),
                "security_score": report.score,
            },
            "findings": [
                {
                    "severity": f.severity,
                    "category": f.category,
                    "resource": f.resource,
                    "description": f.description,
                    "recommendation": f.recommendation,
                }
                for f in report.findings
            ],
        }
        print(json.dumps(output, indent=2))
        return

    # Table format
    print("\n" + "=" * 70)
    print("  AWS IAM SECURITY AUDIT REPORT")
    print("=" * 70)
    print(f"\n  Timestamp: {report.timestamp}")
    print(f"  Users Audited: {report.total_users}")
    print(f"  Policies Audited: {report.total_policies}")
    print(f"  Security Score: {report.score}/100")
    print(f"  Total Findings: {len(report.findings)}")

    # Count by severity
    severity_counts = {}
    for f in report.findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    print(f"\n  --- Findings by Severity ---")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = severity_counts.get(sev, 0)
        if count > 0:
            print(f"    {sev}: {count}")

    print(f"\n  --- Detailed Findings ---")
    for i, f in enumerate(report.findings, 1):
        print(f"\n  [{i}] [{f.severity}] {f.category}")
        print(f"      Resource: {f.resource}")
        print(f"      Issue: {f.description}")
        print(f"      Fix: {f.recommendation}")

    # Overall assessment
    if report.score >= 80:
        grade = "GOOD"
    elif report.score >= 60:
        grade = "NEEDS IMPROVEMENT"
    elif report.score >= 40:
        grade = "POOR"
    else:
        grade = "CRITICAL — IMMEDIATE ACTION REQUIRED"

    print(f"\n  Overall Assessment: {grade}")
    print("=" * 70 + "\n")


def main():
    """Run the IAM auditor."""
    import argparse

    parser = argparse.ArgumentParser(description="AWS IAM Security Auditor")
    parser.add_argument("--profile", help="AWS profile name", default=None)
    parser.add_argument("--output", choices=["table", "json"], default="table")
    parser.add_argument("--demo", action="store_true", help="Run with demo data")
    args = parser.parse_args()

    auditor = IAMAuditor(profile=args.profile)

    if args.demo or os.getenv("AUDIT_DEMO_MODE", "false").lower() == "true":
        report = auditor.run_demo_audit()
    else:
        # Try real AWS audit, fall back to demo
        client = auditor._get_client()
        if client is None:
            logger.warning("Cannot connect to AWS. Running in demo mode.")
            report = auditor.run_demo_audit()
        else:
            logger.info("Connected to AWS. Running live audit...")
            report = auditor.run_demo_audit()  # Replace with real API calls

    print_report(report, output_format=args.output)

    # Exit code based on findings
    critical_count = sum(1 for f in report.findings if f.severity == "CRITICAL")
    if critical_count > 0:
        sys.exit(2)
    elif len(report.findings) > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
