"""
Terraform Compliance Scanner

Scans Terraform files for security misconfigurations:
- Public S3 buckets
- Unencrypted resources
- Overly permissive security groups
- Missing logging/monitoring
- Hardcoded credentials

Usage:
    python scripts/terraform_compliance.py [directory]
"""

import logging
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)


@dataclass
class ComplianceFinding:
    """A single compliance finding."""

    rule_id: str
    severity: str
    file: str
    line: int
    resource: str
    description: str
    remediation: str


# Compliance rules
RULES = [
    {
        "id": "TF-SEC-001",
        "name": "Public S3 Bucket ACL",
        "severity": "CRITICAL",
        "pattern": r'acl\s*=\s*"public-read"',
        "description": "S3 bucket has public-read ACL",
        "remediation": "Set acl = \"private\" and use bucket policies for access control",
    },
    {
        "id": "TF-SEC-002",
        "name": "Open Security Group Ingress",
        "severity": "HIGH",
        "pattern": r'cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]',
        "description": "Security group allows ingress from 0.0.0.0/0",
        "remediation": "Restrict CIDR blocks to specific IP ranges",
    },
    {
        "id": "TF-SEC-003",
        "name": "Unencrypted EBS Volume",
        "severity": "HIGH",
        "pattern": r'encrypted\s*=\s*false',
        "description": "EBS volume encryption is disabled",
        "remediation": "Set encrypted = true for all EBS volumes",
    },
    {
        "id": "TF-SEC-004",
        "name": "Hardcoded Access Key",
        "severity": "CRITICAL",
        "pattern": r'(access_key|secret_key)\s*=\s*"[A-Za-z0-9/+=]+"',
        "description": "Hardcoded AWS credentials detected",
        "remediation": "Use IAM roles, environment variables, or AWS Secrets Manager",
    },
    {
        "id": "TF-SEC-005",
        "name": "Missing Encryption at Rest",
        "severity": "MEDIUM",
        "pattern": r'resource\s+"aws_rds_instance"(?:(?!storage_encrypted).)*$',
        "description": "RDS instance may not have encryption at rest enabled",
        "remediation": "Add storage_encrypted = true to RDS instances",
    },
    {
        "id": "TF-SEC-006",
        "name": "Public IP on Instance",
        "severity": "MEDIUM",
        "pattern": r'associate_public_ip_address\s*=\s*true',
        "description": "EC2 instance has public IP association enabled",
        "remediation": "Use private subnets with NAT gateway for internet access",
    },
    {
        "id": "TF-SEC-007",
        "name": "Missing CloudTrail",
        "severity": "HIGH",
        "pattern": r'enable_logging\s*=\s*false',
        "description": "CloudTrail logging is disabled",
        "remediation": "Set enable_logging = true for audit compliance",
    },
    {
        "id": "TF-SEC-008",
        "name": "Wildcard IAM Policy",
        "severity": "CRITICAL",
        "pattern": r'"Action"\s*:\s*"\*"',
        "description": "IAM policy grants wildcard actions",
        "remediation": "Apply least-privilege: specify only required actions",
    },
    {
        "id": "TF-SEC-009",
        "name": "Missing S3 Versioning",
        "severity": "LOW",
        "pattern": r'resource\s+"aws_s3_bucket"(?:(?!versioning).)*}',
        "description": "S3 bucket may not have versioning enabled",
        "remediation": "Enable versioning for data protection and recovery",
    },
    {
        "id": "TF-SEC-010",
        "name": "HTTP Instead of HTTPS",
        "severity": "HIGH",
        "pattern": r'protocol\s*=\s*"HTTP"',
        "description": "Load balancer listener uses HTTP instead of HTTPS",
        "remediation": "Use HTTPS with a valid TLS certificate",
    },
]


def scan_file(filepath: Path) -> list[ComplianceFinding]:
    """Scan a single Terraform file for compliance issues."""
    findings = []

    try:
        content = filepath.read_text(encoding="utf-8")
        lines = content.splitlines()
    except (OSError, PermissionError) as e:
        logger.warning("Cannot read %s: %s", filepath, e)
        return findings

    for rule in RULES:
        pattern = re.compile(rule["pattern"], re.MULTILINE | re.IGNORECASE)

        for match in pattern.finditer(content):
            # Calculate line number
            line_num = content[:match.start()].count("\n") + 1

            # Try to find the resource name
            resource = "unknown"
            for i in range(line_num - 1, max(0, line_num - 20), -1):
                if i < len(lines):
                    res_match = re.match(r'resource\s+"(\w+)"\s+"(\w+)"', lines[i])
                    if res_match:
                        resource = f"{res_match.group(1)}.{res_match.group(2)}"
                        break

            findings.append(ComplianceFinding(
                rule_id=rule["id"],
                severity=rule["severity"],
                file=str(filepath),
                line=line_num,
                resource=resource,
                description=rule["description"],
                remediation=rule["remediation"],
            ))

    return findings


def scan_directory(directory: str = ".") -> list[ComplianceFinding]:
    """Scan all Terraform files in a directory."""
    all_findings = []
    root = Path(directory)

    tf_files = list(root.rglob("*.tf"))
    logger.info("Found %d Terraform files to scan", len(tf_files))

    for tf_file in tf_files:
        # Skip .terraform directory
        if ".terraform" in str(tf_file):
            continue
        findings = scan_file(tf_file)
        all_findings.extend(findings)

    return all_findings


def print_results(findings: list[ComplianceFinding]) -> None:
    """Print scan results."""
    print("\n" + "=" * 70)
    print("  TERRAFORM COMPLIANCE SCAN REPORT")
    print("=" * 70)

    if not findings:
        print("\n  ✓ No compliance issues found. All checks passed.")
        print("=" * 70 + "\n")
        return

    # Summary
    severity_counts = {}
    for f in findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    print(f"\n  Total Issues: {len(findings)}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = severity_counts.get(sev, 0)
        if count > 0:
            print(f"    {sev}: {count}")

    # Details
    print(f"\n  --- Findings ---")
    for i, f in enumerate(findings, 1):
        print(f"\n  [{f.rule_id}] [{f.severity}]")
        print(f"    File: {f.file}:{f.line}")
        print(f"    Resource: {f.resource}")
        print(f"    Issue: {f.description}")
        print(f"    Fix: {f.remediation}")

    # Pass/Fail
    critical = severity_counts.get("CRITICAL", 0)
    high = severity_counts.get("HIGH", 0)

    if critical > 0:
        status = "FAILED — Critical issues must be resolved"
    elif high > 0:
        status = "WARNING — High severity issues should be addressed"
    else:
        status = "PASSED with advisories"

    print(f"\n  Status: {status}")
    print("=" * 70 + "\n")


def main():
    """Run the Terraform compliance scanner."""
    target = sys.argv[1] if len(sys.argv) > 1 else "."

    if not os.path.isdir(target):
        logger.error("Directory not found: %s", target)
        sys.exit(1)

    logger.info("Scanning Terraform files in: %s", os.path.abspath(target))
    findings = scan_directory(target)
    print_results(findings)

    # Exit codes
    critical = sum(1 for f in findings if f.severity == "CRITICAL")
    if critical > 0:
        sys.exit(2)
    elif findings:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
