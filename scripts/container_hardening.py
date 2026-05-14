"""
Container Hardening Checker

Analyzes Dockerfiles for security best practices:
- Running as non-root
- Using minimal base images
- Pinned image versions
- No secrets in build args
- Multi-stage builds
- Reduced attack surface

Usage:
    python scripts/container_hardening.py [Dockerfile path]
"""

import logging
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


@dataclass
class DockerFinding:
    """A Dockerfile security finding."""

    rule_id: str
    severity: str
    line: int
    description: str
    remediation: str


# Security rules for Dockerfile analysis
RULES = {
    "DH-001": {
        "name": "No USER instruction",
        "severity": "HIGH",
        "description": "Container runs as root (no USER instruction found)",
        "remediation": "Add 'USER nonroot' or 'USER 1000' before CMD/ENTRYPOINT",
    },
    "DH-002": {
        "name": "Unpinned base image",
        "severity": "MEDIUM",
        "description": "Base image uses 'latest' tag or no tag",
        "remediation": "Pin base image to specific version (e.g., python:3.11-slim)",
    },
    "DH-003": {
        "name": "Using full base image",
        "severity": "LOW",
        "description": "Base image is not a minimal variant (slim/alpine/distroless)",
        "remediation": "Use slim, alpine, or distroless base images to reduce attack surface",
    },
    "DH-004": {
        "name": "Secret in ENV/ARG",
        "severity": "CRITICAL",
        "description": "Potential secret exposed in ENV or ARG instruction",
        "remediation": "Use Docker secrets or runtime environment variables instead",
    },
    "DH-005": {
        "name": "No HEALTHCHECK",
        "severity": "LOW",
        "description": "No HEALTHCHECK instruction found",
        "remediation": "Add HEALTHCHECK for container orchestration readiness",
    },
    "DH-006": {
        "name": "ADD instead of COPY",
        "severity": "LOW",
        "description": "ADD instruction used (can auto-extract archives and fetch URLs)",
        "remediation": "Use COPY unless you specifically need ADD's extraction features",
    },
    "DH-007": {
        "name": "Curl/wget in RUN",
        "severity": "MEDIUM",
        "description": "Downloading files in RUN without checksum verification",
        "remediation": "Verify downloaded files with checksums or use COPY from build context",
    },
    "DH-008": {
        "name": "No .dockerignore",
        "severity": "MEDIUM",
        "description": "No .dockerignore file found (may include secrets in build context)",
        "remediation": "Create .dockerignore to exclude .git, .env, secrets, and node_modules",
    },
    "DH-009": {
        "name": "Privileged port",
        "severity": "LOW",
        "description": "Container exposes a privileged port (<1024)",
        "remediation": "Use non-privileged ports (>=1024) when running as non-root",
    },
    "DH-010": {
        "name": "No multi-stage build",
        "severity": "LOW",
        "description": "Single-stage build may include build tools in final image",
        "remediation": "Use multi-stage builds to separate build and runtime environments",
    },
}

# Patterns that suggest secrets
SECRET_PATTERNS = [
    r"(?i)(password|passwd|pwd)\s*=",
    r"(?i)(secret|token|api_key|apikey)\s*=",
    r"(?i)(aws_access_key|aws_secret)",
    r"(?i)(private_key|ssh_key)",
]

# Minimal base image indicators
MINIMAL_IMAGES = ["slim", "alpine", "distroless", "scratch", "busybox", "minimal"]


def analyze_dockerfile(filepath: str) -> list[DockerFinding]:
    """Analyze a Dockerfile for security issues."""
    findings = []
    path = Path(filepath)

    if not path.exists():
        logger.error("Dockerfile not found: %s", filepath)
        return findings

    content = path.read_text(encoding="utf-8")
    lines = content.splitlines()

    has_user = False
    has_healthcheck = False
    has_multistage = False
    from_count = 0
    base_images = []

    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()

        # Skip comments and empty lines
        if not stripped or stripped.startswith("#"):
            continue

        # Check FROM instructions
        if stripped.upper().startswith("FROM"):
            from_count += 1
            image_match = re.match(r"FROM\s+(\S+)", stripped, re.IGNORECASE)
            if image_match:
                image = image_match.group(1)
                base_images.append(image)

                # Check for unpinned images
                if image.endswith(":latest") or ":" not in image:
                    findings.append(DockerFinding(
                        rule_id="DH-002",
                        severity="MEDIUM",
                        line=line_num,
                        description=f"Unpinned base image: {image}",
                        remediation=RULES["DH-002"]["remediation"],
                    ))

                # Check for non-minimal images
                if not any(m in image.lower() for m in MINIMAL_IMAGES):
                    if ":" in image:
                        findings.append(DockerFinding(
                            rule_id="DH-003",
                            severity="LOW",
                            line=line_num,
                            description=f"Non-minimal base image: {image}",
                            remediation=RULES["DH-003"]["remediation"],
                        ))

        # Check USER instruction
        if stripped.upper().startswith("USER"):
            has_user = True

        # Check HEALTHCHECK
        if stripped.upper().startswith("HEALTHCHECK"):
            has_healthcheck = True

        # Check for secrets in ENV/ARG
        if stripped.upper().startswith(("ENV ", "ARG ")):
            for pattern in SECRET_PATTERNS:
                if re.search(pattern, stripped):
                    findings.append(DockerFinding(
                        rule_id="DH-004",
                        severity="CRITICAL",
                        line=line_num,
                        description=f"Potential secret in instruction: {stripped[:60]}",
                        remediation=RULES["DH-004"]["remediation"],
                    ))
                    break

        # Check ADD usage
        if stripped.upper().startswith("ADD "):
            findings.append(DockerFinding(
                rule_id="DH-006",
                severity="LOW",
                line=line_num,
                description="ADD instruction used instead of COPY",
                remediation=RULES["DH-006"]["remediation"],
            ))

        # Check for downloads without verification
        if re.search(r"(curl|wget)\s+", stripped, re.IGNORECASE):
            if not re.search(r"(sha256|checksum|verify|gpg)", stripped, re.IGNORECASE):
                findings.append(DockerFinding(
                    rule_id="DH-007",
                    severity="MEDIUM",
                    line=line_num,
                    description="File download without checksum verification",
                    remediation=RULES["DH-007"]["remediation"],
                ))

        # Check EXPOSE for privileged ports
        if stripped.upper().startswith("EXPOSE"):
            port_match = re.findall(r"\d+", stripped)
            for port in port_match:
                if int(port) < 1024:
                    findings.append(DockerFinding(
                        rule_id="DH-009",
                        severity="LOW",
                        line=line_num,
                        description=f"Privileged port exposed: {port}",
                        remediation=RULES["DH-009"]["remediation"],
                    ))

    # Post-analysis checks
    if not has_user:
        findings.append(DockerFinding(
            rule_id="DH-001",
            severity="HIGH",
            line=0,
            description="No USER instruction — container runs as root",
            remediation=RULES["DH-001"]["remediation"],
        ))

    if not has_healthcheck:
        findings.append(DockerFinding(
            rule_id="DH-005",
            severity="LOW",
            line=0,
            description="No HEALTHCHECK instruction found",
            remediation=RULES["DH-005"]["remediation"],
        ))

    has_multistage = from_count > 1
    if not has_multistage:
        findings.append(DockerFinding(
            rule_id="DH-010",
            severity="LOW",
            line=0,
            description="Single-stage build detected",
            remediation=RULES["DH-010"]["remediation"],
        ))

    # Check for .dockerignore
    dockerfile_dir = path.parent
    if not (dockerfile_dir / ".dockerignore").exists():
        findings.append(DockerFinding(
            rule_id="DH-008",
            severity="MEDIUM",
            line=0,
            description="No .dockerignore file found in project",
            remediation=RULES["DH-008"]["remediation"],
        ))

    return findings


def print_results(findings: list[DockerFinding], filepath: str) -> None:
    """Print scan results."""
    print("\n" + "=" * 70)
    print("  CONTAINER HARDENING SCAN REPORT")
    print("=" * 70)
    print(f"\n  Target: {filepath}")
    print(f"  Total Findings: {len(findings)}")

    if not findings:
        print("\n  All checks passed. Dockerfile follows security best practices.")
        print("=" * 70 + "\n")
        return

    # Summary
    severity_counts = {}
    for f in findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    print(f"\n  --- By Severity ---")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = severity_counts.get(sev, 0)
        if count > 0:
            print(f"    {sev}: {count}")

    print(f"\n  --- Findings ---")
    for i, f in enumerate(findings, 1):
        line_info = f"line {f.line}" if f.line > 0 else "global"
        print(f"\n  [{f.rule_id}] [{f.severity}] ({line_info})")
        print(f"      Issue: {f.description}")
        print(f"      Fix: {f.remediation}")

    # Score
    critical = severity_counts.get("CRITICAL", 0)
    high = severity_counts.get("HIGH", 0)

    if critical > 0:
        grade = "F — Critical security issues"
    elif high > 0:
        grade = "C — Needs hardening"
    elif len(findings) > 3:
        grade = "B — Room for improvement"
    else:
        grade = "A — Minor improvements possible"

    print(f"\n  Security Grade: {grade}")
    print("=" * 70 + "\n")


def main():
    """Run the container hardening checker."""
    target = sys.argv[1] if len(sys.argv) > 1 else "Dockerfile"

    if not Path(target).exists():
        logger.error("File not found: %s", target)
        sys.exit(1)

    logger.info("Scanning: %s", target)
    findings = analyze_dockerfile(target)
    print_results(findings, target)

    critical = sum(1 for f in findings if f.severity == "CRITICAL")
    if critical > 0:
        sys.exit(2)
    elif findings:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
