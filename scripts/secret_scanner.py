"""
Secret Scanner Script

Scans files for accidentally committed secrets, API keys,
and credentials using regex pattern matching.
"""

import logging
import os
import re
import sys
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

# Patterns that indicate potential secrets
SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40}",
    "GitHub Token": r"ghp_[A-Za-z0-9]{36}",
    "Generic API Key": r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"][A-Za-z0-9]{20,}['\"]",
    "Private Key": r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----",
    "Generic Secret": r"(?i)(secret|password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
    "Slack Token": r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}",
    "JWT Token": r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+",
}

# File extensions to scan
SCAN_EXTENSIONS = {
    ".py", ".js", ".ts", ".yml", ".yaml", ".json",
    ".env", ".cfg", ".conf", ".ini", ".toml", ".tf",
    ".sh", ".bash", ".md", ".txt",
}

# Directories to skip
SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", "venv",
    ".venv", "env", ".terraform", "dist", "build",
}


def scan_file(filepath: Path) -> list[dict]:
    """Scan a single file for secret patterns."""
    findings = []

    try:
        content = filepath.read_text(encoding="utf-8", errors="ignore")
    except (OSError, PermissionError) as e:
        logger.warning("Cannot read %s: %s", filepath, e)
        return findings

    for line_num, line in enumerate(content.splitlines(), start=1):
        for name, pattern in SECRET_PATTERNS.items():
            if re.search(pattern, line):
                findings.append({
                    "file": str(filepath),
                    "line": line_num,
                    "type": name,
                    "preview": line[:80] + "..." if len(line) > 80 else line,
                })

    return findings


def scan_directory(root: str = ".") -> list[dict]:
    """Recursively scan a directory for secrets."""
    all_findings = []
    root_path = Path(root)

    for dirpath, dirnames, filenames in os.walk(root_path):
        # Skip excluded directories
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]

        for filename in filenames:
            filepath = Path(dirpath) / filename
            if filepath.suffix in SCAN_EXTENSIONS:
                findings = scan_file(filepath)
                all_findings.extend(findings)

    return all_findings


def main():
    """Run the secret scanner."""
    target = sys.argv[1] if len(sys.argv) > 1 else "."

    logger.info("Scanning directory: %s", os.path.abspath(target))
    findings = scan_directory(target)

    if findings:
        logger.warning("Found %d potential secret(s):", len(findings))
        for f in findings:
            logger.warning(
                "  [%s] %s:%d — %s",
                f["type"],
                f["file"],
                f["line"],
                f["preview"],
            )
        sys.exit(1)
    else:
        logger.info("No secrets detected. Clean scan.")
        sys.exit(0)


if __name__ == "__main__":
    main()
