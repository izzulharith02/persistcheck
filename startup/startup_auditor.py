
#!/usr/bin/env python3
"""
startup_auditor.py - PersistCheck Startup Scripts Auditor.

Scans Linux startup and shell configuration files for
potentially suspicious persistence mechanisms.

READ-ONLY:
This module only reads and analyses files.
It does not execute, modify or delete system files.
"""

import os
import re
from pathlib import Path
from dataclasses import dataclass, asdict


# Module identification
MODULE = "startup"

# Severity levels used throughout PersistCheck
SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


# System-wide startup configuration files
SYSTEM_STARTUP_FILES = [
    "etc/rc.local",
    "etc/profile",
]

# Startup configuration directories
SYSTEM_STARTUP_DIRS = [
    "etc/init.d",
    "etc/profile.d",
]

# User shell configuration files
USER_STARTUP_FILES = [
    ".bashrc",
    ".profile",
]


# Temporary Finding class.
# This will be replaced with the shared Finding class
# from common.py when Member 1 completes that module.

@dataclass
class Finding:
    module: str
    severity: str
    title: str
    path: str
    detail: str
    mitre: str
    recommendation: str

    def to_dict(self):
        return asdict(self)
    
def scan_startup_files(root="/"):
    """
    Locate Linux startup and shell configuration files.

    Args:
        root: Root directory of the system being audited.

    Returns:
        A sorted list of startup file paths.
    """

    root_path = Path(root).resolve()
    targets = []

    # 1. Check fixed system startup files
    for relative_path in SYSTEM_STARTUP_FILES:

        file_path = root_path / relative_path

        if file_path.is_file() and not file_path.is_symlink():
            targets.append(file_path)

    # 2. Check system startup directories
    for relative_dir in SYSTEM_STARTUP_DIRS:

        directory_path = root_path / relative_dir

        if not directory_path.is_dir():
            continue

        if directory_path.is_symlink():
            continue

        try:
            for file_path in directory_path.iterdir():

                if file_path.is_file() and not file_path.is_symlink():
                    targets.append(file_path)

        except PermissionError:
            continue

    # 3. Check root and regular user home directories
    home_directories = [
        root_path / "root",
        root_path / "home"
    ]

    for home_path in home_directories:

        if not home_path.is_dir() or home_path.is_symlink():
            continue

        if home_path.name == "home":
            try:
                user_homes = [
                    path for path in home_path.iterdir()
                    if path.is_dir() and not path.is_symlink()
                ]
            except PermissionError:
                continue
        else:
            user_homes = [home_path]

        for user_home in user_homes:

            for filename in USER_STARTUP_FILES:

                file_path = user_home / filename

                if file_path.is_file() and not file_path.is_symlink():
                    targets.append(file_path)

    # Remove duplicates and return sorted results
    return sorted(set(targets))

# Suspicious patterns found in startup configurations.
# These are indicators for manual review, not proof of malware.

STARTUP_PATTERNS = [
    (
        r"\b(curl|wget)\b.{0,150}\|\s*(sh|bash)\b",
        "HIGH",
        "Remote content piped into a shell",
        "A command downloads content and passes it directly to a shell.",
        "T1546.004",
        "Verify the remote source and inspect the downloaded content."
    ),
    (
        r"/dev/(tcp|udp)/",
        "HIGH",
        "Network redirection detected",
        "Shell network redirection was found in a startup command.",
        "T1546.004",
        "Investigate the destination and purpose of the connection."
    ),
    (
        r"\b(nc|ncat|netcat|socat)\b",
        "MEDIUM",
        "Network utility command detected",
        "A network utility was found in a startup configuration.",
        "T1546.004",
        "Verify whether the network utility is required."
    ),
    (
        r"\bbase64\s+(-d|--decode)\b",
        "MEDIUM",
        "Base64 decoding command detected",
        "A command decodes Base64 data during startup.",
        "T1546.004",
        "Inspect the encoded data and verify its purpose."
    ),
    (
        r"\b(python[0-9.]*|perl|ruby)\s+(-c|-e)\b",
        "MEDIUM",
        "Inline interpreter command detected",
        "An inline interpreter command was found.",
        "T1546.004",
        "Review the inline code and confirm its legitimacy."
    ),
]


def check_suspicious_content(file_path, root="/"):
    """
    Inspect startup file contents for suspicious commands.

    The function reads files only. It never executes their contents.
    """

    findings = []
    root_path = Path(root).resolve()

    try:
        content = file_path.read_text(
            encoding="utf-8",
            errors="replace"
        )
    except OSError:
        return findings

    relative_path = file_path.relative_to(root_path)
    display_path = "/" + relative_path.as_posix()

    for line_number, line in enumerate(content.splitlines(), start=1):

        # Skip empty lines and comments
        stripped_line = line.strip()

        if not stripped_line or stripped_line.startswith("#"):
            continue

        # Check suspicious command patterns
        for pattern, severity, title, detail, mitre, recommendation in STARTUP_PATTERNS:

            if re.search(pattern, line, re.IGNORECASE):

                findings.append(
                    Finding(
                        module=MODULE,
                        severity=severity,
                        title=title,
                        path=display_path,
                        detail=f"{detail} Line: {line_number}.",
                        mitre=mitre,
                        recommendation=recommendation
                    )
                )

    return findings

def check_alias_overrides(file_path, root="/"):
    """
    Detect aliases that override important Linux commands.

    Currently checks:
    - sudo
    - ls

    This function only reads configuration files.
    """

    findings = []
    root_path = Path(root).resolve()

    try:
        content = file_path.read_text(
            encoding="utf-8",
            errors="replace"
        )
    except OSError:
        return findings

    relative_path = file_path.relative_to(root_path)
    display_path = "/" + relative_path.as_posix()

    # Detect aliases for sudo and ls
    alias_pattern = re.compile(
        r"^\s*alias\s+(sudo|ls)\s*=",
        re.IGNORECASE
    )

    for line_number, line in enumerate(content.splitlines(), start=1):

        stripped_line = line.strip()

        # Ignore empty lines and comments
        if not stripped_line or stripped_line.startswith("#"):
            continue

        match = alias_pattern.search(line)

        if not match:
            continue

        command = match.group(1).lower()

        if command == "sudo":
            severity = "MEDIUM"
            title = "Sudo alias override detected"
            detail = (
                f"The sudo command is modified through an alias "
                f"at line {line_number}."
            )
            recommendation = (
                "Review the alias and verify that it does not "
                "mislead users or alter expected command behaviour."
            )

        else:
            severity = "LOW"
            title = "Ls alias override detected"
            detail = (
                f"The ls command is modified through an alias "
                f"at line {line_number}."
            )
            recommendation = (
                "Review the alias and confirm that the modified "
                "directory listing behaviour is intentional."
            )

        findings.append(
            Finding(
                module=MODULE,
                severity=severity,
                title=title,
                path=display_path,
                detail=detail,
                mitre="T1546.004",
                recommendation=recommendation
            )
        )

    return findings

def audit(root="/"):
    """
    Main entry point for the Startup Auditor.

    Scans startup configuration files and returns
    all findings sorted by severity.

    Args:
        root: Root directory of the system being audited.

    Returns:
        A list of Finding objects.
    """

    root_path = Path(root).resolve()

    if not root_path.is_dir():
        raise ValueError(f"Invalid root directory: {root}")

    findings = []

    # Discover startup configuration files
    startup_files = scan_startup_files(root_path)

    # Analyse every discovered file
    for file_path in startup_files:

        # Detect suspicious commands
        findings.extend(
            check_suspicious_content(file_path, root_path)
        )

        # Detect sudo and ls alias overrides
        findings.extend(
            check_alias_overrides(file_path, root_path)
        )

    # Sort findings from highest to lowest severity
    findings.sort(
        key=lambda finding: SEVERITIES.index(finding.severity),
        reverse=True
    )

    return findings




    
    
