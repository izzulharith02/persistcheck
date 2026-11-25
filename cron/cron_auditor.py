
#!/usr/bin/env python3
"""
MHK: PersistCheck Cron Jobs Auditor.
MHK: Read-only inspection of cron jobs and referenced scripts.
MHK: Never executes, modifies, or deletes cron jobs.
"""

import argparse
import glob
import json
import os
import re
import shlex
import stat

from dataclasses import dataclass, asdict


MODULE = "cron"

SEVERITIES = [
    "INFO",
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL"
]

CRON_FILES = [
    "/etc/crontab",
    "/etc/cron.d/*",
]

CRON_DIRS = [
    "/etc/cron.hourly",
    "/etc/cron.daily",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
]


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


# MHK: PATH - Convert audited paths into paths under the selected root.
def on_disk(root, sys_path):
    return os.path.join(root, sys_path.lstrip("/"))


# MHK: DISCOVERY - Find cron configuration files without modifying them.
def discover_cron_files(root):

    root = os.path.abspath(root)

    paths = []

    # Discover standard cron configuration files.
    for pattern in CRON_FILES:
        paths.extend(glob.glob(on_disk(root, pattern)))

    # Discover periodic cron directories.
    for directory in CRON_DIRS:

        real_dir = on_disk(root, directory)

        if os.path.isdir(real_dir):

            for name in sorted(os.listdir(real_dir)):
                paths.append(os.path.join(real_dir, name))

    # Discover user-specific cron files.
    user_patterns = [
        "/var/spool/cron/crontabs/*",
        "/var/spool/cron/*",
    ]

    for pattern in user_patterns:
        paths.extend(glob.glob(on_disk(root, pattern)))

    # Remove duplicates and convert paths to Linux format.
    result = []

    for path in sorted(set(paths)):

        if os.path.isfile(path):

            relative_path = os.path.relpath(path, root)

            linux_path = relative_path.replace(
                os.sep, "/"
            )

            result.append("/" + linux_path.lstrip("/"))

    return result


# MHK: PARSER - Read cron files and extract scheduled commands.
def parse_cron_file(real_path, system_file=True):

    entries = []

    try:

        with open(
            real_path,
            "r",
            encoding="utf-8",
            errors="replace"
        ) as handle:

            for line_number, raw_line in enumerate(handle, start=1):

                line = raw_line.strip()

                if not line or line.startswith("#"):
                    continue

                # Ignore environment variable assignments.
                if re.match(
                    r"^[A-Za-z_][A-Za-z0-9_]*\s*=",
                    line
                ):
                    continue

                try:
                    fields = shlex.split(
                        line,
                        comments=True
                    )

                except ValueError:
                    continue

                if not fields:
                    continue

                # MHK: SPECIAL SCHEDULES - Support cron shortcuts.
                special_schedules = {
                    "@reboot",
                    "@yearly",
                    "@annually",
                    "@monthly",
                    "@weekly",
                    "@daily",
                    "@midnight",
                    "@hourly"
                }

                if fields[0] in special_schedules:

                    schedule = fields[0]

                    if system_file:

                        if len(fields) < 3:
                            continue

                        username = fields[1]
                        command = " ".join(fields[2:])

                    else:

                        if len(fields) < 2:
                            continue

                        username = "unknown"
                        command = " ".join(fields[1:])

                # MHK: STANDARD SCHEDULES - Parse five-field expressions.
                elif system_file:

                    if len(fields) < 7:
                        continue

                    schedule = " ".join(fields[:5])
                    username = fields[5]
                    command = " ".join(fields[6:])

                else:

                    if len(fields) < 6:
                        continue

                    schedule = " ".join(fields[:5])
                    username = "unknown"
                    command = " ".join(fields[5:])

                entries.append({
                    "line": line_number,
                    "schedule": schedule,
                    "user": username,
                    "command": command,
                })

    except OSError:
        return []

    return entries


# MHK: PERMISSIONS - Inspect file ownership and write permissions.
def check_permissions(real_path, root="/"):

    reasons = []

    # Unix permission bits cannot be reliably audited on Windows.
    if os.name != "posix":
        return reasons

    # MHK: FILE PERMISSIONS - Inspect the cron file or referenced script.
    try:

        info = os.stat(real_path)
        mode = info.st_mode

        if mode & stat.S_IWOTH:
            reasons.append("File is world-writable")

        if mode & stat.S_IWGRP:
            reasons.append("File is group-writable")

        if info.st_uid != 0:
            reasons.append("File is not owned by root")

    except OSError:

        reasons.append(
            "Unable to inspect file permissions"
        )

        return reasons

    # MHK: DIRECTORY PERMISSIONS - Inspect parent directories within audit root.
    root_abs = os.path.abspath(root)

    current = os.path.dirname(
        os.path.abspath(real_path)
    )

    while True:

        try:

            if os.path.commonpath(
                [root_abs, current]
            ) != root_abs:

                break

        except ValueError:
            break

        try:

            directory_info = os.stat(current)
            directory_mode = directory_info.st_mode

            if directory_mode & stat.S_IWOTH:

                reasons.append(
                    "Parent directory is world-writable: "
                    + current
                )

            if directory_mode & stat.S_IWGRP:

                reasons.append(
                    "Parent directory is group-writable: "
                    + current
                )

        except OSError:

            reasons.append(
                "Unable to inspect parent directory permissions: "
                + current
            )

        if current == root_abs:
            break

        parent = os.path.dirname(current)

        if parent == current:
            break

        current = parent

    return reasons


# MHK: COMMAND PARSING - Identify scripts referenced by cron commands.
def extract_script_paths(command, root="/"):

    paths = []

    try:
        fields = shlex.split(command)

    except ValueError:
        return paths

    if not fields:
        return paths

    # MHK: INTERPRETERS - Recognise common script interpreters.
    interpreters = {
        "python",
        "python2",
        "python3",
        "perl",
        "ruby",
        "bash",
        "sh",
        "dash",
        "zsh",
        "php",
        "node"
    }

    # MHK: COMMAND - Identify the executable name.
    executable = os.path.basename(fields[0])

    # MHK: INTERPRETER - Look for an existing script argument.
    if executable in interpreters:

        for field in fields[1:]:

            if field.startswith("-"):
                continue

            if not os.path.isabs(field):
                continue

            real_script = on_disk(root, field)

            if os.path.isfile(real_script):

                paths.append(field)
                break

    # MHK: DIRECT SCRIPT - Check directly executed script files.
    elif os.path.isabs(fields[0]):

        real_script = on_disk(root, fields[0])

        if os.path.isfile(real_script) and fields[0].endswith((
            ".sh",
            ".py",
            ".pl",
            ".rb",
            ".php",
            ".js"
        )):

            paths.append(fields[0])

    return sorted(set(paths))


# MHK: AUDIT - Inspect cron files and their scheduled commands.
def audit(root="/"):

    root = os.path.abspath(root)

    findings = []

    for cron_path in discover_cron_files(root):

        real_path = on_disk(root, cron_path)

        is_periodic = any(
            cron_path.startswith(directory + "/")
            for directory in CRON_DIRS
        )

        # MHK: PERIODIC - Inspect scripts run by periodic cron directories.
        if is_periodic:

            reasons = check_permissions(
                real_path,
                root
            )

            if reasons:

                severity = (
                    "HIGH"
                    if any(
                        "writable" in item.lower()
                        for item in reasons
                    )
                    else "MEDIUM"
                )

                findings.append(Finding(
                    MODULE,
                    severity,
                    "Insecure periodic cron script permissions",
                    cron_path,
                    "; ".join(reasons),
                    "T1053.003",
                    "Review ownership and permissions of this cron script."
                ))

            continue

        # Identify user-specific crontabs.
        is_user_crontab = cron_path.startswith(
            "/var/spool/cron/"
        )

        entries = parse_cron_file(
            real_path,
            system_file=not is_user_crontab
        )

        # Inspect cron configuration permissions.
        config_reasons = check_permissions(
            real_path,
            root
        )

        if config_reasons:

            findings.append(Finding(
                MODULE,
                "HIGH",
                "Insecure cron configuration permissions",
                cron_path,
                "; ".join(config_reasons),
                "T1053.003",
                "Restrict cron configuration ownership and write permissions."
            ))

        for entry in entries:

            command = entry["command"]

            script_paths = extract_script_paths(
                command,
                root
            )

            # MHK: DETECTION - Flag potentially suspicious command patterns.
            suspicious_patterns = [
                r"\bcurl\b",
                r"\bwget\b",
                r"\bnc\b",
                r"\bnetcat\b",
                r"/dev/tcp/",
                r"\bbase64\s+-d\b",
                r"\bchmod\s+[0-7]*7[0-7]*\b",
            ]

            if any(
                re.search(pattern, command)
                for pattern in suspicious_patterns
            ):

                findings.append(Finding(
                    MODULE,
                    "MEDIUM",
                    "Potentially suspicious cron command",
                    cron_path,
                    f"Line {entry['line']}: {command}",
                    "T1053.003",
                    "Manually review the command and confirm it is authorised."
                ))

            # MHK: SCRIPT CHECK - Inspect referenced existing scripts.
            for script_path in script_paths:

                real_script = on_disk(
                    root,
                    script_path
                )

                reasons = check_permissions(
                    real_script,
                    root
                )

                if reasons:

                    severity = (
                        "CRITICAL"
                        if (
                            entry["user"] == "root"
                            and any(
                                "writable" in item.lower()
                                for item in reasons
                            )
                        )
                        else "HIGH"
                    )

                    findings.append(Finding(
                        MODULE,
                        severity,
                        "Insecure permissions on cron-referenced script",
                        script_path,
                        (
                            f"Referenced by {cron_path}, "
                            f"line {entry['line']}: "
                            + "; ".join(reasons)
                        ),
                        "T1053.003",
                        "Review the script's ownership and permissions."
                    ))

    return findings


# MHK: CLI - Run the read-only audit and display findings.
def main():

    parser = argparse.ArgumentParser(
        description="MHK: PersistCheck Cron Jobs Auditor"
    )

    parser.add_argument(
        "--root",
        default="/",
        help="MHK: Root directory to audit"
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="MHK: Output findings as JSON"
    )

    args = parser.parse_args()

    findings = audit(args.root)

    if args.json:

        print(json.dumps(
            [finding.to_dict() for finding in findings],
            indent=4
        ))

    else:

        print("PersistCheck - Cron Jobs Auditor")
        print("Findings:", len(findings))

        for finding in findings:

            print(
                f"\n[{finding.severity}] {finding.title}"
            )

            print("Path:", finding.path)
            print("Detail:", finding.detail)
            print("MITRE:", finding.mitre)
            print("Recommendation:", finding.recommendation)


if __name__ == "__main__":
    main()
