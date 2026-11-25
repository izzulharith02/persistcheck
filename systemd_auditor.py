#!/usr/bin/env python3
"""
systemd_auditor.py - PersistCheck module: systemd persistence auditor.

Looks for systemd services and timers that could be used for persistence
(MITRE ATT&CK T1543.002 Systemd Service, T1053.006 Systemd Timers) or that
give a normal user a path to root (writable unit files or binaries run by root).

READ-ONLY: this module never starts, stops, enables, edits or deletes a unit.
It only reads files under the audited root directory.

Can be run alone for testing:
    python3 systemd_auditor.py --root /
    python3 systemd_auditor.py --root /mnt/disk_image --json
main.py imports and calls audit(root) instead.
"""

import argparse
import glob
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass, asdict

MODULE = "systemd"
SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

# Where systemd loads system-wide units from, highest priority first.
SYSTEM_UNIT_DIRS = [
    "/etc/systemd/system",
    "/run/systemd/system",
    "/usr/local/lib/systemd/system",
    "/lib/systemd/system",
    "/usr/lib/systemd/system",
]
# Directories where admins or attackers add their own units (packages use /lib and /usr/lib).
CUSTOM_UNIT_DIRS = ("/etc/systemd/system", "/usr/local/lib/systemd/system")
USER_UNIT_GLOBS = ["/root/.config/systemd/user", "/home/*/.config/systemd/user"]

EXEC_KEYS = ("ExecStart", "ExecStartPre", "ExecStartPost", "ExecReload", "ExecStop", "ExecStopPost")
TEMP_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/")
INTERPRETERS = ("sh", "bash", "dash", "zsh", "python", "perl", "ruby", "php", "node")

SUSPICIOUS_PATTERNS = [
    (re.compile(r"\b(curl|wget)\b[^|;]*\|\s*(ba|z|da)?sh\b"), "CRITICAL", "Downloads remote content and pipes it into a shell"),
    (re.compile(r"/dev/(tcp|udp)/"), "HIGH", "Uses bash /dev/tcp redirection (typical reverse shell)"),
    (re.compile(r"\b(nc|ncat|netcat|socat)\b"), "HIGH", "Uses netcat/socat (possible bind or reverse shell)"),
    (re.compile(r"base64\s+(-d|--decode)"), "HIGH", "Decodes base64 at runtime (hidden payload)"),
    (re.compile(r"\b(curl|wget)\b"), "MEDIUM", "Fetches content from the network"),
    (re.compile(r"\bpython[0-9.]*\s+-c\b|\bperl\s+-e\b"), "MEDIUM", "Runs an inline interpreter one-liner"),
    (re.compile(r"\bchmod\s+(u\+s|g\+s|\+s|[2467][0-7]{3})\b"), "HIGH", "Sets the setuid/setgid bit"),
]


@dataclass
class Finding:
    """One problem found. Same fields as the cron and startup auditors (see common.py)."""
    module: str
    severity: str
    title: str
    path: str
    detail: str
    mitre: str
    recommendation: str

    def to_dict(self):
        return asdict(self)


# ---------------------------------------------------------------- helpers

def bump(severity, levels=1):
    """Raise a severity by N levels, capped at CRITICAL."""
    index = min(SEVERITIES.index(severity) + levels, len(SEVERITIES) - 1)
    return SEVERITIES[index]


def on_disk(root, sys_path):
    """Turn a path inside the audited system (/etc/x) into the real path on disk (<root>/etc/x)."""
    return os.path.join(root, sys_path.lstrip("/"))


def writable_by_others(real_path, root, expected_uid=0):
    """
    Return the reasons a file can be modified by someone other than its expected owner.
    Also walks up the parent directories: a writable parent lets an attacker replace the file.
    Directories with the sticky bit (like /tmp) are skipped for the parent check.
    """
    reasons = []
    try:
        st = os.stat(real_path)
    except OSError:
        return reasons
    noun = "directory" if stat.S_ISDIR(st.st_mode) else "file"
    if st.st_mode & stat.S_IWOTH:
        reasons.append(f"{noun} is world-writable")
    if st.st_mode & stat.S_IWGRP and st.st_gid != 0:
        reasons.append(f"{noun} is group-writable (gid {st.st_gid})")
    if st.st_uid not in (0, expected_uid):
        reasons.append(f"{noun} is owned by uid {st.st_uid}")

    stop = os.path.abspath(root)
    parent = os.path.dirname(os.path.abspath(real_path))
    while parent.startswith(stop) and parent != stop:
        pst = os.stat(parent)
        if pst.st_mode & stat.S_IWOTH and not pst.st_mode & stat.S_ISVTX:
            reasons.append(f"parent directory {parent} is world-writable")
            break
        if pst.st_uid not in (0, expected_uid):
            reasons.append(f"parent directory {parent} is owned by uid {pst.st_uid}")
            break
        parent = os.path.dirname(parent)
    return reasons


def owned_by_package(real_path):
    """Ask dpkg or rpm whether a package installed this file. Returns True, False or None (can't tell)."""
    for cmd in (["dpkg", "-S", real_path], ["rpm", "-qf", real_path]):
        if shutil.which(cmd[0]):
            try:
                result = subprocess.run(cmd, capture_output=True, timeout=15)
            except (subprocess.TimeoutExpired, OSError):
                return None
            return result.returncode == 0
    return None


# ---------------------------------------------------------------- parsing

def parse_unit(real_path):
    """
    Minimal systemd unit file parser -> {section: {key: [values]}}.
    Python's configparser can't be used: systemd allows the same key many times
    (several ExecStartPre=), lines continued with a backslash, and an empty
    value (ExecStart=) that clears earlier values.
    """
    sections, current, pending = {}, None, ""
    with open(real_path, encoding="utf-8", errors="replace") as handle:
        for raw in handle:
            line = pending + raw.strip()
            pending = ""
            if line.endswith("\\"):
                pending = line[:-1] + " "
                continue
            if not line or line[0] in "#;":
                continue
            if line.startswith("[") and line.endswith("]"):
                current = sections.setdefault(line[1:-1], {})
            elif current is not None and "=" in line:
                key, value = (part.strip() for part in line.split("=", 1))
                if value:
                    current.setdefault(key, []).append(value)
                else:
                    current[key] = []
    return sections


def exec_targets(value):
    """
    From an Exec*= line, return the files that actually get run.
    Handles systemd prefixes (@-:+!), 'env VAR=x prog', and interpreters running
    a script (bash /opt/x.sh -> both /bin/bash and /opt/x.sh are returned).
    """
    command = value.lstrip("@-:+!")
    try:
        argv = shlex.split(command)
    except ValueError:
        argv = command.split()
    if argv and os.path.basename(argv[0]) == "env":
        argv = [a for a in argv[1:] if "=" not in a]
    if not argv:
        return []
    targets = [argv[0]]
    if os.path.basename(argv[0]).rstrip("0123456789.") in INTERPRETERS and "-c" not in argv:
        script = next((a for a in argv[1:] if not a.startswith("-")), None)
        if script:
            targets.append(script)
    return targets


# ---------------------------------------------------------------- discovery

def user_unit_dirs(root):
    """Expand /home/*/.config/systemd/user into real per-user directories."""
    dirs = []
    for pattern in USER_UNIT_GLOBS:
        for real in glob.glob(on_disk(root, pattern)):
            dirs.append("/" + os.path.relpath(real, root))
    return dirs


def enabled_units(root):
    """
    A unit is enabled when a symlink to it sits in a *.wants/ or *.requires/ directory.
    Reading those links (instead of running systemctl) also works on an offline image.
    """
    enabled = set()
    for base in SYSTEM_UNIT_DIRS + user_unit_dirs(root):
        for wants_dir in glob.glob(on_disk(root, base) + "/*.wants") + glob.glob(on_disk(root, base) + "/*.requires"):
            for name in os.listdir(wants_dir):
                enabled.add(name)
                if "@" in name:  # getty@tty1.service enables the template getty@.service
                    enabled.add(name.split("@")[0] + "@" + name[name.rfind("."):])
    return enabled


def discover_units(root):
    """
    Yield (unit_path, scope, owner_uid) for every .service and .timer file.
    A system unit name found in a higher-priority directory hides the same name lower down,
    which is how systemd itself resolves overrides.
    """
    seen = set()
    sources = [(d, "system") for d in SYSTEM_UNIT_DIRS] + [(d, "user") for d in user_unit_dirs(root)]
    for base, scope in sources:
        real_dir = on_disk(root, base)
        if not os.path.isdir(real_dir):
            continue
        owner = os.stat(real_dir).st_uid if scope == "user" else 0
        for name in sorted(os.listdir(real_dir)):
            if not name.endswith((".service", ".timer")):
                continue
            key = name if scope == "system" else base + "/" + name
            if key in seen:
                continue
            seen.add(key)
            yield f"{base}/{name}", scope, owner


# ---------------------------------------------------------------- checks

def check_symlink(root, unit_path):
    """Units are normally plain files. A link pointing outside the unit directories is suspicious."""
    real = on_disk(root, unit_path)
    if not os.path.islink(real):
        return None
    target = os.readlink(real)
    if target == "/dev/null":
        return "masked"
    absolute = os.path.normpath(os.path.join(os.path.dirname(unit_path), target))
    if not absolute.startswith(tuple(SYSTEM_UNIT_DIRS)):
        return absolute
    return None


def check_exec_target(root, unit_path, target, runs_as_root, expected_uid, important):
    """
    Check one file that the unit executes.
    'important' = the unit is enabled or was added locally. Stock package units often
    point at optional tools that aren't installed, so minor issues are only reported
    for important units to keep the output useful.
    """
    found = []
    as_who = "root" if runs_as_root else "a normal user"

    def add(severity, title, detail, fix):
        found.append(Finding(MODULE, severity, title, unit_path, detail, "T1543.002", fix))

    if not target.startswith("/"):
        if unit_path.startswith(CUSTOM_UNIT_DIRS):  # stock units rely on systemd's safe search path
                add("LOW", "Executable given as a relative path",
                f"'{target}' is resolved through a search path; prefer an absolute path.",
                "Use the full absolute path to the binary.")
        return found
    if target.startswith(TEMP_DIRS):
        add("HIGH", "Service runs a program from a temporary directory",
            f"{target} is in a temp directory that any user can write to (runs as {as_who}).",
            "Move the program to a root-owned location such as /usr/local/bin.")
    if os.path.basename(target).startswith("."):
        add("MEDIUM", "Service runs a hidden file",
            f"{target} has a hidden (dot) filename, often used to hide malware.",
            "Confirm what this file is; remove the unit if it is not expected.")

    real = on_disk(root, target)
    if not os.path.exists(real):
        if target.startswith(TEMP_DIRS):
            return found  # already reported above
        reasons = writable_by_others(os.path.dirname(real), root, expected_uid)
        if not reasons and not important:
            return found
        severity = ("CRITICAL" if runs_as_root else "HIGH") if reasons else "MEDIUM"
        add(severity, "Service points to a missing executable",
            f"{target} does not exist" + (f"; its directory can be written by others ({'; '.join(reasons)}), "
                                          "so anyone could create it" if reasons else "") + ".",
            "Remove the stale unit or fix the path.")
        return found

    reasons = writable_by_others(real, root, expected_uid)
    if reasons:
        add("CRITICAL" if runs_as_root else "HIGH", "Executable can be modified by other users",
            f"{target} runs as {as_who} but {'; '.join(reasons)}. Editing it gives code execution as {as_who}.",
            f"chown root:root {target} && chmod 755 {target}")
    return found


def audit_unit(root, unit_path, scope, owner_uid, enabled):
    """Run every check on one unit file and return its findings."""
    findings = []
    name = os.path.basename(unit_path)
    real = on_disk(root, unit_path)
    status = "enabled" if name in enabled else "not enabled"
    important = name in enabled or unit_path.startswith(CUSTOM_UNIT_DIRS) or scope == "user"

    link = check_symlink(root, unit_path)
    if link == "masked":
        return findings
    if link:
        findings.append(Finding(MODULE, "HIGH", "Unit file is a symlink to an unusual location", unit_path,
                                f"Links to {link}, outside the normal unit directories ({status}).",
                                "T1543.002", "Check the link target; units should live in /etc/systemd/system."))

    try:
        unit = parse_unit(real)
    except OSError as error:
        findings.append(Finding(MODULE, "INFO", "Unit file could not be read", unit_path, str(error),
                                "T1543.002", "Re-run as root to audit this unit."))
        return findings

    service = unit.get("Service", {})
    run_user = (service.get("User") or ["root"])[-1]
    runs_as_root = scope == "system" and run_user in ("root", "0")

    reasons = writable_by_others(real, root, owner_uid)
    if reasons:
        findings.append(Finding(MODULE, "CRITICAL" if runs_as_root else "HIGH",
                                "Unit file can be modified by other users", unit_path,
                                f"{'; '.join(reasons)}. Anyone who can edit it controls what runs "
                                f"as {run_user} ({status}).",
                                "T1543.002", f"chown root:root {unit_path} && chmod 644 {unit_path}"))

    for key in EXEC_KEYS:
        for value in service.get(key, []):
            for pattern, severity, reason in SUSPICIOUS_PATTERNS:
                if pattern.search(value):
                    findings.append(Finding(MODULE, severity, "Suspicious command in service", unit_path,
                                            f"{key}={value} -> {reason} ({status}, runs as {run_user}).",
                                            "T1543.002", "Investigate the command; disable and remove the unit if unknown."))
                    break  # report only the most serious pattern per line
            for target in exec_targets(value):
                findings.extend(check_exec_target(root, unit_path, target, runs_as_root, owner_uid, important))

    restart = (service.get("Restart") or [""])[-1]
    if restart in ("always", "on-failure", "on-abnormal"):
        for finding in findings:
            if SEVERITIES.index(finding.severity) >= SEVERITIES.index("MEDIUM"):
                finding.severity = bump(finding.severity)
                finding.detail += f" Restart={restart} brings it back if killed."

    if os.path.abspath(root) == "/" and unit_path.startswith(CUSTOM_UNIT_DIRS) and not os.path.islink(real):
        if owned_by_package(real) is False:
            findings.append(Finding(MODULE, "INFO", "Custom unit not installed by any package", unit_path,
                                    f"Created locally by an admin or an attacker ({status}).",
                                    "T1543.002", "Confirm someone on your team created this unit."))
    return findings


def link_timers(root, timers, findings):
    """Mark service findings that are also triggered on a schedule by a .timer (T1053.006)."""
    for timer_path in timers:
        try:
            timer = parse_unit(on_disk(root, timer_path)).get("Timer", {})
        except OSError:
            continue
        default = os.path.basename(timer_path).replace(".timer", ".service")
        target = (timer.get("Unit") or [default])[-1]
        for finding in findings:
            if os.path.basename(finding.path) == target:
                finding.mitre = "T1543.002, T1053.006"
                finding.detail += f" Also scheduled by {os.path.basename(timer_path)}."


# ---------------------------------------------------------------- entry points

def audit(root="/"):
    """Main entry point used by main.py. Returns a list of Finding objects, most severe first."""
    enabled = enabled_units(root)
    findings, timers = [], []
    for unit_path, scope, owner_uid in discover_units(root):
        if unit_path.endswith(".timer"):
            timers.append(unit_path)
        findings.extend(audit_unit(root, unit_path, scope, owner_uid, enabled))
    link_timers(root, timers, findings)
    findings.sort(key=lambda f: SEVERITIES.index(f.severity), reverse=True)
    return findings


def main():
    parser = argparse.ArgumentParser(
        description="PersistCheck systemd auditor (standalone test mode, read-only).",
        epilog="Examples:\n  python3 systemd_auditor.py --root /\n"
               "  python3 systemd_auditor.py --root /mnt/image --json",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", default="/", help="filesystem root to audit (default: / = this machine)")
    parser.add_argument("--json", action="store_true", help="print findings as JSON")
    args = parser.parse_args()

    if not os.path.isdir(args.root):
        parser.error(f"--root {args.root} is not a directory")
    findings = audit(args.root)
    if args.json:
        print(json.dumps([f.to_dict() for f in findings], indent=2))
        return
    for f in findings:
        print(f"[{f.severity:<8}] {f.title}\n           {f.path}\n           {f.detail}\n           Fix: {f.recommendation}\n")
    print(f"{len(findings)} systemd finding(s).")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("\nAborted by user.")
