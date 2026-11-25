
#!/usr/bin/env python3
"""
main.py - PersistCheck Main Program.

Coordinates all persistence auditing modules
and generates security audit reports.

READ-ONLY:
PersistCheck does not modify system files.
"""

import argparse
import json
import platform
import html

from pathlib import Path
from datetime import datetime
from collections import defaultdict
from dataclasses import replace

from startup.startup_auditor import audit as audit_startup
from systemd.systemd_auditor import audit as audit_systemd


# ============================================================
# APPLICATION INFORMATION
# ============================================================

APP_NAME = "PersistCheck"
VERSION = "1.0.0"

SEVERITIES = [
    "INFO",
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL"
]


# ============================================================
# COMMAND LINE ARGUMENTS
# ============================================================

def parse_arguments():

    parser = argparse.ArgumentParser(
        prog="PersistCheck",
        description="Linux Persistence Mechanism Auditor",

        epilog="""
Examples:
  python main.py --help
  python main.py --root / --module startup
  python main.py --root / --module all --format json
  python main.py --root / --module all --format md
  python main.py --root / --module cron --dry-run
        """,

        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        "--root",
        default="/",
        help="Target filesystem root (default: /)"
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview audit without saving report files"
    )

    parser.add_argument(
        "--output",
        default="persistcheck_output",
        help="Directory for generated reports"
    )

    parser.add_argument(
        "--format",
        choices=["json", "md", "html"],
        default="json",
        help="Report format (default: json)"
    )

    parser.add_argument(
        "--module",
        choices=["cron", "systemd", "startup", "all"],
        default="all",
        help="Select auditing module (default: all)"
    )

    return parser.parse_args()


# ============================================================
# RISK SCORING ENGINE
# ============================================================

def apply_risk_scoring(findings):
    """
    Apply combined-risk escalation rules.

    When two or more findings affect the same file,
    increase each finding's severity by one level.

    Maximum severity is CRITICAL.
    Original findings are not modified.
    """

    grouped_findings = defaultdict(list)

    # Group findings by affected file
    for finding in findings:
        grouped_findings[finding.path].append(finding)

    scored_findings = []

    # Evaluate each group
    for path, group in grouped_findings.items():

        combined_risk = len(group) >= 2

        for finding in group:

            new_severity = finding.severity.upper()
            new_detail = finding.detail

            if combined_risk:

                current_level = SEVERITIES.index(new_severity)

                new_level = min(
                    current_level + 1,
                    len(SEVERITIES) - 1
                )

                new_severity = SEVERITIES[new_level]

                new_detail += (
                    " Combined-risk escalation applied: "
                    "multiple findings affect the same file."
                )

            # Create updated finding
            updated_finding = replace(
                finding,
                severity=new_severity,
                detail=new_detail
            )

            scored_findings.append(updated_finding)

    # Sort by severity
    scored_findings.sort(
        key=lambda item: SEVERITIES.index(item.severity.upper()),
        reverse=True
    )

    return scored_findings


# ============================================================
# REPORT DIRECTORY
# ============================================================

def create_report_directory(output_dir):

    hostname = platform.node() or "unknown-host"

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    report_folder = (
        Path(output_dir) / f"{hostname}_{timestamp}"
    )

    report_folder.mkdir(
        parents=True,
        exist_ok=True
    )

    return report_folder


# ============================================================
# JSON REPORT GENERATOR
# ============================================================

def generate_json_report(findings, root, output_dir):

    """
    Generate a JSON security audit report.
    """

    report_folder = create_report_directory(output_dir)

    hostname = platform.node() or "unknown-host"

    report_data = {

        "tool": APP_NAME,
        "version": VERSION,
        "host": hostname,

        "scan_time": datetime.now().isoformat(
            timespec="seconds"
        ),

        "target_root": str(root),

        "status": "COMPLETE",

        "total_findings": len(findings),

        "findings": [
            finding.to_dict()
            for finding in findings
        ]
    }

    report_file = report_folder / "report.json"

    with report_file.open("w", encoding="utf-8") as file:

        json.dump(
            report_data,
            file,
            indent=4,
            ensure_ascii=False
        )

    return report_file


# ============================================================
# MARKDOWN REPORT GENERATOR
# ============================================================

def generate_markdown_report(findings, root, output_dir):

    """
    Generate a Markdown security audit report.
    """

    report_folder = create_report_directory(output_dir)

    hostname = platform.node() or "unknown-host"

    report_file = report_folder / "report.md"

    # Report information
    lines = [

        "# PersistCheck Security Audit Report",

        "",

        f"**Tool:** {APP_NAME}",

        f"**Version:** {VERSION}",

        f"**Host:** {hostname}",

        f"**Scan Time:** {datetime.now().isoformat(timespec='seconds')}",

        f"**Target Root:** `{root}`",

        f"**Total Findings:** {len(findings)}",

        "**Status:** COMPLETE",

        "",

        "---",

        "",

        "## Security Findings",

        ""
    ]

    # Handle empty findings
    if not findings:

        lines.append(
            "No suspicious persistence findings detected."
        )

    # Add findings
    for index, finding in enumerate(findings, start=1):

        lines.extend([

            f"### {index}. [{finding.severity}] {finding.title}",

            "",

            f"- **Module:** {finding.module}",

            f"- **Path:** `{finding.path}`",

            f"- **Detail:** {finding.detail}",

            f"- **MITRE ATT&CK:** {finding.mitre}",

            f"- **Recommendation:** {finding.recommendation}",

            "",

            "---",

            ""
        ])

    # Report footer
    lines.extend([

        "## Audit Summary",

        "",

        f"Total security findings: **{len(findings)}**",

        "",

        "Generated by PersistCheck v1.0.0.",

        "This report is intended for authorised security auditing.",

        ""
    ])

    # Save Markdown report
    report_file.write_text(
        "\n".join(lines),
        encoding="utf-8"
    )

    return report_file

# ============================================================
# HTML Generator
# ============================================================

def generate_html_report(findings, root, output_dir):
    """
    Generate an HTML security audit report.
    """

    report_folder = create_report_directory(output_dir)

    hostname = platform.node() or "unknown-host"
    scan_time = datetime.now().isoformat(timespec="seconds")

    report_file = report_folder / "report.html"

    # Count findings by severity
    severity_counts = {
        severity: sum(
            1 for finding in findings
            if finding.severity.upper() == severity
        )
        for severity in SEVERITIES
    }

    # HTML escape helper to prevent unsafe HTML injection
    def safe(value):
        return html.escape(str(value), quote=True)

    # Generate finding cards
    finding_cards = []

    for index, finding in enumerate(findings, start=1):

        severity = finding.severity.upper()

        finding_cards.append(f"""
        <article class="finding">
            <div class="finding-header">
                <h3>{index}. {safe(finding.title)}</h3>
                <span class="badge {severity.lower()}">
                    {safe(severity)}
                </span>
            </div>

            <p><strong>Module:</strong> {safe(finding.module)}</p>
            <p><strong>Path:</strong>
                <code>{safe(finding.path)}</code>
            </p>
            <p><strong>Detail:</strong> {safe(finding.detail)}</p>
            <p><strong>MITRE ATT&CK:</strong>
                {safe(finding.mitre)}
            </p>
            <p><strong>Recommendation:</strong>
                {safe(finding.recommendation)}
            </p>
        </article>
        """)

    findings_html = "\n".join(finding_cards)

    if not findings:
        findings_html = """
        <p class="empty">
            No suspicious persistence findings detected.
        </p>
        """

    # Build HTML document
    document = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">

<title>PersistCheck Security Audit Report</title>

<style>
body {{
    font-family: Arial, sans-serif;
    background: #f1f5f9;
    color: #1e293b;
    margin: 0;
    padding: 30px;
}}

.container {{
    max-width: 1000px;
    margin: auto;
}}

.header {{
    background: #172554;
    color: white;
    padding: 30px;
    border-radius: 12px;
}}

.header h1 {{
    margin-top: 0;
}}

.summary {{
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 15px;
    margin: 25px 0;
}}

.summary-card {{
    background: white;
    padding: 20px;
    border-radius: 10px;
    box-shadow: 0 2px 8px #00000010;
}}

.summary-card h2 {{
    font-size: 30px;
    margin: 5px 0;
}}

.finding {{
    background: white;
    padding: 22px;
    margin-bottom: 18px;
    border-radius: 10px;
    border-left: 5px solid #64748b;
}}

.finding-header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 10px;
}}

.badge {{
    padding: 6px 12px;
    border-radius: 20px;
    font-weight: bold;
    font-size: 12px;
}}

.critical {{
    background: #fee2e2;
    color: #991b1b;
}}

.high {{
    background: #ffedd5;
    color: #9a3412;
}}

.medium {{
    background: #fef3c7;
    color: #92400e;
}}

.low {{
    background: #dbeafe;
    color: #1e40af;
}}

.info {{
    background: #e2e8f0;
    color: #334155;
}}

code {{
    overflow-wrap: anywhere;
}}

.footer {{
    margin-top: 30px;
    padding: 20px;
    text-align: center;
    color: #64748b;
}}

@media (max-width: 600px) {{
    body {{ padding: 12px; }}
    .summary {{ grid-template-columns: 1fr; }}
    .finding-header {{ align-items: flex-start; }}
}}

@media print {{
    body {{ background: white; padding: 0; }}
    .finding {{ break-inside: avoid; }}
}}
</style>
</head>

<body>
<div class="container">

<header class="header">
    <h1>PersistCheck</h1>
    <p>Persistence Mechanism Auditor</p>
    <p>Security Audit Report | Version {VERSION}</p>
</header>

<section>
    <h2>Audit Information</h2>
    <p><strong>Host:</strong> {safe(hostname)}</p>
    <p><strong>Scan Time:</strong> {safe(scan_time)}</p>
    <p><strong>Target Root:</strong> {safe(root)}</p>
    <p><strong>Status:</strong> COMPLETE</p>
</section>

<section class="summary">
    <div class="summary-card">
        <p>Total Findings</p>
        <h2>{len(findings)}</h2>
    </div>

    <div class="summary-card">
        <p>High / Critical</p>
        <h2>{severity_counts["HIGH"] + severity_counts["CRITICAL"]}</h2>
    </div>

    <div class="summary-card">
        <p>Medium</p>
        <h2>{severity_counts["MEDIUM"]}</h2>
    </div>
</section>

<section>
    <h2>Security Findings</h2>
    {findings_html}
</section>

<footer class="footer">
    <p>Generated by PersistCheck v{VERSION}</p>
    <p>For authorised security auditing only.</p>
</footer>

</div>
</body>
</html>
"""

    report_file.write_text(
        document,
        encoding="utf-8"
    )

    return report_file



# ============================================================
# MAIN PROGRAM
# ============================================================

def main():

    """
    Main entry point of PersistCheck.
    """

    args = parse_arguments()

    root_path = Path(args.root).resolve()

    # Validate root directory
    if not root_path.is_dir():

        raise SystemExit(
            f"Error: Invalid root directory: {args.root}"
        )

    # Display application information
    print(f"{APP_NAME} v{VERSION}")

    print("Linux Persistence Mechanism Auditor")

    print("-" * 45)

    print(f"Target root : {root_path}")

    print(f"Module      : {args.module}")

    print(f"Format      : {args.format}")

    print(f"Output      : {args.output}")

    print(f"Dry-run     : {args.dry_run}")


    # ========================================================
    # RUN AUDITING MODULES
    # ========================================================

    all_findings = []

    # 1. Startup Auditor
    if args.module in ("startup", "all"):

        print("\nStarting Startup Auditor...")

        print("-" * 45)

        startup_findings = audit_startup(str(root_path))

        all_findings.extend(startup_findings)

        print(
            f"Startup findings: {len(startup_findings)}"
        )


    # 2. Systemd Auditor
    if args.module in ("systemd", "all"):

        print("\nStarting Systemd Auditor...")

        print("-" * 45)

        systemd_findings = audit_systemd(str(root_path))

        all_findings.extend(systemd_findings)

        print(
            f"Systemd findings: {len(systemd_findings)}"
        )


    # 3. Cron Auditor
    if args.module in ("cron", "all"):

        print("\nCron Auditor integration is pending.")


    # ========================================================
    # APPLY RISK SCORING
    # ========================================================

    all_findings = apply_risk_scoring(all_findings)


    # ========================================================
    # GENERATE REPORT
    # ========================================================

    if not args.dry_run:

        if args.format == "json":

            report_file = generate_json_report(
                all_findings,
                root_path,
                args.output
            )

        elif args.format == "md":

            report_file = generate_markdown_report(
            all_findings,
            root_path,
            args.output
            )

        elif args.format == "html":

            report_file = generate_html_report(
            all_findings,
            root_path,
            args.output
            )

        else:
            report_file = None

        if report_file:

            print(
                f"\n{args.format.upper()} report saved: {report_file}"
            )


    # ========================================================
    # DISPLAY AUDIT SUMMARY
    # ========================================================

    print("\n" + "=" * 45)

    print("PERSISTCHECK AUDIT SUMMARY")

    print("=" * 45)

    for finding in all_findings:

        print(
            f"\n[{finding.severity}] {finding.title}"
        )

        print(f"Module : {finding.module}")

        print(f"Path   : {finding.path}")

        print(f"Detail : {finding.detail}")

        print(f"MITRE  : {finding.mitre}")

        print(f"Fix    : {finding.recommendation}")


    # Final total
    print("\n" + "-" * 45)

    print(f"Total findings: {len(all_findings)}")


# ============================================================
# PROGRAM EXECUTION
# ============================================================

if __name__ == "__main__":

    try:

        main()

    except KeyboardInterrupt:

        raise SystemExit(
            "\nPersistCheck interrupted by user."
        )
