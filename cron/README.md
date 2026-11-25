# Cron Jobs Auditor

**Project:** PersistCheck  
**Module:** Cron Jobs Auditor  
**Author / Contributor:** MHK  
**Language:** Python 3

## 1. Overview

The Cron Jobs Auditor is a Python-based security auditing tool developed as part of the PersistCheck project.

Its purpose is to inspect scheduled cron jobs on Linux systems and identify potentially insecure configurations that could introduce security risks.

Cron jobs are commonly used to automate system maintenance, backups and recurring tasks. However, attackers may abuse insecure scheduled tasks to maintain persistence, execute malicious commands or gain unauthorised access.

This module helps administrators identify suspicious cron configurations and permission weaknesses.

## 2. Main Features

The Cron Jobs Auditor provides the following functionality:

- **Cron Job Discovery:** Identifies system-wide and user-specific cron configuration files.
- **Suspicious Command Detection:** Flags potentially suspicious scheduled commands, including commands involving remote downloads.
- **Permission Auditing:** Checks cron configuration files for insecure permissions.
- **Directory Permission Checking:** Inspects parent directories for potentially unsafe write permissions.
- **Script Path Inspection:** Identifies scripts executed through common interpreters, including Python, Bash, Perl, PHP, Ruby and Node.js.
- **Cron Schedule Parsing:** Supports standard five-field cron expressions and special schedules.
- **JSON Output:** Provides findings in JSON format for easier integration and further analysis.
- **Alternative Root Support:** Allows auditing a specified filesystem root using the `--root` option.

## 3. Requirements

The following are required:

- Linux operating system
- Python 3
- Terminal access
- Appropriate permissions to inspect system cron files

The module uses Python's standard library.

## 4. Project Structure

```text
persistcheck/
│
├── cron/
│   ├── __init__.py
│   ├── cron_auditor.py
│   └── README.md
│
├── lab/
├── systemd/
├── requirements.txt
└── README.md
```

## 5. Installation

Clone the PersistCheck repository:

```bash
git clone https://github.com/izzulharith02/persistcheck.git
```

Navigate into the project directory:

```bash
cd persistcheck
```

Check that Python 3 is installed:

```bash
python3 --version
```

## 6. How to Use

### A. Run a standard audit

From the main PersistCheck directory, execute:

```bash
sudo python3 -m cron.cron_auditor
```

This starts the Cron Jobs Auditor and inspects the available cron configurations.

### B. Run an audit without sudo

```bash
python3 -m cron.cron_auditor
```

Some system files may not be accessible without elevated permissions. Consequently, results may be incomplete.

### C. Generate JSON output

To display the audit findings in JSON format:

```bash
sudo python3 -m cron.cron_auditor --json
```

JSON output is useful for automated processing, reporting and integration with other security tools.

### D. Audit an alternative filesystem root

To inspect a separate Linux filesystem or test environment:

```bash
python3 -m cron.cron_auditor --root /path/to/test-root
```

Replace `/path/to/test-root` with the directory containing the filesystem you want to audit.

## 7. Security Checks

The auditor examines several security-related conditions.

| Security check | Description |
|---|---|
| World-writable files | Identifies cron files writable by all users. |
| Group-writable files | Identifies cron files writable by their group. |
| File ownership | Checks whether cron files are owned by root. |
| World-writable directories | Detects parent directories writable by all users. |
| Group-writable directories | Detects parent directories writable by their group. |
| Suspicious commands | Identifies potentially suspicious scheduled commands. |
| Script execution | Inspects commands that execute scripts through common interpreters. |

These checks help identify configurations that could potentially be abused for persistence or privilege escalation.

## 8. Understanding the Results

The auditor reports findings with information such as:

- **Module:** Identifies the auditing module.
- **Severity:** Indicates the assigned risk level.
- **Title:** Summarises the detected security issue.
- **Path:** Identifies the affected file or location.
- **Detail:** Provides additional information about the finding.
- **MITRE:** Provides the associated MITRE ATT&CK reference when available.
- **Recommendation:** Suggests an appropriate remediation action.

A clean audit may display:

```text
Findings: 0
```

This means no findings were reported during that audit. It does not guarantee that the system is completely secure.

## 9. Troubleshooting

**Permission denied**

Run the audit with elevated privileges:

```bash
sudo python3 -m cron.cron_auditor
```

**Python command not found**

Check whether Python 3 is installed:

```bash
python3 --version
```

**Module not found**

Make sure you are running the command from the main PersistCheck directory and that the `cron` directory contains `__init__.py`.

**JSON output is empty**

An empty JSON array (`[]`) means the auditor did not report any findings during that execution.

## 10. Security Recommendations

If insecure cron configurations are identified:

1. Review the affected cron job and determine whether it is legitimate.
2. Remove unauthorised or unnecessary scheduled tasks.
3. Restrict file permissions to authorised users.
4. Ensure sensitive cron configuration files have appropriate ownership.
5. Secure parent directories against unauthorised modification.
6. Investigate suspicious scripts and commands before removing them.
7. Re-run the auditor after remediation.

## 11. Limitations

- The auditor identifies potential security weaknesses; it does not automatically remediate them.
- A suspicious command is not necessarily malicious and requires manual investigation.
- Some checks require elevated privileges.
- Findings depend on the files and filesystem accessible during the audit.
- A clean result does not guarantee the absence of persistence mechanisms or other security vulnerabilities.

## 12. Testing

Run the following commands to check the Python module:

```bash
python3 -m py_compile cron/cron_auditor.py
```

Run the auditor:

```bash
sudo python3 -m cron.cron_auditor
```

Generate JSON output:

```bash
sudo python3 -m cron.cron_auditor --json
```

## 13. Credits

**Developed by:** MHK  
**Project:** PersistCheck – Ethical Hacking Tool Development Assignment  
**Module:** Cron Jobs Auditor

Part of the PersistCheck security auditing toolkit, developed to help identify insecure scheduled tasks and potential Linux persistence weaknesses.
