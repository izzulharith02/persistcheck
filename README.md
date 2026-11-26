# PersistCheck – Linux Persistence Mechanism Auditor

**PersistCheck** is a Python-based security auditing tool that checks Linux systems for potentially suspicious persistence mechanisms.

Persistence is a technique attackers may use to maintain access to a compromised system, even after a restart or user logout. PersistCheck helps system administrators and security students identify unusual configurations in common Linux persistence locations.

The tool checks three main areas:

- **Cron Jobs** – Scheduled tasks that automatically execute commands.
- **Systemd Services** – Background services and timers that can run automatically.
- **Startup Configurations** – Shell configuration files and startup scripts that may execute commands when a user logs in or the system starts.

PersistCheck is designed for defensive security auditing. It performs read-only checks and reports potential findings without automatically changing or deleting system configurations.

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Features](#features)
3. [How PersistCheck Works](#how-persistcheck-works)
4. [Project Structure](#project-structure)
5. [Requirements](#requirements)
6. [Installation](#installation)
7. [Running PersistCheck](#running-persistcheck)
8. [Checking Individual Modules](#checking-individual-modules)
9. [Understanding the Results](#understanding-the-results)
10. [Generating Reports](#generating-reports)
11. [Controlled Laboratory Testing](#controlled-laboratory-testing)
12. [MITRE ATTCK Mapping](#mitre-attck-mapping)
13. [Ethical Use and Safety](#ethical-use-and-safety)
14. [Limitations and Future Improvements](#limitations-and-future-improvements)
15. [Troubleshooting](#troubleshooting)
16. [License](#license)

---

## 1. Project Overview

PersistCheck was developed as part of an Ethical Hacking Tool Development project.

The purpose of the tool is to help identify possible persistence-related security weaknesses in Linux systems. Instead of checking only one location, PersistCheck combines three separate auditing modules into one command-line application.

Each module examines a different part of the Linux system and reports configurations that may require further investigation.

**Main objectives:**

- Identify potentially suspicious scheduled tasks.
- Inspect systemd services and timers.
- Check common startup and shell configuration files.
- Identify insecure file permissions and unusual command execution.
- Generate reports that can be reviewed by system administrators or security students.
- Provide a simple command-line interface for running security audits.

## 2. Features

### Cron Jobs Auditor

Checks scheduled tasks that may execute commands automatically.

It examines:

- System and user cron configurations.
- Scheduled commands and their contents.
- Scripts referenced by scheduled tasks.
- File ownership and permissions.
- Potentially suspicious command patterns.

### Systemd Services Auditor

Checks systemd services and timers that may be used to execute programs automatically.

It examines:

- Enabled systemd services.
- Systemd service configuration files.
- Executable paths referenced by services.
- File ownership and permissions.
- Suspicious or unusual executable locations.
- Systemd timers and their related services.

### Startup Configuration Auditor

Checks common Linux startup and shell configuration files.

It examines locations such as:

- `/etc/rc.local`
- `/etc/profile`
- `/etc/init.d/`
- `/etc/profile.d/`
- User `.bashrc` files.
- User `.profile` files.

It looks for potentially suspicious configurations, including:

- Remote content being downloaded and passed directly to a shell.
- Unusual network connections using `/dev/tcp` or `/dev/udp`.
- Commands involving netcat, ncat or socat.
- Base64 decoding commands.
- Inline Python, Perl or Ruby execution.
- Unusual aliases that may override common commands.

### Additional Features

- Run one module or all modules.
- Read-only auditing.
- Dry-run mode.
- JSON report generation.
- Markdown report generation.
- HTML report generation.
- Command-line options for selecting modules and output locations.

## 3. How PersistCheck Works

PersistCheck uses a modular structure. Each auditor checks its own assigned area and returns findings to the main program.

The main program collects the results and displays a summary.

**Basic workflow:**

1. The user starts PersistCheck through the terminal.
2. The user selects a module or chooses to run all modules.
3. The selected auditors inspect the relevant Linux configuration files.
4. The auditors identify configurations that match their security checks.
5. PersistCheck displays the findings.
6. The user can generate a report for further review.

**Important:** A finding does not automatically mean that the system has been compromised. It indicates something that should be checked by an administrator or security analyst.

## 4. Project Structure

The project is separated into folders to make the code easier to understand and maintain.

```text
persistcheck/
│
├── main.py
├── requirements.txt
├── README.md
├── LICENSE
│
├── cron/
│   ├── cron_auditor.py
│   └── README.md
│
├── systemd/
│   ├── systemd_auditor.py
│   └── README.md
│
├── startup/
│   └── startup_auditor.py
│
└── lab/
    ├── plant_test_persistence.sh
    └── cleanup.sh
```

| File or Folder | Purpose |
|---|---|
| `main.py` | Main program and command-line interface. |
| `requirements.txt` | Lists the project's Python dependencies. |
| `cron/` | Contains the Cron Jobs Auditor. |
| `systemd/` | Contains the Systemd Services Auditor. |
| `startup/` | Contains the Startup Configuration Auditor. |
| `lab/` | Contains scripts for controlled laboratory testing. |
| `README.md` | Project documentation. |
| `LICENSE` | Project license. |

## 5. Requirements

Before running PersistCheck, make sure the following are available:

- A Linux operating system.
- Python 3.
- A terminal or command-line interface.
- Git, if cloning the project from GitHub.

Kali Linux or Ubuntu can be used for testing.

Some checks may require root privileges to inspect system-wide configuration files.

Check whether Python is installed:

```bash
python3 --version
```

Check whether Git is installed:

```bash
git --version
```

## 6. Installation

Follow these steps to download and prepare PersistCheck.

### Step 1: Clone the repository

Open a terminal and run:

```bash
git clone <YOUR_GITHUB_REPOSITORY_URL>
```

Replace `<YOUR_GITHUB_REPOSITORY_URL>` with the HTTPS or SSH URL of your GitHub repository.

### Step 2: Enter the project directory

```bash
cd persistcheck
```

If your downloaded folder has a different name, use that folder name instead.

### Step 3: Check the project files

```bash
ls
```

You should see files and folders such as:

```text
main.py
cron/
systemd/
startup/
lab/
requirements.txt
README.md
```

### Step 4: Install dependencies

If the project requires packages listed in `requirements.txt`, install them using:

```bash
python3 -m pip install -r requirements.txt
```

PersistCheck's auditing modules are designed to use Python's standard library, so external packages may not be required for the core auditing functions.

## 7. Running PersistCheck

Before starting an audit, make sure you are inside the project directory.

### Step 1: View the available commands

Run:

```bash
python3 main.py --help
```

This displays the available command-line options.

### Step 2: Run a basic audit

To check all three modules:

```bash
sudo python3 main.py --root / --module all
```

The `--root /` option tells PersistCheck to inspect the Linux root filesystem.

The `--module all` option runs all three auditing modules.

### Step 3: Run a dry-run audit

To preview the audit without generating a report file:

```bash
sudo python3 main.py --root / --module all --dry-run
```

Dry-run mode is useful when checking the tool's output without saving a report.

## 8. Checking Individual Modules

You do not need to run all three modules every time. You can select a specific module.

### Cron Jobs Auditor

```bash
sudo python3 main.py --root / --module cron
```

This checks scheduled tasks and their referenced scripts.

### Systemd Services Auditor

```bash
sudo python3 main.py --root / --module systemd
```

This checks systemd services, timers and related configurations.

### Startup Configuration Auditor

```bash
sudo python3 main.py --root / --module startup
```

This checks common startup and shell configuration files.

### Run all modules

```bash
sudo python3 main.py --root / --module all
```

This performs a complete audit using all three modules.

## 9. Understanding the Results

After an audit, PersistCheck displays a summary of the findings.

The results contain information about the module, the affected file or configuration, the reason it was flagged and its severity.

The severity levels help users decide which findings should be investigated first.

| Severity | Meaning |
|---|---|
| CRITICAL | A potentially serious security weakness that should be investigated immediately. |
| HIGH | A suspicious configuration that requires prompt investigation. |
| MEDIUM | A configuration that may introduce security risks and should be reviewed. |
| LOW | A minor or unusual configuration that may be legitimate but deserves attention. |
| INFO | Informational details that may help with further investigation. |

**Remember:** Severity describes the potential risk identified by the tool. It does not prove that an attacker has used the configuration.

For example, a custom systemd service may be legitimate. However, if it runs an executable from an unusual or insecure location, it may deserve further investigation.

## 10. Generating Reports

PersistCheck supports three report formats: JSON, Markdown and HTML.

Reports can be generated by using the `--output` and `--format` options.

### JSON Report

```bash
sudo python3 main.py --root / --module all --output reports --format json
```

JSON is useful for structured data, further processing and integration with other tools.

### Markdown Report

```bash
sudo python3 main.py --root / --module all --output reports --format md
```

Markdown reports are easy to read and can be opened in text editors or displayed on GitHub.

### HTML Report

```bash
sudo python3 main.py --root / --module all --output reports --format html
```

HTML reports can be opened in a web browser and provide a more readable presentation of the audit results.

**Note:** The `reports` directory is used as the output location in these examples. Use the actual directory name and path you want to save your reports in.

## 11. Controlled Laboratory Testing

PersistCheck includes scripts for creating and removing test persistence configurations.

These scripts are intended for a controlled laboratory environment, such as a Kali Linux virtual machine.

**Do not run the test script on a personal, university or production system.**

### Step 1: Prepare a virtual machine

1. Start your Kali Linux virtual machine.
2. Make sure you have permission to perform the test.
3. Create a VirtualBox snapshot before making changes.
4. Open the terminal.
5. Navigate to the PersistCheck project directory.

### Step 2: Run the laboratory setup script

```bash
sudo ./lab/plant_test_persistence.sh --i-am-on-a-lab-vm
```

The confirmation option is required by the script.

The script creates controlled test configurations that can be detected by PersistCheck.

### Step 3: Run the audit

```bash
sudo python3 main.py --root / --module all --output lab_test_reports --format json
```

Review the findings to confirm that PersistCheck can identify the test configurations.

### Step 4: Remove the laboratory test configurations

After testing, run:

```bash
sudo ./lab/cleanup.sh
```

This removes the test configurations created by the laboratory setup script.

### Step 5: Verify the cleanup

Check whether the laboratory directory still exists:

```bash
sudo ls -la /opt/persistcheck_lab
```

If the directory has been removed, the command should report that it does not exist.

Run a final audit:

```bash
sudo python3 main.py --root / --module all --dry-run
```

Review the results to confirm that the planted test configurations are no longer being detected.

**Important:** Do not skip cleanup. The laboratory scripts intentionally create test persistence configurations and should only be used in an isolated test environment.

## 12. MITRE ATT&CK Mapping

PersistCheck's checks relate to the following MITRE ATT&CK techniques:

| Technique ID | Technique | Related Module |
|---|---|---|
| T1053.003 | Cron | Cron Jobs Auditor |
| T1543.002 | Systemd Service | Systemd Services Auditor |
| T1053.006 | Scheduled Task | Systemd Services Auditor |
| T1546.004 | Unix Shell Configuration Modification | Startup Configuration Auditor |

These mappings help explain how the checked configurations may relate to techniques used by attackers to maintain persistence.

For more information, visit the official [MITRE ATT&CK website](https://attack.mitre.org/).

## 13. Ethical Use and Safety

PersistCheck was developed for defensive security auditing, educational purposes and controlled laboratory testing.

Users should follow these guidelines:

- Only run audits on systems they own or have permission to assess.
- Do not use the laboratory scripts on production systems.
- Create a virtual machine snapshot before controlled testing.
- Review findings before deciding whether a configuration is malicious.
- Do not automatically delete or modify configurations based only on a finding.
- Remove all laboratory test configurations after testing.

PersistCheck performs auditing and reporting. It does not automatically fix vulnerabilities or remove suspicious configurations.

## 14. Limitations and Future Improvements

PersistCheck currently focuses on three common Linux persistence areas: Cron, Systemd and startup configurations.

There are other possible persistence locations and techniques that are not covered by the current version.

Possible future improvements include:

- Adding checks for more Linux persistence locations.
- Improving detection to reduce false positives.
- Providing more detailed explanations for each finding.
- Improving severity assessment using additional system context.
- Comparing reports from previous audits to identify changes.
- Adding stronger authorization and safety checks before laboratory testing.

## 15. Troubleshooting

### Problem: Python command not found

Check whether Python 3 is installed:

```bash
python3 --version
```

If Python 3 is not installed, install it using your Linux distribution's package manager.

For Kali Linux or Debian-based systems:

```bash
sudo apt update
sudo apt install python3
```

### Problem: Permission denied

Some system configuration files require administrator privileges.

Try running the audit with `sudo`:

```bash
sudo python3 main.py --root / --module all
```

Only use administrator privileges when you are authorised to inspect the system.

### Problem: Script cannot be executed

If a laboratory script cannot be executed, check its permissions:

```bash
ls -l lab/
```

If necessary, make the script executable:

```bash
chmod +x lab/plant_test_persistence.sh
chmod +x lab/cleanup.sh
```

### Problem: Cannot find main.py

Make sure you are inside the PersistCheck project directory.

Run:

```bash
pwd
ls
```

If `main.py` is not listed, navigate to the correct project directory.

### Problem: No findings are displayed

This does not necessarily mean that the system is completely secure.

It means that the selected checks did not identify configurations matching the tool's detection rules.

---

## 16. License

This project is distributed under the license included in the repository.

Please refer to the `LICENSE` file for the applicable terms and conditions.

---

**PersistCheck – Linux Persistence Mechanism Auditor**

Developed for educational and defensive security auditing purposes.
