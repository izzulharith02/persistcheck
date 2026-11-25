<!-- Systemd module README (Member 2). Fill in every [bracketed] value. -->

## Systemd Auditor

`systemd_auditor.py` checks systemd services and timers for persistence (MITRE ATT&CK **T1543.002 – Systemd Service**, **T1053.006 – Systemd Timers**) and for privilege-escalation paths.

| Check | Severity | Why it matters |
|---|---|---|
| Unit file writable by non-root users | CRITICAL (root service) / HIGH | Anyone who can edit the unit controls what root runs at boot |
| `ExecStart` program or script writable by non-root users | CRITICAL / HIGH | Replacing the program gives code execution as the service user |
| Program runs from `/tmp`, `/var/tmp` or `/dev/shm` | HIGH | Temp directories are writable by every user and are a common malware drop location |
| Suspicious command (`curl \| sh`, `/dev/tcp`, `nc`, `base64 -d`, setuid `chmod`) | MEDIUM – CRITICAL | Typical download-and-run, reverse-shell and obfuscation techniques |
| Hidden (dot-file) program | MEDIUM | Used to hide malware from casual `ls` |
| Missing program in a directory others can write to | CRITICAL / HIGH | An attacker can create the missing file and it will run on boot |
| Unit is a symlink outside the normal unit directories | HIGH | Unusual; can point to an attacker-controlled file |
| Custom unit not owned by any package (`dpkg`/`rpm`) | INFO | Highlights locally added units for review |

**How it works**
- Reads unit files from `/etc/systemd/system`, `/run/systemd/system`, `/usr/local/lib/systemd/system`, `/lib/systemd/system`, `/usr/lib/systemd/system` and each user's `~/.config/systemd/user`.
- Works out which units are **enabled** by reading the symlinks in `*.wants/` directories rather than calling `systemctl`, so it also works on an offline disk image (`--root /mnt/image`).
- Uses its own unit parser because systemd allows repeated keys, line continuations and empty `ExecStart=` resets, which Python's `configparser` cannot handle.
- Follows each `Exec*=` command to the files it really runs (including scripts passed to `bash`, `python`, etc.) and checks their permissions and every parent directory.
- Raises severity by one level when `Restart=always`/`on-failure` is set (the persistence survives being killed), and tags findings with T1053.006 when a `.timer` triggers the service.
- **Read-only:** it never starts, stops, enables, edits or deletes a unit.

```bash
python3 systemd/systemd_auditor.py --root /            # audit this machine
python3 systemd/systemd_auditor.py --root /mnt/image   # audit a mounted disk image offline
python3 systemd/systemd_auditor.py --json              # machine-readable output
```

### Lab test walkthrough

Tested on a Kali Linux 2026.1 VM (VirtualBox) with a snapshot taken first. Screenshots were taken before the module was moved into the `systemd/` folder, so the commands show `systemd_auditor.py` without the folder prefix.

**Step 1 – Baseline scan of the clean system**

```bash
sudo python3 systemd/systemd_auditor.py
```

<img width="724" height="148" alt="01_clean_scan" src="https://github.com/user-attachments/assets/7c548373-58b9-4a04-913a-52f75df32a3b" />



The only finding is a real leftover unit in the Kali image (`grub-install-devices.service`) that points to a missing script. It is MEDIUM, not CRITICAL, because `/usr/local/sbin` is root-owned.

**Step 2 – Plant harmless test persistence (lab VM only)**

```bash
chmod +x lab/*.sh
sudo ./lab/plant_test_persistence.sh --i-am-on-a-lab-vm
```

<img width="724" height="95" alt="image" src="https://github.com/user-attachments/assets/5da06e9f-a048-49d9-9a16-35fd143f3422" />


**Step 3 – Scan again: all planted test cases are detected**

```bash
sudo python3 systemd/systemd_auditor.py | grep -E "^\[|pc-test"
```

<img width="724" height="512" alt="image" src="https://github.com/user-attachments/assets/1b668c6a-aa1f-4daa-bf1e-b468a92d26c4" />


| Planted test case | Result |
|---|---|
| `pc-test-fetch.service` – `curl \| sh` pattern | CRITICAL – suspicious command |
| `pc-test-writable-exec.service` – root runs a world-writable script | CRITICAL – executable modifiable by others |
| `pc-test-writable-unit.service` – world-writable unit file | CRITICAL – unit file modifiable by others |
| `pc-test-tmp.service` + `.timer` – hidden program in `/tmp` | HIGH – temp directory, MEDIUM – hidden file, linked to the timer (T1053.006) |

**Step 4 – Clean up and confirm**

```bash
sudo ./lab/cleanup.sh
sudo python3 systemd/systemd_auditor.py
```

<img width="724" height="275" alt="image" src="https://github.com/user-attachments/assets/271ce9a9-50e6-4b4d-b8f4-aac263165839" />


**Command-line help**

```bash
python3 systemd/systemd_auditor.py --help
```

<img width="724" height="227" alt="image" src="https://github.com/user-attachments/assets/d7df3f49-2aca-4692-a5a7-ffec16e41054" />


**JSON output** (same fields as the other PersistCheck modules)

```bash
sudo python3 systemd/systemd_auditor.py --json
```

![JSON output](screenshots/06_json_output.png)

### Limitations and testing notes

- **Package check timeout.** The first scan showed 1 finding and later scans showed 2. The `dpkg -S` lookup timed out on a cold start (5 s), so the "not installed by any package" check was skipped. The timeout was raised to 15 s and results are now consistent.

 <img width="724" height="355" alt="image" src="https://github.com/user-attachments/assets/3456c437-2fc9-41af-808a-5d851dd2c170" />


- **False positives on stock units.** The first version reported 33 findings on a clean system, mostly stock package units pointing at optional tools that are not installed. Minor checks (missing binary, relative path) now only apply to enabled or locally added units, which brought a clean system down to 1–2 real findings.
- **Offline images (`--root`).** Absolute symlinks inside a mounted image (e.g. `/bin -> usr/bin`) resolve against the host, so some binaries may be reported missing. The package check only runs on the live system (`--root /`).
- **Run as root.** Without `sudo`, unreadable unit files are reported as INFO and not fully checked.

---

## Rules of Engagement (RoE)

These rules apply to every use of PersistCheck, including coursework demos.

**1. Authorised scope**
- Only systems you **own**, or systems you have **written permission** to audit from the owner.
- For IKB31603: only the team's own lab VM(s): `[VM hostname / IP, e.g. persistcheck-lab / 192.168.56.10]`.
- Default scope is the local machine (`--root /`) or a disk image you are authorised to examine (`--root /mnt/image`).
- Out of scope: university servers, lab machines belonging to others, cloud hosts, and any production system.

**2. Time windows**
- Coursework testing: `[start date] – [end date / submission date]`, `[e.g. 09:00–22:00 MYT]`.
- On any other system: only within the window written in the owner's authorisation letter. Agree a time that avoids business-critical periods.

**3. Permitted techniques**
- Read-only inspection of cron, systemd and startup configuration files and their permissions.
- Package ownership queries (`dpkg -S`, `rpm -qf`).
- Running `lab/plant_test_persistence.sh` **only** on a disposable lab VM.

**4. Prohibited actions**
- Exploiting any finding (e.g. actually editing a writable root script).
- Modifying, deleting, enabling or disabling services, cron jobs or startup files on a system you don't own.
- Copying findings, configuration files or credentials off the audited system, except the report into the designated output folder.
- Running the lab planting script on any non-lab machine.
- Sharing findings with anyone other than the system owner (see Responsible Disclosure).

**5. Emergency stop procedure**
1. Press **Ctrl+C**. PersistCheck stops cleanly and saves a partial report marked `INCOMPLETE`.
2. If the terminal does not respond: `pkill -f persistcheck` from another terminal.
3. Lab VM only: run `sudo ./lab/cleanup.sh` to remove all planted test files.
4. Tell the system owner (or lab lecturer) what happened, when, and what was running.
5. Emergency contacts: `[Team leader name – phone]`, `[Lab lecturer name – email]`.

---

## Responsible Disclosure

PersistCheck finds problems such as root services that any user can hijack. If you find one on a system you are authorised to audit, handle it as follows.

**Who to tell**
1. **The system owner or administrator first.** This is the person who authorised the audit.
2. **The software vendor or project maintainer**, if the problem comes from a package's default configuration (e.g. a package that installs a world-writable unit). Use their `SECURITY.md`, `security.txt` or security contact.
3. **MyCERT (CyberSecurity Malaysia)** through its **Cyber999** incident reporting service, if you find signs of an actual compromise (e.g. an unknown service downloading and running code) on a Malaysian system and the owner cannot be reached or does not respond.

**When**
- **Active compromise** (signs an attacker is already present): report to the owner **immediately**, the same day.
- **Misconfiguration** (e.g. CRITICAL writable root service): report within **24 hours** of the audit.
- **Vendor issues:** follow coordinated disclosure. Give the vendor **90 days** to release a fix before any public discussion, or less if they agree.
- **Never** publish details of an unfixed issue on GitHub, social media or in public reports.

**How**
- Send the report privately (direct to the owner, or by encrypted email or password-protected archive, sharing the password by a separate channel).
- Include: the PersistCheck version, the date and time of the audit, the affected file paths, the severity, why it is dangerous, and the suggested fix from the report.
- Do **not** include passwords, tokens or personal data in the report. PersistCheck masks secrets in its output, but check before you send.
- Keep a record of when you reported and the owner's reply.
- Delete the local output folder (`./persistcheck_output/`) once the owner confirms receipt and you no longer need it.

**Reporting a bug in PersistCheck itself:** open a GitHub issue. For security bugs in the tool, email `[team contact email]` instead of opening a public issue.
