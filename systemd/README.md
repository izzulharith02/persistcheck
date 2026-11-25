<!-- Member 2's README sections. Paste these into README.md. Fill in every [bracketed] value. -->

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
python3 systemd_auditor.py --root /            # audit this machine
python3 systemd_auditor.py --root /mnt/image   # audit a mounted disk image offline
python3 systemd_auditor.py --json              # machine-readable output
```

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
