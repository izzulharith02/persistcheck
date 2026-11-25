#!/usr/bin/env bash
# Removes everything lab/plant_test_persistence.sh created. Safe to run more than once.
# Usage: sudo ./lab/cleanup.sh

set -uo pipefail
if [[ $EUID -ne 0 ]]; then
    echo "Must run as root (sudo)." ; exit 1
fi

rm -f /etc/systemd/system/multi-user.target.wants/pc-test-writable-exec.service
rm -f /etc/systemd/system/pc-test-writable-exec.service \
      /etc/systemd/system/pc-test-writable-unit.service \
      /etc/systemd/system/pc-test-tmp.service \
      /etc/systemd/system/pc-test-tmp.timer \
      /etc/systemd/system/pc-test-fetch.service
rm -f /tmp/.pc_test_hidden /etc/cron.d/pc-test /etc/profile.d/pc-test.sh
rm -rf /opt/persistcheck_lab

command -v systemctl >/dev/null && systemctl daemon-reload 2>/dev/null
echo "Lab test cases removed."
