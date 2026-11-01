#!/bin/sh
# Reload unit files after the unit file has been removed or replaced.
set -e

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi

exit 0
