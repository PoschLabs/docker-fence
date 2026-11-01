#!/bin/sh
# Reload unit files so systemd sees docker-fence.service.
# The service is intentionally NOT enabled or started here.
set -e

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi

exit 0
