#!/bin/sh
# Stop and disable the service on real removal only, never on upgrade.
# $1 is "remove" (deb) or "0" (rpm) when the package is being removed.
set -e

case "$1" in
    remove|0)
        if [ -d /run/systemd/system ]; then
            systemctl stop docker-fence.service >/dev/null 2>&1 || true
            systemctl disable docker-fence.service >/dev/null 2>&1 || true
        fi
        ;;
esac

exit 0
