#!/bin/sh
# Stop and disable the service on real removal only, never on upgrade.
# $1 is "remove" (deb) or "0" (rpm) when the package is being removed.
set -e

case "$1" in
    remove|0)
        if [ -d /run/systemd/system ]; then
            if ! systemctl stop docker-fence.service >/dev/null 2>&1; then
                echo "docker-fence: warning: could not stop docker-fence.service; DOCKER-FENCE rules may still be present. Run 'docker-fence remove' to delete them." >&2
            fi
            systemctl disable docker-fence.service >/dev/null 2>&1 || true
        fi
        ;;
esac

exit 0
