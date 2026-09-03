#!/bin/sh
# One-shot bootstrap for the compose split (runs as root, once):
# seed the daemon-owned config volume with a sealed config, and prepare the
# custody + socket volumes with the ownership the daemon's startup check
# demands. The operator role, scripted.
set -eu

DAEMON_UID=7381
DAEMON_GID=7381
SOCKET_GID=7999

# Custody volumes: exclusively the daemon's.
install -d -o "$DAEMON_UID" -g "$DAEMON_GID" -m 0700 /var/lib/opaque
install -d -o "$DAEMON_UID" -g "$DAEMON_GID" -m 0700 /etc/opaque
# Socket volume: daemon-owned, socket-group traversable.
install -d -o "$DAEMON_UID" -g "$SOCKET_GID" -m 0750 /run/opaque

install -o "$DAEMON_UID" -g "$DAEMON_GID" -m 0600 /seed/config.toml /etc/opaque/config.toml

# Seal as the daemon account: the seal key is minted 0600 under uid 7381 —
# custody from the first moment it exists.
su_exec() {
    # busybox/debian-slim have no su-exec/gosu; setpriv ships in util-linux.
    setpriv --reuid="$DAEMON_UID" --regid="$DAEMON_GID" --clear-groups "$@"
}
HOME=/var/lib/opaque OPAQUE_CONFIG=/etc/opaque/config.toml \
    su_exec /opt/opaque/opaque setup --seal

echo "bootstrap: config sealed and custody volumes prepared"
ls -la /etc/opaque
