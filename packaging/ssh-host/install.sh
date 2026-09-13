#!/bin/sh
# Install source and unit files only. Keys, account/config and activation are explicit.
set -eu
[ "$(uname -s)" = Linux ] || { echo 'Linux host required' >&2; exit 1; }
[ "$(id -u)" = 0 ] || { echo 'Root installation required' >&2; exit 1; }
source_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
install -d -o root -g root -m 0755 /opt/opaque-ssh /etc/opaque-ssh
install -d -o root -g root -m 0700 /var/lib/opaque-ssh
for name in host_config health_probe principal_hook host_guard broker_control host_daemon; do
    install -o root -g root -m 0644 "$source_dir/$name.py" "/opt/opaque-ssh/$name.py"
done
for name in guard control sshd; do
    install -o root -g root -m 0644 "$source_dir/opaque-ssh-$name.service" /etc/systemd/system/
done
printf '%s\n' 'Installed source and service units. Configure custody, keys, profile and sshd before activation; see docs/ssh-health.md.'
