# Disposable Linux service environment. No daemon, fixture keys or evidence are
# baked into the image; the canonical checkout is mounted read-only by run.py.
FROM hashicorp/vault:1.21.4@sha256:4e33b126a59c0c333b76fb4e894722462659a6bec7c48c9ee8cea56fccfd2569 AS vault
FROM rust:1.95.0-slim-trixie@sha256:e14e87345b4d5964ddcc3491d27ee046a0f23820f340c3c1e24da6880141f7c0
RUN apt-get update && apt-get install -y --no-install-recommends \
      systemd systemd-sysv dbus openssh-server openssh-client python3 \
      python3-cryptography ca-certificates git pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/* /etc/ssh/ssh_host_* \
    && useradd --uid 7382 --user-group --home-dir /nonexistent \
      --shell /bin/sh --password x opaque \
    && systemctl mask ssh.service ssh.socket systemd-remount-fs.service getty.target \
    && printf 'opaque-contained-ssh-v1\n' > /etc/opaque-contained-fixture \
    && mkdir -p /var/lib/opaque-contained /run/sshd \
    && chmod 700 /var/lib/opaque-contained \
    && truncate -s 0 /etc/machine-id
COPY --from=vault /bin/vault /usr/local/bin/vault
ENV container=docker
STOPSIGNAL SIGRTMIN+3
ENTRYPOINT ["/sbin/init"]
