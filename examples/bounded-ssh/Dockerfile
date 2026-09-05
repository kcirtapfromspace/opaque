FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server openssh-client python3 python3-cryptography ca-certificates \
    && rm -rf /var/lib/apt/lists/* /etc/ssh/ssh_host_* \
    && useradd --uid 7382 --user-group --home-dir /home/opaque --shell /bin/sh --password x opaque \
    && mkdir -p /home/opaque /run/sshd /run/opaque-ssh /var/lib/opaque-ssh /etc/opaque-ssh /client \
    && chmod 700 /var/lib/opaque-ssh \
    && chown 7382:7382 /client
COPY host_guard.py health_probe.py fixture_host.py principal_hook.py broker_control.py /opt/opaque-ssh/
RUN chmod 755 /opt/opaque-ssh/*.py
ENTRYPOINT ["/usr/bin/python3", "-I", "/opt/opaque-ssh/fixture_host.py"]
