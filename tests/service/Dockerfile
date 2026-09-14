# Add the real PAM user-manager integration needed by systemd --user. The
# contained base retains the systemd/root boundary; no source or keys are baked in.
ARG CONTAINED_IMAGE
FROM ${CONTAINED_IMAGE}
RUN apt-get update && apt-get install -y --no-install-recommends libpam-systemd \
    && rm -rf /var/lib/apt/lists/*
