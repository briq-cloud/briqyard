# The fleet as an image (ADR 0057). Built from the release's binaries, not from source: the
# release workflow lays them out as <context>/<amd64|arm64>/{briqyard-fleet,briqyard}.
# The release builds on Ubuntu 24.04 (glibc 2.39); the base needs a glibc at least as new.
FROM debian:trixie-slim

# ssh: the fleet installs hosts by running it (ADR 0028). curl: the health check.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl openssh-client \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --gid 10001 briqyard \
 && useradd --system --uid 10001 --gid 10001 --create-home --home-dir /home/briqyard --shell /usr/sbin/nologin briqyard \
 && install -d -m 0700 -o briqyard -g briqyard /var/lib/briqyard-fleet \
 && install -d -m 0755 -o briqyard -g briqyard /etc/briqyard

ARG TARGETARCH
COPY --chmod=0755 ${TARGETARCH}/briqyard-fleet ${TARGETARCH}/briqyard /usr/local/bin/
COPY --chmod=0755 healthcheck.sh /usr/local/bin/briqyard-fleet-healthcheck

# The registry (every host's token and pool key) and the pinned SSH host keys: the fleet's
# alone. The configuration, the SSH key and the credentials file: the operator's.
VOLUME ["/var/lib/briqyard-fleet", "/etc/briqyard"]
USER briqyard
ENV BRIQYARD_LOG=info BRIQYARD_URL=http://127.0.0.1:7430
EXPOSE 7430
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 CMD ["briqyard-fleet-healthcheck"]
ENTRYPOINT ["briqyard-fleet"]
CMD ["--config", "/etc/briqyard/fleet.yaml"]
