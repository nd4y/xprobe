# The core is pinned to the version running on the nodes. That is the whole
# point of a custom probe: xray-checker compiles the core into its binary
# (26.3.27), and XHTTP against 26.7.28 nodes fails silently. Here a divergence
# is visible in one line and fixed by one rebuild.
FROM python:3.13-slim

ARG XRAY_VERSION=v26.7.28

# curl and unzip are needed only at build time and removed immediately: the
# probe reaches out with its own code (SOCKS5 and HTTP live in prober.py), and
# an image that holds other people's configs should not carry extra tools.
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates unzip \
 && curl -fsSL "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/Xray-linux-64.zip" \
      -o /tmp/xray.zip \
 && unzip -q /tmp/xray.zip -d /usr/local/bin xray \
 && chmod +x /usr/local/bin/xray \
 && rm /tmp/xray.zip \
 && xray version \
 && apt-get purge -y --auto-remove curl unzip \
 && rm -rf /var/lib/apt/lists/*

COPY prober.py /app/prober.py
WORKDIR /app
EXPOSE 8080

# Probes reach out as an unprivileged user: nothing here needs root, and the
# process holds other people's configs.
RUN useradd --system --create-home prober

# The state directory is created IN THE IMAGE with the right owner. Docker
# copies the owner from the image into an EMPTY named volume on first mount;
# without this the volume stays root-owned, the (non-root) process cannot
# write, and the config cache, the metrics spool and — worst of all — the
# enrolled node's IDENTITY are lost: every restart would enroll it with the
# control plane all over again.
RUN mkdir -p /var/lib/xprobe && chown prober:prober /var/lib/xprobe

USER prober

CMD ["python", "-u", "/app/prober.py"]
