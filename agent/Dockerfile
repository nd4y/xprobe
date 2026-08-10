# The core version is the whole point of a custom probe: xray-checker compiles
# one in (26.3.27), and XHTTP against 26.7.28 nodes fails silently. Here the
# versions are explicit, and several are carried at once so a check can be run
# with the version its target actually serves — or two versions compared
# against the same host.
#
# The first entry is the default. Each lands in /opt/xray/<version>/xray; the
# probe picks one per check and refuses to substitute another, because a
# silent substitution is exactly the failure this tool exists to expose.
FROM python:3.13-slim

ARG XRAY_VERSIONS="v26.7.28 v26.3.27"

# curl and unzip are needed only at build time and removed immediately: the
# probe reaches out with its own code (SOCKS5 and HTTP live in prober.py), and
# an image that holds other people's configs should not carry extra tools.
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates unzip \
 && for v in ${XRAY_VERSIONS}; do \
      curl -fsSL "https://github.com/XTLS/Xray-core/releases/download/$v/Xray-linux-64.zip" \
        -o /tmp/xray.zip \
   && mkdir -p "/opt/xray/$v" \
   && unzip -q /tmp/xray.zip -d "/opt/xray/$v" xray \
   && chmod +x "/opt/xray/$v/xray" \
   && rm /tmp/xray.zip \
   && "/opt/xray/$v/xray" version | head -1; \
    done \
 && ln -s "/opt/xray/$(echo ${XRAY_VERSIONS} | cut -d' ' -f1)/xray" /usr/local/bin/xray \
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
