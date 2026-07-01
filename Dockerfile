FROM python:3.12-slim

# `gosu` lets the entrypoint drop from root to the runtime user cleanly.
RUN apt-get update && apt-get install -y --no-install-recommends gosu \
    && rm -rf /var/lib/apt/lists/*

# The app runs as this unprivileged user by default. Its uid/gid can be remapped
# at runtime via PUID/PGID (see docker-entrypoint.sh) so it can write to
# host-owned bind mounts on a NAS. (The Debian base already ships a system user
# named `proxy` at uid 13, so we use a distinct name to avoid a collision.)
RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin appuser

WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir . && pip cache purge || true

COPY policy.yaml ./policy.yaml
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENV DATA_DIR=/data \
    POLICY_PATH=/app/policy.yaml \
    TOKEN_STORE_PATH=/data/token.json \
    MCP_HOST=0.0.0.0 MCP_PORT=8443 \
    ADMIN_HOST=0.0.0.0 ADMIN_PORT=8081

RUN mkdir -p /data && chown -R appuser:appuser /data

# Start as root so the entrypoint can remap PUID/PGID and chown /data; it then
# drops to the unprivileged user (default uid 10001) before exec'ing the app.
EXPOSE 8443 8081
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD python -c "import urllib.request,os; urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('ADMIN_PORT','8081')+'/healthz')" || exit 1

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["gmail-proxy"]
