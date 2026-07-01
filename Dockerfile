FROM python:3.12-slim

# Run as a non-root user.
RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin proxy

WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir . && pip cache purge || true

COPY policy.yaml ./policy.yaml

ENV DATA_DIR=/data \
    POLICY_PATH=/app/policy.yaml \
    MCP_HOST=0.0.0.0 MCP_PORT=8443 \
    ADMIN_HOST=0.0.0.0 ADMIN_PORT=8081

RUN mkdir -p /data /secrets && chown -R proxy:proxy /data /secrets
USER proxy

EXPOSE 8443 8081
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD python -c "import urllib.request,os; urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('ADMIN_PORT','8081')+'/healthz')" || exit 1

CMD ["gmail-proxy"]
