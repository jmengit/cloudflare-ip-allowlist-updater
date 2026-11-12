FROM python:3.12-alpine

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app
COPY pyproject.toml README.md /app/
COPY src /app/src
RUN pip install --no-cache-dir .

USER 65532:65532
ENTRYPOINT ["cf-allowlist-updater"]

# Functional probe: healthy only when a real Cloudflare update succeeded within
# HEALTH_MAX_AGE_SECONDS (default: one update interval + 10 minutes).
HEALTHCHECK --interval=60s --timeout=15s --start-period=5m --retries=3 \
    CMD ["cf-allowlist-updater", "--health"]
