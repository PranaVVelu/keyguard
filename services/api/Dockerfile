# KeyGuard API: local demo image (D-009 limits apply: single process, in-memory rate-limit counters).
FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:0.13.7 /uv /usr/local/bin/uv

WORKDIR /srv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PROJECT_ENVIRONMENT=/srv/.venv
COPY pyproject.toml uv.lock ./
RUN uv sync --locked --no-dev --no-install-project

COPY app ./app

RUN useradd --create-home --uid 10001 keyguard && mkdir -p /data && chown keyguard /data
USER keyguard

ENV KEYGUARD_DATABASE_URL=sqlite:////data/keyguard.db
# Hosts like Render assign the port through $PORT; locally it defaults to 8000.
ENV PORT=8000
EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s --retries=5 \
  CMD python -c "import os, urllib.request; urllib.request.urlopen(f'http://127.0.0.1:{os.environ[\"PORT\"]}/api/health')"
# One worker by default (memory rate-limit counters are per process, D-009). With KEYGUARD_RATE_STORE=database
# (required in production, D-013) more workers are safe; set KEYGUARD_WORKERS to scale.
# --no-proxy-headers: uvicorn must not rewrite the client address from X-Forwarded-For; the app decides whom to
# trust (KEYGUARD_TRUSTED_PROXIES or the web proxy's shared secret).
CMD ["sh", "-c", "exec /srv/.venv/bin/uvicorn app.main:create_app --factory --host 0.0.0.0 --port \"$PORT\" --workers \"${KEYGUARD_WORKERS:-1}\" --no-proxy-headers"]
