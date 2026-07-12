# grokcli-2api — high-concurrency image (Redis + PostgreSQL required at runtime)
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    GROK2API_HOST=0.0.0.0 \
    GROK2API_PORT=3000 \
    GROK2API_OPEN_BROWSER=0 \
    GROK2API_STORE_BACKEND=hybrid \
    GROK2API_WORKERS=4 \
    PYTHONPATH=/app/grok-build-auth

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
COPY requirements-store.txt /app/requirements-store.txt
RUN python -m pip install --no-cache-dir -r /app/requirements.txt \
    && python -m pip install --no-cache-dir -r /app/requirements-store.txt

COPY . /app

RUN test -f /app/grok-build-auth/xconsole_client/client.py \
    && test -f /app/grok_build_adapter.py \
    && python -c "import grok_build_adapter, app; print('build-check', app.APP_VERSION, grok_build_adapter.ADAPTER_BUILD)"

EXPOSE 3000

# data/ only for optional JSON import artifacts / models cache
VOLUME ["/app/data"]

CMD ["python", "app.py"]
