# syntax=docker/dockerfile:1
# Image for `docker compose up`: the pipeline demo and the API, no API key needed.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONPATH=/app/backend

WORKDIR /app

# Pinned dependencies first, so a code change reuses this layer.
COPY deploy/requirements.lock deploy/requirements.lock
RUN pip install -r deploy/requirements.lock \
 && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin riskops

# The demo reads examples/ relative to the source tree, so the layout is kept.
COPY LICENSE ./
COPY backend/app backend/app
COPY examples examples
COPY docs/eval/triage-tape-synthetic-7d.jsonl docs/eval/

USER riskops
CMD ["python", "-m", "app.demo"]
