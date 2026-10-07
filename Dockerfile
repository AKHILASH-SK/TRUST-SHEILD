# TrustShield backend with a real headless-Chromium sandbox.
# Build from the repository root:  docker build -t trustshield-backend .
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    TRUSTSHIELD_ENV=production \
    CHROME_BIN=/usr/bin/chromium \
    CHROMEDRIVER_PATH=/usr/bin/chromedriver \
    MAX_CONCURRENT_ANALYSES=2 \
    PORT=8080

RUN apt-get update \
    && apt-get install -y --no-install-recommends chromium chromium-driver fonts-liberation ca-certificates libgomp1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /srv

COPY backend/requirements.txt backend/requirements.txt
RUN pip install -r backend/requirements.txt

COPY backend backend
COPY frontend frontend

RUN useradd --create-home --uid 10001 app \
    && mkdir -p /srv/backend/data \
    && chown -R app:app /srv
USER app

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s \
    CMD python -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/health' % os.environ.get('PORT','8080'), timeout=4)"

CMD ["gunicorn", "--chdir", "backend", "-c", "backend/gunicorn.conf.py", "app:app"]
