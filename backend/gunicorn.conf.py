import os

# Render dynamically sets PORT (default 10000)
port = os.environ.get("PORT", "10000")
bind = f"0.0.0.0:{port}"

# One worker: rate-limit, lockout and graph state live in this process.
# Threads let health checks and quick requests run while a slow scan is in flight.
workers = 1
worker_class = "gthread"
threads = int(os.environ.get("WEB_THREADS", "8"))

# Generous 120s timeout to prevent premature worker terminations
timeout = 120
keepalive = 5

# Ensure immediate logging to stdout/stderr
accesslog = "-"
errorlog = "-"
loglevel = "info"
