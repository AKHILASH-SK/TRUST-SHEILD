import os

# Render dynamically sets PORT (default 10000)
port = os.environ.get("PORT", "10000")
bind = f"0.0.0.0:{port}"

# Use 1 worker with 2 threads to allow concurrent health checks without blocking
workers = 1
threads = 2

# Generous 120s timeout to prevent premature worker terminations
timeout = 120
keepalive = 5

# Ensure immediate logging to stdout/stderr
accesslog = "-"
errorlog = "-"
loglevel = "info"
