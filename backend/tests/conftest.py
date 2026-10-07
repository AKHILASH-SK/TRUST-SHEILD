import os
import sys

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

# Tests must never reach a real database or the services configured in .env
os.environ["DB_HOST"] = "127.0.0.1"
os.environ["DB_PORT"] = "1"
os.environ["DB_PASSWORD"] = "test"
os.environ["DB_CONNECT_TIMEOUT"] = "1"
os.environ["ENABLE_THREAT_SYNC"] = "false"
os.environ["SECRET_KEY"] = "test-secret-key-for-unit-tests-only"
os.environ["ADMIN_API_KEY"] = "test-admin-key"
os.environ.pop("RENDER", None)
