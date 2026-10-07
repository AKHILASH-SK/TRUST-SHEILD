"""
TrustShield - single source of database connection settings.

In production (Render / Fly / Railway or TRUSTSHIELD_ENV=production) DB_HOST and
DB_PASSWORD must be provided; the local defaults only apply to development.
"""

import os

from dotenv import load_dotenv

load_dotenv()

from security import IS_PRODUCTION

if IS_PRODUCTION and not (os.getenv("DB_HOST") and os.getenv("DB_PASSWORD")):
    raise RuntimeError("DB_HOST and DB_PASSWORD must be set in production")

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "port": int(os.getenv("DB_PORT", "5432")),
    "dbname": os.getenv("DB_NAME", "trustshield_db"),
    "user": os.getenv("DB_USER", "postgres"),
    "password": os.getenv("DB_PASSWORD", "postgres"),
    "connect_timeout": int(os.getenv("DB_CONNECT_TIMEOUT", "8")),
}
