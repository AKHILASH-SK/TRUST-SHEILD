-- TrustShield base schema (PostgreSQL 13+). Safe to run repeatedly.
-- The Flask app also adds the sealing columns on forensic_cases and the portal columns on link_scans at startup,
-- but this file is the complete reference so a fresh database can be created from the repository alone.
--   psql "$DATABASE_URL" -f backend/sql/schema.sql

CREATE TABLE IF NOT EXISTS users (
    id           SERIAL PRIMARY KEY,
    name         VARCHAR(100) NOT NULL,
    last_name    VARCHAR(100) NOT NULL,
    email        VARCHAR(255) NOT NULL UNIQUE,
    phone_number VARCHAR(20)  NOT NULL UNIQUE,
    pin          VARCHAR(100) NOT NULL,          -- bcrypt hash (60 chars); never the PIN itself
    created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS link_scans (
    id                SERIAL PRIMARY KEY,
    user_id           INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    url               VARCHAR(2048) NOT NULL,
    risk_level        VARCHAR(50),
    reasons           TEXT,
    verdict           TEXT,
    analyzed_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    source_app        VARCHAR(100),
    threat_score      DOUBLE PRECISION,
    analysis_complete BOOLEAN
);
CREATE INDEX IF NOT EXISTS idx_link_scans_user_time ON link_scans(user_id, analyzed_at DESC);

CREATE TABLE IF NOT EXISTS scan_features (
    id            SERIAL PRIMARY KEY,
    scan_id       INTEGER NOT NULL REFERENCES link_scans(id) ON DELETE CASCADE,
    feature_name  VARCHAR(255),
    feature_value TEXT,
    extracted_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS forensic_cases (
    case_id        VARCHAR(50) PRIMARY KEY,
    evidence_hash  VARCHAR(64),
    verdict        VARCHAR(100),
    threat_score   DOUBLE PRECISION,
    sender         VARCHAR(255),
    subject        VARCHAR(500),
    dossier_json   TEXT NOT NULL,                -- canonical JSON that the seal covers (no integrity block)
    raw_eml        TEXT,                         -- legacy text copy
    raw_eml_bytes  BYTEA,                        -- original uploaded bytes
    created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    owner_user_id  INTEGER,
    signature      VARCHAR(64),                  -- HMAC-SHA256 seal
    sealed_at      VARCHAR(40)                   -- exact timestamp string that was signed
);
CREATE INDEX IF NOT EXISTS idx_forensic_cases_hash    ON forensic_cases(evidence_hash);
CREATE INDEX IF NOT EXISTS idx_forensic_cases_created ON forensic_cases(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_forensic_cases_owner   ON forensic_cases(owner_user_id);

CREATE TABLE IF NOT EXISTS phishing_links (
    id            SERIAL PRIMARY KEY,
    url           VARCHAR(2048) UNIQUE NOT NULL,
    domain        VARCHAR(255),
    threat_type   VARCHAR(50),
    source        VARCHAR(100),
    confidence    DOUBLE PRECISION DEFAULT 1.0,
    date_added    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_verified TIMESTAMP,
    is_active     BOOLEAN DEFAULT TRUE
);
CREATE INDEX IF NOT EXISTS idx_phishing_links_domain ON phishing_links(domain);

CREATE TABLE IF NOT EXISTS phishing_feed_sources (
    id         SERIAL PRIMARY KEY,
    name       VARCHAR(100) UNIQUE,
    url        VARCHAR(500),
    last_fetch TIMESTAMP,
    next_fetch TIMESTAMP,
    is_active  BOOLEAN DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS official_brands (
    id                 SERIAL PRIMARY KEY,
    name               VARCHAR(100) UNIQUE,
    primary_domain     VARCHAR(255),
    aliases            JSONB DEFAULT '[]',
    trusted_subdomains JSONB DEFAULT '[]',
    trusted_cdns       JSONB DEFAULT '[]',
    date_added         TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
