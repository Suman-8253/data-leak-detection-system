-- =============================================================
-- Data Leak Detection & SQL Injection Prevention System
-- PostgreSQL Database Schema
-- =============================================================

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- =============================================================
-- 1. USERS TABLE
-- =============================================================
CREATE TABLE IF NOT EXISTS users (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username        VARCHAR(50) NOT NULL,
    normalized_email VARCHAR(255) NOT NULL,
    password_hash   TEXT NOT NULL,
    role            VARCHAR(20) NOT NULL DEFAULT 'user'
                    CHECK (role IN ('user', 'admin')),
    account_status  VARCHAR(20) NOT NULL DEFAULT 'active'
                    CHECK (account_status IN ('active', 'suspended', 'locked')),
    created_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_login      TIMESTAMP WITH TIME ZONE,

    CONSTRAINT uq_users_username UNIQUE (username),
    CONSTRAINT uq_users_email UNIQUE (normalized_email)
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users (username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users (normalized_email);
CREATE INDEX IF NOT EXISTS idx_users_role ON users (role);

-- =============================================================
-- 2. SECURE RECORDS TABLE
-- =============================================================
CREATE TABLE IF NOT EXISTS secure_records (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    owner_id            UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title               VARCHAR(255) NOT NULL,
    encrypted_payload   BYTEA NOT NULL,
    encryption_nonce    BYTEA NOT NULL,
    encryption_version  INTEGER NOT NULL DEFAULT 1,
    created_at          TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_secure_records_owner ON secure_records (owner_id);
CREATE INDEX IF NOT EXISTS idx_secure_records_created ON secure_records (created_at DESC);

-- =============================================================
-- 3. SECURITY EVENTS TABLE
-- =============================================================
CREATE TABLE IF NOT EXISTS security_events (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_type          VARCHAR(80) NOT NULL,
    severity            VARCHAR(20) NOT NULL
                        CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    user_id             UUID REFERENCES users(id) ON DELETE SET NULL,
    endpoint            VARCHAR(500),
    timestamp           TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    action_taken        VARCHAR(100) NOT NULL DEFAULT 'logged',
    sanitized_details   TEXT,
    correlation_id      UUID
);

CREATE INDEX IF NOT EXISTS idx_security_events_type ON security_events (event_type);
CREATE INDEX IF NOT EXISTS idx_security_events_severity ON security_events (severity);
CREATE INDEX IF NOT EXISTS idx_security_events_user ON security_events (user_id);
CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON security_events (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_correlation ON security_events (correlation_id);

-- =============================================================
-- 4. CAPABILITY CODES TABLE
-- =============================================================
CREATE TABLE IF NOT EXISTS capability_codes (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    token_hash          VARCHAR(128) NOT NULL,
    owner_id            UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    permitted_action    VARCHAR(50) NOT NULL,
    resource_scope      VARCHAR(255),
    expires_at          TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked_at          TIMESTAMP WITH TIME ZONE,
    created_at          TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_capability_token_hash UNIQUE (token_hash)
);

CREATE INDEX IF NOT EXISTS idx_capability_owner ON capability_codes (owner_id);
CREATE INDEX IF NOT EXISTS idx_capability_token_hash ON capability_codes (token_hash);
CREATE INDEX IF NOT EXISTS idx_capability_expires ON capability_codes (expires_at);
CREATE INDEX IF NOT EXISTS idx_capability_action ON capability_codes (permitted_action);

-- =============================================================
-- 5. AUDIT LOGS TABLE
-- =============================================================
CREATE TABLE IF NOT EXISTS audit_logs (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    actor_id        UUID REFERENCES users(id) ON DELETE SET NULL,
    action          VARCHAR(100) NOT NULL,
    resource_type   VARCHAR(50),
    resource_id     UUID,
    outcome         VARCHAR(20) NOT NULL DEFAULT 'success'
                    CHECK (outcome IN ('success', 'failure', 'denied')),
    timestamp       TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    correlation_id  UUID
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_actor ON audit_logs (actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs (action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_resource ON audit_logs (resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_correlation ON audit_logs (correlation_id);
