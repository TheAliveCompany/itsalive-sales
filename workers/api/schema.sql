-- itsalive.co Database Schema
-- Run against D1: wrangler d1 execute itsalive-db --file=schema.sql

-- Site owners (people who deploy sites)
CREATE TABLE IF NOT EXISTS owners (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Deployed apps/sites
CREATE TABLE IF NOT EXISTS apps (
  subdomain TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL,
  custom_domain TEXT,
  cf_zone_id TEXT,
  domain_status TEXT DEFAULT 'none',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (owner_id) REFERENCES owners(id)
);

-- Index for custom domain lookups
CREATE INDEX IF NOT EXISTS idx_apps_custom_domain ON apps(custom_domain);

-- Deploy tokens for progressive deploys
CREATE TABLE IF NOT EXISTS deploy_tokens (
  token TEXT PRIMARY KEY,
  subdomain TEXT NOT NULL,
  email TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Pending deployments (waiting for email verification)
CREATE TABLE IF NOT EXISTS pending_deploys (
  id TEXT PRIMARY KEY,
  subdomain TEXT NOT NULL,
  email TEXT NOT NULL,
  token TEXT,
  files_manifest TEXT,
  expires_at DATETIME NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- App users (end users of deployed apps)
CREATE TABLE IF NOT EXISTS app_users (
  id TEXT PRIMARY KEY,
  app_subdomain TEXT NOT NULL,
  email TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(app_subdomain, email)
);

-- User sessions
CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  app_subdomain TEXT NOT NULL,
  user_id TEXT NOT NULL,
  expires_at DATETIME NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES app_users(id)
);

-- App data (shared data within an app)
CREATE TABLE IF NOT EXISTS app_data (
  app_subdomain TEXT NOT NULL,
  collection TEXT NOT NULL,
  doc_id TEXT NOT NULL,
  data TEXT NOT NULL,
  created_by TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (app_subdomain, collection, doc_id),
  FOREIGN KEY (created_by) REFERENCES app_users(id)
);

-- User-private data
CREATE TABLE IF NOT EXISTS user_data (
  app_subdomain TEXT NOT NULL,
  user_id TEXT NOT NULL,
  key TEXT NOT NULL,
  data TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (app_subdomain, user_id, key),
  FOREIGN KEY (user_id) REFERENCES app_users(id)
);

-- Collection settings (public read, schema validation, etc.)
CREATE TABLE IF NOT EXISTS collection_settings (
  app_subdomain TEXT NOT NULL,
  collection TEXT NOT NULL,
  public_read BOOLEAN DEFAULT FALSE,
  schema TEXT, -- JSON schema for validation
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (app_subdomain, collection)
);

-- App settings (branding, customization)
CREATE TABLE IF NOT EXISTS app_settings (
  app_subdomain TEXT PRIMARY KEY,
  email_app_name TEXT,           -- Custom app name for emails (defaults to subdomain)
  email_primary_color TEXT DEFAULT '#00d4ff',  -- Primary accent color
  email_button_color TEXT DEFAULT '#ffffff',   -- Button background color
  email_tagline TEXT,            -- Custom tagline under app name
  branding_configured BOOLEAN DEFAULT FALSE,   -- Flag that setup is complete
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Cron jobs (scheduled URL execution)
CREATE TABLE IF NOT EXISTS cron_jobs (
  id TEXT PRIMARY KEY,
  app_subdomain TEXT NOT NULL,
  name TEXT,
  schedule TEXT NOT NULL, -- cron expression: minute hour day month weekday
  url TEXT NOT NULL,
  method TEXT DEFAULT 'POST',
  headers TEXT, -- JSON object
  body TEXT,
  enabled BOOLEAN DEFAULT TRUE,
  last_run DATETIME,
  next_run DATETIME,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Job queue (async task processing)
CREATE TABLE IF NOT EXISTS jobs (
  id TEXT PRIMARY KEY,
  app_subdomain TEXT NOT NULL,
  type TEXT NOT NULL,
  data TEXT, -- JSON payload
  status TEXT DEFAULT 'pending', -- pending, running, completed, failed
  run_at DATETIME NOT NULL,
  attempts INTEGER DEFAULT 0,
  max_attempts INTEGER DEFAULT 3,
  last_error TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  completed_at DATETIME
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_app_data_subdomain ON app_data(app_subdomain);
CREATE INDEX IF NOT EXISTS idx_app_data_collection ON app_data(app_subdomain, collection);
CREATE INDEX IF NOT EXISTS idx_user_data_user ON user_data(app_subdomain, user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_subdomain ON sessions(app_subdomain);
CREATE INDEX IF NOT EXISTS idx_app_users_subdomain ON app_users(app_subdomain);
CREATE INDEX IF NOT EXISTS idx_cron_jobs_subdomain ON cron_jobs(app_subdomain);
CREATE INDEX IF NOT EXISTS idx_cron_jobs_next_run ON cron_jobs(next_run);
CREATE INDEX IF NOT EXISTS idx_jobs_subdomain ON jobs(app_subdomain);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status, run_at);
