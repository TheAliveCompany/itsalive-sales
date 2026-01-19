-- App owners (people who deploy sites)
CREATE TABLE IF NOT EXISTS owners (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Deployed apps
CREATE TABLE IF NOT EXISTS apps (
  subdomain TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL,
  custom_domain TEXT,
  cf_zone_id TEXT,
  domain_status TEXT DEFAULT 'none',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (owner_id) REFERENCES owners(id)
);

-- Pending deployments (awaiting email verification)
CREATE TABLE IF NOT EXISTS pending_deploys (
  id TEXT PRIMARY KEY,
  subdomain TEXT NOT NULL,
  email TEXT NOT NULL,
  token TEXT,
  files_manifest JSON,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  expires_at DATETIME NOT NULL
);

-- App users (end users who log into deployed apps)
CREATE TABLE IF NOT EXISTS app_users (
  id TEXT PRIMARY KEY,
  app_subdomain TEXT NOT NULL,
  email TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(app_subdomain, email),
  FOREIGN KEY (app_subdomain) REFERENCES apps(subdomain)
);

-- Sessions for app users
CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  app_subdomain TEXT NOT NULL,
  user_id TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  expires_at DATETIME NOT NULL
);

-- App data (the db.get/set store)
CREATE TABLE IF NOT EXISTS app_data (
  app_subdomain TEXT NOT NULL,
  collection TEXT NOT NULL,
  doc_id TEXT NOT NULL,
  data JSON NOT NULL,
  created_by TEXT,
  lat REAL,
  lng REAL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (app_subdomain, collection, doc_id)
);

-- User-scoped data (the me.get/set store)
CREATE TABLE IF NOT EXISTS user_data (
  app_subdomain TEXT NOT NULL,
  user_id TEXT NOT NULL,
  key TEXT NOT NULL,
  data JSON NOT NULL,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (app_subdomain, user_id, key)
);

-- Deploy tokens (for subsequent deploys without email verification)
CREATE TABLE IF NOT EXISTS deploy_tokens (
  token TEXT PRIMARY KEY,
  subdomain TEXT NOT NULL,
  email TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (subdomain) REFERENCES apps(subdomain)
);

-- Collection settings (public_read, public_write, schema validation)
CREATE TABLE IF NOT EXISTS collection_settings (
  app_subdomain TEXT NOT NULL,
  collection TEXT NOT NULL,
  public_read INTEGER DEFAULT 0,
  public_write INTEGER DEFAULT 0,
  schema JSON,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (app_subdomain, collection)
);

-- App settings (branding, etc.)
CREATE TABLE IF NOT EXISTS app_settings (
  app_subdomain TEXT PRIMARY KEY,
  email_app_name TEXT,
  email_primary_color TEXT,
  email_button_color TEXT,
  email_tagline TEXT,
  branding_configured INTEGER DEFAULT 0,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Platform bug reports from Claude instances
CREATE TABLE IF NOT EXISTS platform_bugs (
  id TEXT PRIMARY KEY,
  app_subdomain TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  code_context TEXT,
  error_message TEXT,
  severity TEXT DEFAULT 'medium',
  status TEXT DEFAULT 'pending',
  auto_fixable INTEGER DEFAULT 0,
  fix_applied TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  reviewed_at DATETIME,
  fixed_at DATETIME
);

-- Platform feedback from Claude instances
CREATE TABLE IF NOT EXISTS platform_feedback (
  id TEXT PRIMARY KEY,
  app_subdomain TEXT NOT NULL,
  category TEXT,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  use_case TEXT,
  priority_suggestion TEXT,
  status TEXT DEFAULT 'new',
  roadmap_item_id TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  reviewed_at DATETIME
);

-- User file uploads
CREATE TABLE IF NOT EXISTS uploads (
  id TEXT PRIMARY KEY,
  app_subdomain TEXT NOT NULL,
  filename TEXT NOT NULL,
  original_filename TEXT,
  content_type TEXT NOT NULL,
  size INTEGER NOT NULL,
  width INTEGER,
  height INTEGER,
  variants TEXT,
  created_by TEXT,
  public INTEGER DEFAULT 1,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Email sending log
CREATE TABLE IF NOT EXISTS email_log (
  id TEXT PRIMARY KEY,
  app_subdomain TEXT NOT NULL,
  to_email TEXT NOT NULL,
  to_user_id TEXT,
  subject TEXT NOT NULL,
  template TEXT,
  status TEXT DEFAULT 'queued',
  error_message TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  sent_at DATETIME
);

-- Email templates
CREATE TABLE IF NOT EXISTS email_templates (
  id TEXT PRIMARY KEY,
  app_subdomain TEXT NOT NULL,
  name TEXT NOT NULL,
  subject TEXT NOT NULL,
  html_body TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(app_subdomain, name)
);

-- Webhooks for collection events
CREATE TABLE IF NOT EXISTS webhooks (
  id TEXT PRIMARY KEY,
  app_subdomain TEXT NOT NULL,
  collection TEXT NOT NULL,
  event TEXT NOT NULL,
  url TEXT NOT NULL,
  secret TEXT,
  enabled INTEGER DEFAULT 1,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Cron jobs
CREATE TABLE IF NOT EXISTS cron_jobs (
  id TEXT PRIMARY KEY,
  app_subdomain TEXT NOT NULL,
  name TEXT,
  schedule TEXT NOT NULL,
  url TEXT NOT NULL,
  method TEXT DEFAULT 'POST',
  headers TEXT,
  body TEXT,
  enabled INTEGER DEFAULT 1,
  last_run DATETIME,
  next_run DATETIME,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Job queue
CREATE TABLE IF NOT EXISTS jobs (
  id TEXT PRIMARY KEY,
  app_subdomain TEXT NOT NULL,
  type TEXT NOT NULL,
  data TEXT,
  status TEXT DEFAULT 'pending',
  run_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  started_at DATETIME,
  completed_at DATETIME,
  attempts INTEGER DEFAULT 0,
  max_attempts INTEGER DEFAULT 3,
  error_message TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- AI credits (token balance per owner account)
CREATE TABLE IF NOT EXISTS owner_credits (
  owner_id TEXT PRIMARY KEY,
  balance INTEGER DEFAULT 0,
  lifetime_purchased INTEGER DEFAULT 0,
  lifetime_used INTEGER DEFAULT 0,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (owner_id) REFERENCES owners(id)
);

-- AI usage log (detailed tracking for billing)
CREATE TABLE IF NOT EXISTS ai_usage (
  id TEXT PRIMARY KEY,
  app_subdomain TEXT NOT NULL,
  user_id TEXT,
  provider TEXT NOT NULL,
  tier TEXT NOT NULL,
  model TEXT NOT NULL,
  input_tokens INTEGER NOT NULL,
  output_tokens INTEGER NOT NULL,
  total_tokens INTEGER NOT NULL,
  credits_used INTEGER NOT NULL,
  has_vision INTEGER DEFAULT 0,
  estimated_cost_usd REAL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- AI settings per app (token limits, etc.)
CREATE TABLE IF NOT EXISTS ai_settings (
  app_subdomain TEXT PRIMARY KEY,
  max_input_tokens INTEGER DEFAULT 4096,
  max_output_tokens INTEGER DEFAULT 4096,
  allowed_tiers TEXT DEFAULT 'good,best',
  enabled INTEGER DEFAULT 1,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- User activity tracking for DAU/WAU/MAU
CREATE TABLE IF NOT EXISTS user_activity (
  app_subdomain TEXT NOT NULL,
  user_id TEXT NOT NULL,
  date TEXT NOT NULL,
  PRIMARY KEY (app_subdomain, user_id, date)
);

-- OG routes for dynamic meta tags in SPAs
CREATE TABLE IF NOT EXISTS og_routes (
  id TEXT PRIMARY KEY,
  app_subdomain TEXT NOT NULL,
  pattern TEXT NOT NULL,           -- '/recipe/:id' or '/user/:username'
  collection TEXT NOT NULL,        -- 'recipes' or 'users'
  id_param TEXT DEFAULT 'id',      -- which URL param is the doc ID
  title_field TEXT,                -- 'title' or 'name'
  description_field TEXT,          -- 'description' or 'bio'
  image_field TEXT,                -- 'image_url' or 'avatar'
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(app_subdomain, pattern)
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_pending_token ON pending_deploys(token);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(app_subdomain, user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_app_data_collection ON app_data(app_subdomain, collection);
CREATE INDEX IF NOT EXISTS idx_app_data_geo ON app_data(app_subdomain, collection, lat, lng);
CREATE INDEX IF NOT EXISTS idx_apps_owner ON apps(owner_id);
CREATE INDEX IF NOT EXISTS idx_apps_custom_domain ON apps(custom_domain);
CREATE INDEX IF NOT EXISTS idx_deploy_tokens_subdomain ON deploy_tokens(subdomain);
CREATE INDEX IF NOT EXISTS idx_bugs_status ON platform_bugs(status);
CREATE INDEX IF NOT EXISTS idx_feedback_status ON platform_feedback(status);
CREATE INDEX IF NOT EXISTS idx_uploads_subdomain ON uploads(app_subdomain);
CREATE INDEX IF NOT EXISTS idx_uploads_user ON uploads(app_subdomain, created_by);
CREATE INDEX IF NOT EXISTS idx_email_log_subdomain ON email_log(app_subdomain, created_at);
CREATE INDEX IF NOT EXISTS idx_email_log_user ON email_log(app_subdomain, to_user_id);
CREATE INDEX IF NOT EXISTS idx_webhooks_subdomain ON webhooks(app_subdomain, collection);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(app_subdomain, status, run_at);
CREATE INDEX IF NOT EXISTS idx_cron_next_run ON cron_jobs(enabled, next_run);
CREATE INDEX IF NOT EXISTS idx_ai_usage_app ON ai_usage(app_subdomain, created_at);
CREATE INDEX IF NOT EXISTS idx_ai_usage_user ON ai_usage(app_subdomain, user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_og_routes_subdomain ON og_routes(app_subdomain);
CREATE INDEX IF NOT EXISTS idx_user_activity_date ON user_activity(app_subdomain, date);
CREATE INDEX IF NOT EXISTS idx_app_users_created ON app_users(app_subdomain, created_at);

-- Upload usage tracking (for billing stats)
CREATE TABLE IF NOT EXISTS upload_usage (
  id TEXT PRIMARY KEY,
  app_subdomain TEXT NOT NULL,
  user_id TEXT,
  filename TEXT NOT NULL,
  content_type TEXT NOT NULL,
  size INTEGER NOT NULL,
  credits_used INTEGER DEFAULT 5,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_upload_usage_app ON upload_usage(app_subdomain, created_at);

-- Stripe customer tracking
CREATE TABLE IF NOT EXISTS stripe_customers (
  owner_id TEXT PRIMARY KEY,
  stripe_customer_id TEXT UNIQUE NOT NULL,
  default_payment_method TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (owner_id) REFERENCES owners(id)
);

-- Subscriptions (per-site, credits are shared account-wide)
CREATE TABLE IF NOT EXISTS subscriptions (
  id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL,
  app_subdomain TEXT NOT NULL,
  stripe_subscription_id TEXT UNIQUE NOT NULL,
  plan TEXT NOT NULL,  -- 'pro_monthly' or 'pro_annual'
  status TEXT NOT NULL DEFAULT 'active',
  current_period_start DATETIME,
  current_period_end DATETIME,
  cancel_at_period_end INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (owner_id) REFERENCES owners(id),
  FOREIGN KEY (app_subdomain) REFERENCES apps(subdomain)
);

-- Auto-refill settings
CREATE TABLE IF NOT EXISTS auto_refill_settings (
  owner_id TEXT PRIMARY KEY,
  enabled INTEGER DEFAULT 1,
  threshold INTEGER DEFAULT 10000,
  refill_amount INTEGER DEFAULT 50000,
  refill_price INTEGER DEFAULT 5000,  -- $50.00 in cents
  last_refill_at DATETIME,
  FOREIGN KEY (owner_id) REFERENCES owners(id)
);

-- Credit transactions log
CREATE TABLE IF NOT EXISTS credit_transactions (
  id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL,
  amount INTEGER NOT NULL,
  type TEXT NOT NULL,  -- 'subscription', 'auto_refill', 'signup_bonus', 'manual'
  stripe_payment_intent_id TEXT,
  description TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (owner_id) REFERENCES owners(id)
);

CREATE INDEX IF NOT EXISTS idx_subscriptions_owner ON subscriptions(owner_id);
CREATE INDEX IF NOT EXISTS idx_subscriptions_app ON subscriptions(app_subdomain);
CREATE INDEX IF NOT EXISTS idx_subscriptions_stripe ON subscriptions(stripe_subscription_id);
CREATE INDEX IF NOT EXISTS idx_credit_transactions_owner ON credit_transactions(owner_id, created_at);
CREATE INDEX IF NOT EXISTS idx_stripe_customers_stripe ON stripe_customers(stripe_customer_id);
