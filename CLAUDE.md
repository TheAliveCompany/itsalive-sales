# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

itsalive.co is a one-command deployment platform for static web apps. Users run `npx itsalive`, pick a subdomain, verify email, and their site is live at `subdomain.itsalive.co`.

**Key concept:** Instead of an SDK, we inject a CLAUDE.md into deployed projects that teaches Claude Code how to use our auth and database APIs. The AI is the SDK.

## Build & Development Commands

```bash
# Deploy workers
npx wrangler deploy --config workers/serve/wrangler.toml
npx wrangler deploy --config workers/api/wrangler.toml

# Run locally
npx wrangler dev --config workers/serve/wrangler.toml
npx wrangler dev --config workers/api/wrangler.toml

# Database operations
npx wrangler d1 execute itsalive-db --file=schema.sql
npx wrangler d1 execute itsalive-db --command="SELECT * FROM apps"

# CLI development (from cli/)
npm link  # to test `npx itsalive` locally
```

## Architecture

Two Cloudflare Workers:

1. **Serve Worker** (`workers/serve/`) - Routes `*.itsalive.co` requests to R2 bucket, serves static files from `R2:/{subdomain}/path`

2. **API Worker** (`workers/api/`) - Handles all API endpoints at `api.itsalive.co`:
   - Deploy flow: `/deploy/init`, `/deploy/:id/status`, `/verify`, `/deploy/:id/upload-urls`, `/deploy/:id/finalize`
   - Auth: `/auth/login` (magic link), `/auth/me`, `/auth/logout`
   - Database: `/db/:collection/:id`, `/me/:key` (user-private data)

**Storage:**
- R2 bucket `itsalive-sites` - deployed static files
- D1 database `itsalive-db` - owners, apps, pending_deploys, app_users, sessions, app_data, user_data
- KV namespaces - RATE_LIMITS, EMAIL_TOKENS

**CLI** (`cli/`) - The `npx itsalive` tool that scans files, handles deploy flow, and writes CLAUDE.md to user projects.

## Deployment Flow

1. CLI calls `POST /deploy/init` with subdomain, email, manifest
2. API sends verification email, returns deploy_id
3. CLI polls `GET /deploy/:id/status` until email verified
4. CLI gets presigned R2 URLs from `POST /deploy/:id/upload-urls`
5. CLI uploads files directly to R2 in parallel
6. CLI calls `POST /deploy/:id/finalize`
7. CLI writes CLAUDE.md template to user's project

## Sales Site (site/)

The marketing site at itsalive.co lives in the `site/` directory and auto-deploys on git push.

**To deploy the sales site:** Simply commit and push to GitHub. The site auto-deploys via GitHub Pages.
```bash
git add site/
git commit -m "Update sales site"
git push
```

**When creating new pages:**
- Always add Open Graph tags for social sharing cards
- Use this template in the `<head>`:
```html
<!-- Open Graph -->
<meta property="og:type" content="website">
<meta property="og:url" content="https://itsalive.co/PAGE_PATH/">
<meta property="og:title" content="PAGE_TITLE - itsalive.co">
<meta property="og:description" content="PAGE_DESCRIPTION">
<meta property="og:image" content="https://itsalive.co/og-image.png">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="PAGE_TITLE - itsalive.co">
<meta name="twitter:description" content="PAGE_DESCRIPTION">
<meta name="twitter:image" content="https://itsalive.co/og-image.png">
```
