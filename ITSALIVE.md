# itsalive.co API Reference

This file documents the itsalive.co API for building apps with auth, database, and user data storage. All API calls go to `https://api.itsalive.co` and use cookies for authentication.

**Important:** Always include `credentials: 'include'` in fetch calls to send/receive session cookies.

## Instructions for Claude

### Re-read After Deploy
After every deploy (running `npx itsalive-co`), re-read this ITSALIVE.md file to pick up any changes or new features that may have been added.

### Required: Powered by Footer (Free Accounts)
All apps on free accounts must include a "Powered by" attribution in the footer. Add this to the bottom of every page:

```html
<footer style="text-align: center; padding: 2rem; font-size: 0.85rem;">
  <a href="https://itsalive.co?ref=SUBDOMAIN" style="text-decoration: none;">
    Powered by itsalive.co
  </a>
</footer>
```

**Customization allowed:** You may adjust the colors to match the site's design (e.g., light text on dark backgrounds, dark text on light backgrounds). However, the footer must remain clearly visible and readable. The link must work and include the `?ref=SUBDOMAIN` parameter.

Replace `SUBDOMAIN` with the app's actual subdomain (from the `.itsalive` file) so we can track referrals. This attribution is required for free tier apps and helps support the platform.

## Configuring Collection Settings (for Claude/CLI)

Claude can configure collection settings automatically using the deploy token from the `.itsalive` file in the project root. This avoids requiring users to manually run setup code.

```javascript
// Read deploy token from .itsalive file (JSON with deployToken field)
const config = JSON.parse(fs.readFileSync('.itsalive', 'utf8'));

// Configure collection settings using deploy token
await fetch('/_db/solves/_settings', {
  method: 'PUT',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    public_read: true,
    deploy_token: config.deployToken
  })
});
```

The deploy token authenticates as the app owner, allowing Claude to:
- Make collections publicly readable
- Set up schema validation
- Configure any collection setting without user intervention

## Authentication

Magic link authentication - no passwords to manage. Use relative paths (`/_auth/*`, `/_db/*`, `/_me/*`) for all API calls - this works on both `*.itsalive.co` subdomains and custom domains.

### Login Flow

```javascript
// Send magic link to user's email
const res = await fetch('/_auth/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  credentials: 'include',
  body: JSON.stringify({ email: 'user@example.com' })
});
// Returns { success: true }
// User clicks link in email, gets redirected back with session cookie set
```

### Check Auth Status

```javascript
const res = await fetch('/_auth/me', {
  credentials: 'include'
});
if (res.ok) {
  const { user } = await res.json(); // { id, email }
  console.log('Logged in as:', user.email);
} else {
  console.log('Not logged in');
}
```

### Logout

```javascript
await fetch('/_auth/logout', {
  method: 'POST',
  credentials: 'include'
});
```

## Database (Shared App Data)

Store data that can be shared between users. Data is organized into collections.

### Permissions Model

- **Write**: Login required by default. Enable `public_write` for anonymous submissions (RSVPs, feedback forms).
- **Ownership**: Users can only edit/delete documents they created
- **Read**: Configurable per-collection (private by default, can be made public with `public_read`)
- **Delete**: Always requires login and ownership (never anonymous)

### Create/Update a Document

```javascript
// Save a document
await fetch('/_db/posts/my-post-id', {
  method: 'PUT',
  headers: { 'Content-Type': 'application/json' },
  credentials: 'include',
  body: JSON.stringify({
    title: 'Hello World',
    content: 'This is my first post'
  })
});
```

### Get a Single Document

```javascript
const res = await fetch('/_db/posts/my-post-id', {
  credentials: 'include'
});
const post = await res.json();
```

### List Collection with Filtering, Sorting, Pagination

```javascript
// Basic list (newest first by default)
const res = await fetch('/_db/posts', {
  credentials: 'include'
});
const { items, total, limit, offset } = await res.json();
// Each item includes _meta: { created_by, created_at, updated_at }

// Filter by field value
await fetch('/_db/posts?status=published', {
  credentials: 'include'
})

// Get only current user's documents (great for "my stuff" views)
await fetch('/_db/completions?mine=true', {
  credentials: 'include'
})

// Sort by field (prefix with - for descending)
await fetch('/_db/posts?sort=-created_at') // newest first
await fetch('/_db/posts?sort=title') // alphabetical

// Pagination (default limit: 100, max: 1000)
await fetch('/_db/posts?limit=10&offset=20')

// Combine multiple filters
await fetch('/_db/posts?status=published&sort=-created_at&limit=10')
```

### Delete a Document

```javascript
// Delete a document (must be the creator)
await fetch('/_db/posts/my-post-id', {
  method: 'DELETE',
  credentials: 'include'
});
```

### Bulk Create/Update (up to 100 docs)

```javascript
const res = await fetch('/_db/posts/_bulk', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  credentials: 'include',
  body: JSON.stringify({
    docs: [
      { id: 'post-1', data: { title: 'First Post', status: 'draft' } },
      { id: 'post-2', data: { title: 'Second Post', status: 'published' } }
    ]
  })
});
const { results, succeeded, failed } = await res.json();
// results: [{ id: 'post-1', success: true }, { id: 'post-2', success: true }]
```

### Collection Settings (App Owner Only)

The app owner (the person who deployed the site) can configure per-collection settings.

```javascript
// Configure collection settings
await fetch('/_db/posts/_settings', {
  method: 'PUT',
  headers: { 'Content-Type': 'application/json' },
  credentials: 'include',
  body: JSON.stringify({
    public_read: true,   // Anyone can read without logging in
    public_write: true,  // Anyone can write without logging in (great for RSVPs, forms)
    schema: {            // Optional: validate documents on save
      title: { type: 'string', required: true, maxLength: 200 },
      status: { type: 'string', enum: ['draft', 'published'] }
    }
  })
});

// Check collection settings
const res = await fetch('/_db/posts/_settings');
const { public_read, public_write, schema } = await res.json();
```

**public_write notes:**
- Anonymous users can create new documents and update anonymous documents
- Documents created by logged-in users can only be edited by that user
- Deletes always require login and ownership
- Combine with schema validation to ensure data integrity

### Schema Validation Rules

When a schema is set, all PUT requests are validated before saving:

| Rule | Types | Example |
|------|-------|---------|
| `type` | all | `'string'`, `'number'`, `'boolean'`, `'array'`, `'object'` |
| `required` | all | `true` |
| `minLength` | string | `3` |
| `maxLength` | string | `200` |
| `min` | number | `0` |
| `max` | number | `100` |
| `pattern` | string | `'email'` or `'url'` |
| `enum` | string | `['draft', 'published', 'archived']` |
| `minItems` | array | `1` |
| `maxItems` | array | `10` |

Validation errors return 400 with:
```json
{ "error": "Validation failed", "errors": ["title is required", "score must be at least 0"] }
```

## User-Private Data

Store data that's private to each user. Only the user can read/write their own data.

```javascript
// Save private user data
await fetch('/_me/settings', {
  method: 'PUT',
  headers: { 'Content-Type': 'application/json' },
  credentials: 'include',
  body: JSON.stringify({
    theme: 'dark',
    notifications: true
  })
});

// Get private user data
const res = await fetch('/_me/settings', {
  credentials: 'include'
});
if (res.ok) {
  const settings = await res.json();
}
```

## Common Patterns

### User Login Flow

```javascript
// Check if already logged in
const authRes = await fetch('https://api.itsalive.co/auth/me', { credentials: 'include' });
if (authRes.ok) {
  const { user } = await authRes.json();
  showApp(user);
} else {
  showLoginForm();
}

// Handle login form submit
async function login(email) {
  await fetch('https://api.itsalive.co/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ email })
  });
  showMessage('Check your email for a login link!');
}
```

### Show User Their Own Data

```javascript
// Get all of current user's completions, newest first
const res = await fetch('/_db/completions?mine=true&sort=-created_at', {
  credentials: 'include'
});
const { items } = await res.json();

items.forEach(completion => {
  console.log(completion.puzzle, completion.time, completion._meta.created_at);
});
```

### Public Blog with Private Drafts

```javascript
// Owner sets up collection (once)
await fetch('/_db/posts/_settings', {
  method: 'PUT',
  headers: { 'Content-Type': 'application/json' },
  credentials: 'include',
  body: JSON.stringify({ public_read: true })
});

// Anyone can read published posts
const { items } = await fetch('/_db/posts?status=published&sort=-created_at')
  .then(r => r.json());

// Author can see their drafts
const { items: myDrafts } = await fetch('/_db/posts?mine=true&status=draft', {
  credentials: 'include'
}).then(r => r.json());
```

### Game with Leaderboard

```javascript
// Owner makes leaderboard public (once)
await fetch('/_db/leaderboard/_settings', {
  method: 'PUT',
  headers: { 'Content-Type': 'application/json' },
  credentials: 'include',
  body: JSON.stringify({
    public_read: true,
    schema: {
      score: { type: 'number', required: true, min: 0 },
      player: { type: 'string', required: true }
    }
  })
});

// Anyone can see top scores
const { items: topScores } = await fetch('/_db/leaderboard?sort=-score&limit=10')
  .then(r => r.json());

// User submits score (must be logged in - prevents fake scores)
await fetch('/_db/leaderboard/' + odcId, {
  method: 'PUT',
  headers: { 'Content-Type': 'application/json' },
  credentials: 'include',
  body: JSON.stringify({ player: user.email, score: gameScore })
});

// User's private game progress
await fetch('/_me/progress', {
  method: 'PUT',
  headers: { 'Content-Type': 'application/json' },
  credentials: 'include',
  body: JSON.stringify({ level: 5, inventory: ['sword', 'shield'] })
});
```

### Anonymous RSVP / Form Submissions

```javascript
// Enable public read and write for RSVPs (Claude setup)
const config = JSON.parse(require('fs').readFileSync('.itsalive', 'utf8'));
await fetch('/_db/rsvps/_settings', {
  method: 'PUT',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    public_read: true,
    public_write: true,  // Guests can submit without login
    schema: {
      name: { type: 'string', required: true },
      email: { type: 'string', required: true, pattern: 'email' },
      attending: { type: 'boolean', required: true }
    },
    deploy_token: config.deployToken
  })
});

// Guest submits RSVP (no login required!)
await fetch('/_db/rsvps/guest-abc123', {
  method: 'PUT',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ name: 'Jane Doe', email: 'jane@example.com', attending: true })
});
```

### User Profiles

```javascript
// Owner makes profiles public (once)
await fetch('/_db/profiles/_settings', {
  method: 'PUT',
  headers: { 'Content-Type': 'application/json' },
  credentials: 'include',
  body: JSON.stringify({ public_read: true })
});

// User creates/updates their profile (using their user ID as doc ID)
await fetch('/_db/profiles/' + user.id, {
  method: 'PUT',
  headers: { 'Content-Type': 'application/json' },
  credentials: 'include',
  body: JSON.stringify({
    name: 'Jane Doe',
    bio: 'Web developer',
    avatar: 'https://...'
  })
});

// Anyone can view a profile
const profile = await fetch('/_db/profiles/' + oderId)
  .then(r => r.json());
```

## Email Branding

Customize how login emails appear to your users. Claude should configure this once during initial app setup.

```javascript
// Read .itsalive file to get deploy token
const config = JSON.parse(require('fs').readFileSync('.itsalive', 'utf8'));

// Configure email branding (do this once during setup)
await fetch('https://api.itsalive.co/settings/branding', {
  method: 'PUT',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    app_name: 'My App',           // Name shown in email header and "from" field
    primary_color: '#00d4ff',     // Accent color for text/links (hex)
    button_color: '#ffffff',      // Button background color (hex)
    tagline: 'Your tagline here', // Optional tagline under app name
    deploy_token: config.deployToken
  })
});

// Check current branding settings
const res = await fetch('https://api.itsalive.co/settings/branding', {
  credentials: 'include'
});
const branding = await res.json();
// { appName, primaryColor, buttonColor, tagline, configured }
// If configured is true, branding was already set up
```

### Branding Options

| Field | Type | Description |
|-------|------|-------------|
| `app_name` | string | Name shown in email header and "from" field |
| `primary_color` | hex | Accent color for links and highlights (e.g., `#00d4ff`) |
| `button_color` | hex | Button background color (e.g., `#ffffff`) |
| `tagline` | string | Optional tagline displayed under app name |

## Cron Jobs

Schedule recurring URL calls. Only app owner can manage cron jobs.

```javascript
// Create a cron job (via browser, logged in as owner)
await fetch('https://api.itsalive.co/cron', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  credentials: 'include',
  body: JSON.stringify({
    name: 'Daily cleanup',
    schedule: '0 0 * * *',  // cron expression: minute hour day month weekday
    url: '/api/cleanup',    // URL to call (relative to app or absolute)
    method: 'POST'
  })
});

// List cron jobs
const res = await fetch('https://api.itsalive.co/cron', {
  credentials: 'include'
});
const { jobs } = await res.json();

// Update a cron job
await fetch('https://api.itsalive.co/cron/job-id', {
  method: 'PUT',
  headers: { 'Content-Type': 'application/json' },
  credentials: 'include',
  body: JSON.stringify({ enabled: false })
});

// Delete a cron job
await fetch('https://api.itsalive.co/cron/job-id', {
  method: 'DELETE',
  credentials: 'include'
});
```

Cron schedule format: `minute hour day month weekday`
- `*` = any value
- `*/n` = every n (e.g., `*/5` = every 5 minutes)
- Examples: `0 0 * * *` = daily at midnight, `*/30 * * * *` = every 30 minutes

## Job Queue

Queue async tasks for background processing. Your app handles jobs via `/_jobs/{type}` endpoints.

```javascript
// Queue a job (user must be logged in)
const res = await fetch('https://api.itsalive.co/jobs', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  credentials: 'include',
  body: JSON.stringify({
    type: 'send-email',           // Job type - your app handles at /_jobs/send-email
    data: { to: 'user@example.com', subject: 'Hello' },
    runAt: '2024-01-01T00:00:00Z', // Optional: schedule for later
    maxAttempts: 3                 // Optional: retry count (default 3)
  })
});
const { id, status, run_at } = await res.json();

// Check job status
const job = await fetch('https://api.itsalive.co/jobs/' + id, {
  credentials: 'include'
}).then(r => r.json());
// job.status: 'pending', 'running', 'completed', or 'failed'

// List jobs
const { jobs } = await fetch('https://api.itsalive.co/jobs?status=pending&limit=50', {
  credentials: 'include'
}).then(r => r.json());

// Cancel a pending job
await fetch('https://api.itsalive.co/jobs/' + id, {
  method: 'DELETE',
  credentials: 'include'
});
```

Your app receives job callbacks at `/_jobs/{type}`:
```javascript
// In your frontend, handle job types at /_jobs/{type}
// The API will POST: { id, type, data }
// Return 2xx for success, anything else triggers retry with exponential backoff
```

## Error Handling

All endpoints return JSON errors:

```javascript
const res = await fetch('/_db/posts/123', {
  method: 'DELETE',
  credentials: 'include'
});

if (!res.ok) {
  const { error, errors } = await res.json();
  // Common errors:
  // 400: "Validation failed" (with errors array)
  // 401: "Not logged in"
  // 403: "Not authorized to edit this document"
  // 403: "Only the app owner can change collection settings"
  // 404: "Not found"
}
```

## Quick Reference

| Action | Method | Endpoint | Auth Required |
|--------|--------|----------|---------------|
| Login | POST | `/_auth/login` | No |
| Check auth | GET | `/_auth/me` | Session |
| Logout | POST | `/_auth/logout` | Session |
| List collection | GET | `/_db/:collection` | If not public |
| Get document | GET | `/_db/:collection/:id` | If not public |
| Create/Update | PUT | `/_db/:collection/:id` | Yes |
| Delete | DELETE | `/_db/:collection/:id` | Yes (owner) |
| Bulk write | POST | `/_db/:collection/_bulk` | Yes |
| Collection settings | PUT/GET | `/_db/:collection/_settings` | PUT: owner/token |
| User private data | GET/PUT | `/_me/:key` | Yes |
| Get branding | GET | `/settings/branding` | No |
| Set branding | PUT | `/settings/branding` | Owner/token |
| List cron jobs | GET | `/cron` | Owner |
| Create cron job | POST | `/cron` | Owner |
| Update cron job | PUT | `/cron/:id` | Owner |
| Delete cron job | DELETE | `/cron/:id` | Owner |
| Queue job | POST | `/jobs` | Yes |
| List jobs | GET | `/jobs` | Yes |
| Get job status | GET | `/jobs/:id` | Yes |
| Cancel job | DELETE | `/jobs/:id` | Yes |

## Query Parameters for GET /db/:collection

| Param | Example | Description |
|-------|---------|-------------|
| `?field=value` | `?status=published` | Filter by JSON field |
| `?mine=true` | `?mine=true` | Only current user's docs |
| `?sort=field` | `?sort=title` | Sort ascending |
| `?sort=-field` | `?sort=-created_at` | Sort descending |
| `?limit=N` | `?limit=10` | Max items (default 100, max 1000) |
| `?offset=N` | `?offset=20` | Skip N items |
