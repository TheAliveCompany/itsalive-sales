# itsalive.co Feature Requests from Building Mushroom

Building mushroom (a writing platform) on itsalive was smooth overall. Here are features that would have made it better or that we're waiting on:

---

## Already on your roadmap (excited for these!)

### Image uploads

**What we need:** Users writing stories need to embed images in their rich text content.

**Ideal API design:**

```javascript
// Upload an image
const formData = new FormData();
formData.append('file', fileInput.files[0]);

const res = await fetch('https://api.itsalive.co/uploads', {
  method: 'POST',
  credentials: 'include',
  body: formData
});

const { url, id } = await res.json();
// url: "https://cdn.itsalive.co/mushroom/abc123.jpg"
// id: "abc123" (for deletion later)
```

**What would make it great:**
- Auto-resize/optimize images (max 1600px wide, compress to ~80% quality)
- Return multiple sizes: `{ url, thumbnail, medium, large }`
- Support paste from clipboard (base64 upload)
- CORS headers so images work in `<img>` tags
- Optional: `?width=800` parameter on URL for on-the-fly resizing

**How we'd use it:**
```javascript
// In our rich text editor toolbar
async function insertImage() {
  const input = document.createElement('input');
  input.type = 'file';
  input.accept = 'image/*';
  input.onchange = async () => {
    const formData = new FormData();
    formData.append('file', input.files[0]);
    const { url } = await fetch(`${API}/uploads`, {
      method: 'POST',
      credentials: 'include',
      body: formData
    }).then(r => r.json());

    document.execCommand('insertImage', false, url);
  };
  input.click();
}
```

---

### Scheduled emails / digests

**What we need:** Users choose daily or weekly email digests. We store their preference in their profile as `digest_frequency: "daily" | "weekly" | "off"`.

**Ideal API design:**

```javascript
// Configure a digest (one-time setup, done by Claude during deploy)
await fetch('https://api.itsalive.co/digests', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    deploy_token: config.deployToken,

    // Which users to email
    audience: {
      collection: 'profiles',
      filter: { digest_frequency: 'daily' }  // or 'weekly'
    },

    // Schedule
    schedule: 'daily',  // or 'weekly' (Sundays?)
    time: '08:00',      // UTC

    // What content to include (per-user)
    content: {
      // Query to run FOR EACH USER, with {{user_id}} substitution
      collection: 'stories',
      filter: { status: 'published' },
      // Only stories from people this user follows
      join: {
        collection: 'follows',
        on: 'author_id = follows.following_id',
        where: { follower_id: '{{user_id}}' }
      },
      sort: '-created_at',
      limit: 10,
      // Only stories since last digest
      since: '{{last_digest_at}}'
    },

    // Email template
    template: {
      subject: 'Your mushroom digest',
      // Handlebars-style template
      body: `
        <h1>Stories from your feed</h1>
        {{#each stories}}
          <div>
            <h2>{{title}}</h2>
            <p>by {{author_email}}</p>
            <p>{{excerpt content 200}}</p>
            <a href="https://mushroom.itsalive.co/#/story/{{id}}">Read more</a>
          </div>
        {{/each}}
        {{#if stories.length == 0}}
          <p>No new stories this week. Why not write one?</p>
        {{/if}}
        <hr>
        <a href="https://mushroom.itsalive.co/#/settings">Update preferences</a>
      `
    }
  })
});
```

**Simpler alternative** (if the above is too complex):

```javascript
// Just let us define a webhook that gets called on schedule
await fetch('https://api.itsalive.co/cron', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    deploy_token: config.deployToken,
    schedule: '0 8 * * *',  // cron syntax, daily at 8am
    webhook: 'https://some-serverless-function.com/send-digests'
  })
});
```

Then we'd handle the logic ourselves in a serverless function. Less magical, but more flexible.

**Even simpler alternative:**

```javascript
// Digest as a special collection type
await fetch('https://api.itsalive.co/db/digests/_settings', {
  method: 'PUT',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    deploy_token: config.deployToken,
    type: 'email_digest',

    // Who gets emails (reference a field in profiles)
    frequency_field: 'digest_frequency',  // looks for 'daily' or 'weekly'

    // What to send (we write digest docs ourselves)
    // Each doc: { user_id, subject, html, created_at }
    // itsalive sends unsent docs matching the schedule
  })
});

// Then our app (or a cron job) creates digest documents:
await fetch('https://api.itsalive.co/db/digests/user123-2024-01-15', {
  method: 'PUT',
  headers: { 'Content-Type': 'application/json' },
  credentials: 'include',
  body: JSON.stringify({
    user_id: 'user123',
    user_email: 'user@example.com',
    subject: 'Your weekly mushroom digest',
    html: '<h1>Stories from your feed</h1>...',
    send_at: '2024-01-15T08:00:00Z'
  })
});
// itsalive picks it up and sends at send_at time
```

**Our preference:** The "simpler alternative" with a cron webhook would be most flexible. We can generate the HTML ourselves and just need itsalive to trigger it on schedule.

---

## Would significantly improve the app

### Location-based queries
**Problem:** We want to show "writers within 50 miles" but can only do text matching on city names.

**Wish:**
- Store lat/lng coordinates (or auto-geocode from city name)
- Query by distance: `?near=lat,lng&radius=50mi`

### Batch/bulk reads
**Problem:** To display a feed, we fetch profiles one-by-one in a loop. Slow and lots of requests.

**Wish:**
- `GET /db/profiles?id=abc,def,ghi` - fetch multiple docs by ID in one request
- Or: `POST /db/profiles/_batch` with array of IDs

### Full-text search
**Problem:** No way to search story content or titles.

**Wish:**
- `?search=keyword` parameter that searches across text fields
- Even basic substring matching would help

### Aggregation queries
**Problem:** To get counts, we fetch all items and count client-side.

**Wish:**
- `?count=true` returns just the count
- `GET /db/stories/_count?author_id=abc`

---

## Would improve SEO / sharing

### Dynamic meta tags / SSR
**Problem:** All pages have the same OG tags because it's a static SPA. Sharing a specific story shows generic "mushroom" preview, not the story title.

**Wish:**
- Edge function or server-side rendering option
- Or: a way to define dynamic meta tags per-route
- Or: an OG image generation service (`/og/stories/{id}` returns a rendered image)

---

## Nice to have

### Real-time subscriptions
- WebSocket or SSE for live updates
- "New story in your feed" without refresh

### Webhooks
- Notify external services on collection changes
- Could integrate with email services, analytics, etc.

### Collection indexes
- Mark fields as indexed for faster queries
- `?sort=-created_at` is common, should be fast

### Relational / nested queries
- Fetch story + author profile in one request
- `?include=author` or similar

### Custom email templates
- Beyond branding colors
- Full HTML template control for magic links

### Data export
- Download all my app's data as JSON
- For backups or migration

---

## Minor DX improvements

### CLI improvements
- `npx itsalive-co --watch` for auto-deploy on file changes
- `npx itsalive-co logs` to see recent auth/db activity

### Dashboard
- Web UI to browse collections, see users, basic analytics
- Useful for debugging and understanding usage

---

## Summary: Top 3 requests

1. **Batch reads** - fetch multiple docs by ID (biggest perf win)
2. **Location queries** - distance-based filtering
3. **Dynamic OG images** - or any SSR capability for meta tags

Thanks for building itsalive — the auth + database + hosting combo made it possible to build this entire app in a single HTML file. Very cool.
