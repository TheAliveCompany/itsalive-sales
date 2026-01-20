import { AutoRouter } from 'itty-router';

// Custom CORS middleware that supports async custom domain lookup
async function handleCors(request, env) {
  try {
    // Check for proxied requests from serve worker
    const forwardedHost = request.headers.get('X-Forwarded-Host');
    if (forwardedHost) {
      // Check if it's an itsalive.co subdomain
      if (forwardedHost.endsWith('.itsalive.co')) {
        const match = forwardedHost.match(/^([^.]+)\.itsalive\.co$/);
        if (match) {
          request.subdomainFromProxy = match[1];
          request.allowedOrigin = `https://${forwardedHost}`;
        }
      } else if (forwardedHost) {
        // Custom domain - look up subdomain in DB
        const app = await env.DB.prepare(
          'SELECT subdomain FROM apps WHERE custom_domain = ?'
        ).bind(forwardedHost).first();
        if (app) {
          request.subdomainFromProxy = app.subdomain;
          request.allowedOrigin = `https://${forwardedHost}`;
        }
      }
      return;
    }
  } catch (e) {
    console.error('handleCors error (forwardedHost):', e.message);
  }

  const origin = request.headers.get('origin');
  if (!origin) return;

  // Check if origin is allowed
  let allowed = false;
  let subdomain = null;

  // Allow itsalive.co and *.itsalive.co
  if (origin === 'https://itsalive.co' || origin === 'https://www.itsalive.co') {
    allowed = true;
  }
  else if (origin.endsWith('.itsalive.co')) {
    allowed = true;
    const match = origin.match(/^https?:\/\/([^.]+)\.itsalive\.co/);
    subdomain = match ? match[1] : null;
  }
  // Allow localhost for dev
  else if (origin === 'http://localhost:3000') {
    allowed = true;
  }
  // Check custom domains
  else {
    try {
      const hostname = new URL(origin).hostname;
      const app = await env.DB.prepare(
        'SELECT subdomain FROM apps WHERE custom_domain = ?'
      ).bind(hostname).first();
      if (app) {
        allowed = true;
        subdomain = app.subdomain;
        // Store custom domain info for later use
        request.customDomain = hostname;
        request.subdomainFromCustomDomain = subdomain;
      }
    } catch (e) {
      // Invalid URL, not allowed
    }
  }

  if (allowed) {
    request.allowedOrigin = origin;
  }
}

function corsify(response, request) {
  if (!request.allowedOrigin) return response;

  const headers = new Headers(response.headers);
  headers.set('Access-Control-Allow-Origin', request.allowedOrigin);
  headers.set('Access-Control-Allow-Credentials', 'true');

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function preflight(request) {
  if (request.method === 'OPTIONS') {
    return new Response(null, {
      headers: {
        'Access-Control-Allow-Origin': request.headers.get('origin') || '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Credentials': 'true',
        'Access-Control-Max-Age': '86400',
      },
    });
  }
}

const router = AutoRouter({
  before: [handleCors, preflight],
  finally: [corsify],
  catch: (err, request) => {
    console.error('Router error:', err.message, err.stack);
    console.error('Request URL:', request.url);
    return new Response(JSON.stringify({
      error: err.message,
      type: err.name,
      url: request.url,
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  },
});

// Helper to generate random IDs
function generateId() {
  return crypto.randomUUID();
}

// Helper to generate tokens
function generateToken() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

// Cloudflare Zone API helpers for custom domains
async function createZoneForDomain(env, domain) {
  if (!env.CLOUDFLARE_API_TOKEN || !env.CLOUDFLARE_ACCOUNT_ID) {
    return { success: false, error: 'Cloudflare credentials not configured' };
  }

  // Create zone for the domain
  const response = await fetch(
    'https://api.cloudflare.com/client/v4/zones',
    {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.CLOUDFLARE_API_TOKEN}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        name: domain,
        account: { id: env.CLOUDFLARE_ACCOUNT_ID },
        type: 'full',
      }),
    }
  );

  const result = await response.json();
  if (!result.success) {
    const error = result.errors?.[0]?.message || 'Failed to add domain';
    // Check if zone already exists
    if (error.includes('already exists')) {
      return { success: false, error: 'This domain is already configured in Cloudflare' };
    }
    return { success: false, error };
  }

  return {
    success: true,
    zone_id: result.result.id,
    nameservers: result.result.name_servers,
    status: result.result.status,
  };
}

async function getZoneStatus(env, zoneId) {
  if (!env.CLOUDFLARE_API_TOKEN) {
    return { success: false, error: 'Cloudflare credentials not configured' };
  }

  const response = await fetch(
    `https://api.cloudflare.com/client/v4/zones/${zoneId}`,
    {
      headers: {
        'Authorization': `Bearer ${env.CLOUDFLARE_API_TOKEN}`,
      },
    }
  );

  const result = await response.json();
  if (!result.success) {
    return { success: false, error: 'Failed to check zone status' };
  }

  return {
    success: true,
    status: result.result.status,
    nameservers: result.result.name_servers,
  };
}

async function setupZoneDNSAndRoutes(env, zoneId, domain, targetSubdomain) {
  if (!env.CLOUDFLARE_API_TOKEN) {
    return { success: false, error: 'Cloudflare credentials not configured' };
  }

  // Add DNS record pointing to our worker (using proxy)
  // We'll use a CNAME to our main domain which has the worker route
  const dnsResponse = await fetch(
    `https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records`,
    {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.CLOUDFLARE_API_TOKEN}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        type: 'CNAME',
        name: '@',
        content: 'itsalive.co',
        proxied: true,
      }),
    }
  );

  // Add www CNAME too
  await fetch(
    `https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records`,
    {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.CLOUDFLARE_API_TOKEN}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        type: 'CNAME',
        name: 'www',
        content: 'itsalive.co',
        proxied: true,
      }),
    }
  );

  // Add Worker route for this domain
  const routeResponse = await fetch(
    `https://api.cloudflare.com/client/v4/zones/${zoneId}/workers/routes`,
    {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.CLOUDFLARE_API_TOKEN}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        pattern: `${domain}/*`,
        script: 'itsalive-serve',
      }),
    }
  );

  // Also add www route
  await fetch(
    `https://api.cloudflare.com/client/v4/zones/${zoneId}/workers/routes`,
    {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.CLOUDFLARE_API_TOKEN}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        pattern: `www.${domain}/*`,
        script: 'itsalive-serve',
      }),
    }
  );

  const routeResult = await routeResponse.json();
  if (!routeResult.success) {
    console.error('Failed to add worker route:', routeResult.errors);
    return { success: false, error: 'Failed to configure domain routing' };
  }

  return { success: true };
}

async function deleteZone(env, zoneId) {
  if (!env.CLOUDFLARE_API_TOKEN) {
    return { success: false, error: 'Cloudflare credentials not configured' };
  }

  const response = await fetch(
    `https://api.cloudflare.com/client/v4/zones/${zoneId}`,
    {
      method: 'DELETE',
      headers: {
        'Authorization': `Bearer ${env.CLOUDFLARE_API_TOKEN}`,
      },
    }
  );

  const result = await response.json();
  return { success: result.success };
}

// Helper to generate styled error page
function errorPage({ title, message, icon = '&#10060;' }) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title} - itsalive.co</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: system-ui, -apple-system, sans-serif;
      background: #0a0a0b;
      color: #fff;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      justify-content: center;
      align-items: center;
      padding: 2rem;
    }
    .card {
      background: rgba(255,255,255,0.02);
      border: 1px solid rgba(255,255,255,0.08);
      border-radius: 16px;
      padding: 3rem;
      text-align: center;
      max-width: 440px;
    }
    .icon {
      font-size: 4rem;
      margin-bottom: 1.5rem;
    }
    h1 {
      font-size: 1.75rem;
      font-weight: 700;
      margin-bottom: 0.75rem;
      color: #ff4d4d;
    }
    p {
      color: #888;
      line-height: 1.6;
    }
    .footer {
      margin-top: 2rem;
      font-size: 0.85rem;
    }
    .footer a {
      color: #444;
      text-decoration: none;
    }
    .footer a:hover {
      color: #00d4ff;
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">${icon}</div>
    <h1>${title}</h1>
    <p>${message}</p>
  </div>
  <p class="footer"><a href="https://itsalive.co">itsalive.co</a></p>
</body>
</html>`;
}

// Helper to get app branding settings
async function getAppBranding(env, subdomain) {
  const settings = await env.DB.prepare(
    'SELECT email_app_name, email_primary_color, email_button_color, email_tagline, branding_configured FROM app_settings WHERE app_subdomain = ?'
  ).bind(subdomain).first();

  return {
    appName: settings?.email_app_name || subdomain,
    primaryColor: settings?.email_primary_color || '#00d4ff',
    buttonColor: settings?.email_button_color || '#ffffff',
    tagline: settings?.email_tagline || null,
    configured: settings?.branding_configured === 1,
  };
}

// Helper to generate styled email HTML
function emailTemplate({ buttonText, buttonUrl, footer, branding = {} }) {
  const {
    appName = "It's Alive!",
    primaryColor = '#00d4ff',
    buttonColor = '#ffffff',
    tagline = null,
  } = branding;

  // Determine button text color based on button background brightness
  const buttonTextColor = buttonColor.toLowerCase() === '#ffffff' || buttonColor.toLowerCase() === '#fff' ? '#000000' : '#ffffff';

  return `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin: 0; padding: 0; background-color: #0a0a0b; font-family: system-ui, -apple-system, sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #0a0a0b; padding: 40px 20px;">
    <tr>
      <td align="center">
        <table width="100%" cellpadding="0" cellspacing="0" style="max-width: 480px; background: linear-gradient(135deg, rgba(255,255,255,0.03) 0%, rgba(255,255,255,0.01) 100%); border: 1px solid rgba(255,255,255,0.08); border-radius: 16px; padding: 40px;">
          <tr>
            <td align="center" style="padding-bottom: ${tagline ? '8px' : '32px'};">
              <span style="font-size: 32px; font-weight: 800; color: ${primaryColor};">${appName}</span>
            </td>
          </tr>
          ${tagline ? `<tr>
            <td align="center" style="padding-bottom: 32px;">
              <p style="margin: 0; font-size: 14px; color: #666666;">${tagline}</p>
            </td>
          </tr>` : ''}
          <tr>
            <td align="center" style="padding-bottom: 24px;">
              <a href="${buttonUrl}" style="display: inline-block; padding: 14px 32px; background: ${buttonColor}; color: ${buttonTextColor}; text-decoration: none; font-weight: 600; font-size: 16px; border-radius: 8px;">${buttonText}</a>
            </td>
          </tr>
          <tr>
            <td align="center">
              <p style="margin: 0; font-size: 13px; color: #555555;">${footer}</p>
            </td>
          </tr>
        </table>
        <p style="margin-top: 24px; font-size: 12px; color: #444444;">
          <a href="https://itsalive.co" style="color: #444444; text-decoration: none;">Powered by itsalive.co</a>
        </p>
      </td>
    </tr>
  </table>
</body>
</html>`;
}

// Helper to send email via Resend
async function sendEmail(env, to, subject, html, options = {}) {
  // Support both old signature (fromName as string) and new signature (options object)
  if (typeof options === 'string') {
    options = { fromName: options };
  }

  const { fromName = "It's Alive!", replyTo, fromDomain } = options;

  try {
    // Determine from address based on verified domain or default
    const from = fromDomain
      ? `${fromName} <noreply@${fromDomain}>`
      : `${fromName} <noreply@itsalive.co>`;

    const body = {
      from,
      to,
      subject,
      html,
    };

    if (replyTo) {
      body.reply_to = replyTo;
    }

    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.RESEND_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const error = await res.text();
      console.error('Resend API error:', res.status, error);
    }
    return res.ok;
  } catch (e) {
    console.error('sendEmail error:', e.message);
    return false;
  }
}

// Spam prevention: heuristic scoring
function heuristicSpamScore(subject, html) {
  let score = 0;

  // Check link count
  const linkCount = (html.match(/href=/gi) || []).length;
  if (linkCount > 10) score += 30;

  // Check for spam phrases
  const spamPhrases = ['act now', 'limited time', 'click here', 'winner', 'congratulations', 'free money', 'urgent', 'guaranteed', 'no obligation'];
  const lowerHtml = html.toLowerCase();
  const lowerSubject = subject.toLowerCase();
  for (const phrase of spamPhrases) {
    if (lowerHtml.includes(phrase) || lowerSubject.includes(phrase)) score += 15;
  }

  // All caps subject
  if (subject === subject.toUpperCase() && subject.length > 10) score += 20;

  // Minimal content
  const textContent = html.replace(/<[^>]*>/g, '').trim();
  if (textContent.length < 50) score += 25;

  // Excessive exclamation marks
  const exclamationCount = (subject.match(/!/g) || []).length;
  if (exclamationCount > 2) score += 15;

  return Math.min(score, 100);
}

// AI spam check for borderline cases
async function aiSpamCheck(env, subject, html) {
  if (!env.ANTHROPIC_API_KEY) {
    return { isSpam: false, reason: 'AI check unavailable' };
  }

  try {
    const textContent = html.replace(/<[^>]*>/g, '').substring(0, 1000);
    const res = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'x-api-key': env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: 'claude-3-haiku-20240307',
        max_tokens: 100,
        messages: [{
          role: 'user',
          content: `Is this email spam or legitimate marketing/transactional email? Reply with SPAM or OK followed by a brief reason.

Subject: ${subject}
Content: ${textContent}`
        }]
      })
    });

    if (!res.ok) {
      return { isSpam: false, reason: 'AI check failed' };
    }

    const data = await res.json();
    const response = data.content[0].text.toUpperCase();
    const isSpam = response.startsWith('SPAM');
    return { isSpam, reason: data.content[0].text };
  } catch (e) {
    console.error('AI spam check error:', e.message);
    return { isSpam: false, reason: 'AI check error' };
  }
}

// Combined spam check
async function checkSpam(env, subject, html, subdomain) {
  // Layer 1: Heuristics
  const score = heuristicSpamScore(subject, html);

  if (score > 80) {
    return { blocked: true, reason: 'Content flagged as spam', score };
  }

  if (score < 30) {
    return { blocked: false, score };
  }

  // Layer 2: AI check for borderline cases (30-80)
  const aiResult = await aiSpamCheck(env, subject, html);

  if (aiResult.isSpam) {
    return { blocked: true, reason: aiResult.reason, score, aiChecked: true };
  }

  return { blocked: false, score, aiChecked: true };
}

// Email rate limiting per app
async function checkEmailRateLimit(env, subdomain) {
  const key = `email_rate:${subdomain}`;
  const current = await env.RATE_LIMITS.get(key);
  const count = current ? parseInt(current) : 0;

  if (count >= 100) {  // 100 emails/hour
    return { allowed: false, remaining: 0 };
  }

  await env.RATE_LIMITS.put(key, String(count + 1), { expirationTtl: 3600 });
  return { allowed: true, remaining: 100 - count - 1 };
}

// Add unsubscribe footer to emails
function addUnsubscribeFooter(html, unsubscribeUrl) {
  const footer = `
    <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #e0e0e0; text-align: center; font-size: 12px; color: #666;">
      <p>You received this email because you're subscribed to updates.</p>
      <p><a href="${unsubscribeUrl}" style="color: #666; text-decoration: underline;">Unsubscribe</a></p>
    </div>
  `;

  // Insert before closing body tag if present, otherwise append
  if (html.includes('</body>')) {
    return html.replace('</body>', footer + '</body>');
  }
  return html + footer;
}

// Helper to get subdomain from request origin
function getSubdomain(request) {
  // Check if request came from a custom domain (set by handleCors)
  if (request.subdomainFromCustomDomain) {
    return request.subdomainFromCustomDomain;
  }
  // Check if request was proxied from a custom domain (X-Forwarded-Host set by serve worker)
  if (request.subdomainFromProxy) {
    return request.subdomainFromProxy;
  }
  // Otherwise extract from *.itsalive.co origin
  const origin = request.headers.get('origin') || '';
  const match = origin.match(/^https?:\/\/([^.]+)\.itsalive\.co/);
  return match ? match[1] : null;
}

// Helper to get session from cookie
async function getSession(request, env) {
  // Check for session token from header (custom domain proxy) or cookie
  let token = request.headers.get('X-Session-Token');

  if (!token) {
    const cookie = request.headers.get('cookie') || '';
    const match = cookie.match(/itsalive_session=([^;]+)/);
    if (!match) return null;
    token = match[1];
  }

  const subdomain = getSubdomain(request);
  if (!subdomain) return null;

  const session = await env.DB.prepare(
    'SELECT * FROM sessions WHERE token = ? AND app_subdomain = ? AND expires_at > datetime("now")'
  ).bind(token, subdomain).first();

  if (!session) return null;

  const user = await env.DB.prepare(
    'SELECT id, email FROM app_users WHERE id = ?'
  ).bind(session.user_id).first();

  // Track user activity for DAU/WAU/MAU (fire-and-forget)
  if (user) {
    trackUserActivity(env, subdomain, user.id).catch(() => {});
  }

  return user;
}

// Track user activity for DAU/WAU/MAU metrics
async function trackUserActivity(env, subdomain, userId) {
  const today = new Date().toISOString().slice(0, 10);
  await env.DB.prepare(
    'INSERT OR IGNORE INTO user_activity (app_subdomain, user_id, date) VALUES (?, ?, ?)'
  ).bind(subdomain, userId, today).run();
}

// Helper to query Analytics Engine via SQL API
async function queryAnalytics(env, sql) {
  if (!env.CLOUDFLARE_API_TOKEN || !env.CLOUDFLARE_ACCOUNT_ID) {
    return { data: [] }; // Silently return empty if not configured
  }

  const response = await fetch(
    `https://api.cloudflare.com/client/v4/accounts/${env.CLOUDFLARE_ACCOUNT_ID}/analytics_engine/sql`,
    {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.CLOUDFLARE_API_TOKEN}`,
        'Content-Type': 'text/plain',
      },
      body: sql,
    }
  );

  if (!response.ok) {
    const text = await response.text();
    console.error('Analytics API error:', response.status, text);
    return { data: [] };
  }

  return response.json();
}

// ============ OWNER DASHBOARD ENDPOINTS ============

// Helper to get owner session from cookie
async function getOwnerSession(request, env) {
  const cookie = request.headers.get('cookie') || '';
  const match = cookie.match(/itsalive_owner=([^;]+)/);
  if (!match) return null;

  const token = match[1];
  const data = await env.EMAIL_TOKENS.get(`owner_session:${token}`);
  if (!data) return null;

  const parsed = JSON.parse(data);

  // Ensure owner_id exists (handle old session format)
  if (!parsed.owner_id && parsed.id) {
    parsed.owner_id = parsed.id;
  }

  if (!parsed.owner_id || !parsed.email) {
    console.error('Invalid session data - missing owner_id or email:', JSON.stringify(parsed));
    return null;
  }

  return parsed;
}

// POST /owner/login - Send magic link for dashboard access
router.post('/owner/login', async (request, env) => {
  const { email } = await request.json();

  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return new Response(JSON.stringify({ error: 'Invalid email' }), { status: 400 });
  }

  // Check if this email owns any apps
  const owner = await env.DB.prepare(
    'SELECT id, email FROM owners WHERE email = ?'
  ).bind(email).first();

  if (!owner) {
    // No apps yet - that's ok, they might be about to deploy
    // Still send the link so they can access dashboard after deploying
  }

  const token = generateToken();
  await env.EMAIL_TOKENS.put(`owner_login:${token}`, JSON.stringify({
    email,
    owner_id: owner?.id || null,
  }), {
    expirationTtl: 600, // 10 minutes
  });

  const verifyUrl = `https://api.itsalive.co/owner/verify?token=${token}`;
  await sendEmail(
    env,
    email,
    'Login to itsalive.co Dashboard',
    emailTemplate({
      buttonText: 'Access Dashboard',
      buttonUrl: verifyUrl,
      footer: 'This link expires in 10 minutes.',
      branding: {
        appName: "It's Alive!",
        primaryColor: '#00d4ff',
        tagline: 'Manage your deployed apps',
      },
    }),
    "It's Alive!"
  );

  return { success: true };
});

// GET /owner/verify - Verify magic link and set owner cookie
router.get('/owner/verify', async (request, env) => {
  const url = new URL(request.url);
  const token = url.searchParams.get('token');

  if (!token) {
    return new Response('Missing token', { status: 400 });
  }

  const data = await env.EMAIL_TOKENS.get(`owner_login:${token}`);
  if (!data) {
    return new Response('Invalid or expired token', { status: 400 });
  }

  const { email } = JSON.parse(data);
  await env.EMAIL_TOKENS.delete(`owner_login:${token}`);

  // Get or create owner record
  let owner = await env.DB.prepare(
    'SELECT id FROM owners WHERE email = ?'
  ).bind(email).first();

  if (!owner) {
    const ownerId = generateToken();
    await env.DB.prepare(
      'INSERT INTO owners (id, email) VALUES (?, ?)'
    ).bind(ownerId, email).run();
    owner = { id: ownerId };

    // Give new owners 2500 free credits
    const FREE_CREDITS = 2500;
    await env.DB.prepare(`
      INSERT INTO owner_credits (owner_id, balance, lifetime_purchased)
      VALUES (?, ?, ?)
    `).bind(ownerId, FREE_CREDITS, FREE_CREDITS).run();
  }

  // Create session token
  const sessionToken = generateToken();
  await env.EMAIL_TOKENS.put(`owner_session:${sessionToken}`, JSON.stringify({
    owner_id: owner.id,
    email,
  }), {
    expirationTtl: 30 * 24 * 60 * 60, // 30 days
  });

  // Redirect to dashboard with cookie
  return new Response(null, {
    status: 302,
    headers: {
      'Location': 'https://itsalive.co/dashboard',
      'Set-Cookie': `itsalive_owner=${sessionToken}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${30 * 24 * 60 * 60}; Domain=.itsalive.co`,
    },
  });
});

// GET /owner/me - Check if owner is logged in
router.get('/owner/me', async (request, env) => {
  try {
    const owner = await getOwnerSession(request, env);
    if (!owner) {
      return new Response(JSON.stringify({ error: 'Not logged in' }), { status: 401 });
    }
    return new Response(JSON.stringify({ email: owner.email, owner_id: owner.owner_id }));
  } catch (e) {
    return new Response(JSON.stringify({ error: '/owner/me error: ' + e.message }), { status: 500 });
  }
});

// POST /owner/logout - Clear owner session
router.post('/owner/logout', async (request, env) => {
  const cookie = request.headers.get('cookie') || '';
  const match = cookie.match(/itsalive_owner=([^;]+)/);
  if (match) {
    await env.EMAIL_TOKENS.delete(`owner_session:${match[1]}`);
  }

  return new Response(JSON.stringify({ success: true }), {
    headers: {
      'Set-Cookie': 'itsalive_owner=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Domain=.itsalive.co',
    },
  });
});

// GET /owner/apps - List all apps owned by the logged-in owner
router.get('/owner/apps', async (request, env) => {
  const owner = await getOwnerSession(request, env);
  if (!owner || !owner.owner_id) {
    return new Response(JSON.stringify({ error: 'Not logged in' }), { status: 401 });
  }

  const apps = await env.DB.prepare(`
    SELECT a.subdomain, a.custom_domain, a.created_at,
           s.email_app_name, s.branding_configured
    FROM apps a
    LEFT JOIN app_settings s ON a.subdomain = s.app_subdomain
    WHERE a.owner_id = ?
    ORDER BY a.created_at DESC
  `).bind(owner.owner_id).all();

  return new Response(JSON.stringify({ apps: apps.results || [] }));
});

// Public stats endpoint (for landing page counter)
router.get('/stats/public', async (request, env) => {
  // Count sites created in the last 7 days
  const oneWeekAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
  const result = await env.DB.prepare(
    'SELECT COUNT(*) as count FROM apps WHERE created_at >= ?'
  ).bind(oneWeekAgo).first();

  return new Response(JSON.stringify({
    sitesThisWeek: result?.count || 0
  }), {
    headers: {
      'content-type': 'application/json',
      'access-control-allow-origin': '*',
      'cache-control': 'public, max-age=300' // Cache for 5 minutes
    }
  });
});

// ============ RESELLER PROGRAM ============

// Helper to generate reseller code
function generateResellerCode(prefix = '') {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // Removed confusing chars
  let code = prefix ? prefix.toUpperCase() + '-' : '';
  for (let i = 0; i < 6; i++) {
    code += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return code;
}

// POST /reseller/apply - Apply to become a reseller
router.post('/reseller/apply', async (request, env) => {
  const owner = await getOwnerSession(request, env);
  if (!owner) {
    return new Response(JSON.stringify({ error: 'Not logged in' }), { status: 401 });
  }

  const body = await request.json();
  const { company_name, payout_email } = body;

  if (!payout_email) {
    return new Response(JSON.stringify({ error: 'Payout email required' }), { status: 400 });
  }

  // Check if already a reseller
  const existing = await env.DB.prepare(
    'SELECT id FROM resellers WHERE owner_id = ?'
  ).bind(owner.owner_id).first();

  if (existing) {
    return new Response(JSON.stringify({ error: 'Already a reseller' }), { status: 400 });
  }

  const resellerId = crypto.randomUUID();
  await env.DB.prepare(`
    INSERT INTO resellers (id, owner_id, company_name, payout_email, status)
    VALUES (?, ?, ?, ?, 'active')
  `).bind(resellerId, owner.owner_id, company_name || null, payout_email).run();

  return new Response(JSON.stringify({
    success: true,
    reseller_id: resellerId,
    message: 'Welcome to the reseller program!'
  }));
});

// GET /reseller/me - Get reseller profile and stats
router.get('/reseller/me', async (request, env) => {
  const owner = await getOwnerSession(request, env);
  if (!owner) {
    return new Response(JSON.stringify({ error: 'Not logged in' }), { status: 401 });
  }

  const reseller = await env.DB.prepare(`
    SELECT r.*,
           (SELECT COUNT(*) FROM reseller_codes WHERE reseller_id = r.id) as codes_count,
           (SELECT COUNT(*) FROM reseller_referrals WHERE reseller_id = r.id) as referrals_count
    FROM resellers r
    WHERE r.owner_id = ?
  `).bind(owner.owner_id).first();

  if (!reseller) {
    return new Response(JSON.stringify({ error: 'Not a reseller', is_reseller: false }), { status: 404 });
  }

  return new Response(JSON.stringify({
    is_reseller: true,
    reseller: {
      id: reseller.id,
      company_name: reseller.company_name,
      payout_email: reseller.payout_email,
      status: reseller.status,
      total_earned: reseller.total_earned,
      total_paid: reseller.total_paid,
      pending_payout: reseller.pending_payout,
      codes_count: reseller.codes_count,
      referrals_count: reseller.referrals_count,
      created_at: reseller.created_at
    }
  }));
});

// POST /reseller/codes - Generate a new coupon code
router.post('/reseller/codes', async (request, env) => {
  const owner = await getOwnerSession(request, env);
  if (!owner) {
    return new Response(JSON.stringify({ error: 'Not logged in' }), { status: 401 });
  }

  const reseller = await env.DB.prepare(
    'SELECT id, status FROM resellers WHERE owner_id = ?'
  ).bind(owner.owner_id).first();

  if (!reseller) {
    return new Response(JSON.stringify({ error: 'Not a reseller' }), { status: 403 });
  }

  if (reseller.status !== 'active') {
    return new Response(JSON.stringify({ error: 'Reseller account is not active' }), { status: 403 });
  }

  const body = await request.json();
  const { discount_type, prefix } = body;

  // Validate discount type
  const validTypes = ['free_1month', 'half_3months', 'discount_year'];
  if (!validTypes.includes(discount_type)) {
    return new Response(JSON.stringify({
      error: 'Invalid discount type. Must be: free_1month, half_3months, or discount_year'
    }), { status: 400 });
  }

  // Generate unique code
  let code;
  let attempts = 0;
  while (attempts < 10) {
    code = generateResellerCode(prefix);
    const exists = await env.DB.prepare(
      'SELECT code FROM reseller_codes WHERE code = ?'
    ).bind(code).first();
    if (!exists) break;
    attempts++;
  }

  if (attempts >= 10) {
    return new Response(JSON.stringify({ error: 'Failed to generate unique code' }), { status: 500 });
  }

  await env.DB.prepare(`
    INSERT INTO reseller_codes (code, reseller_id, discount_type)
    VALUES (?, ?, ?)
  `).bind(code, reseller.id, discount_type).run();

  // Human-readable discount descriptions
  const discountDescriptions = {
    'free_1month': 'Free for the first month',
    'half_3months': '50% off for the first 3 months',
    'discount_year': '20% off for the first year'
  };

  return new Response(JSON.stringify({
    success: true,
    code: code,
    discount_type: discount_type,
    description: discountDescriptions[discount_type]
  }));
});

// GET /reseller/codes - List reseller's codes
router.get('/reseller/codes', async (request, env) => {
  const owner = await getOwnerSession(request, env);
  if (!owner) {
    return new Response(JSON.stringify({ error: 'Not logged in' }), { status: 401 });
  }

  const reseller = await env.DB.prepare(
    'SELECT id FROM resellers WHERE owner_id = ?'
  ).bind(owner.owner_id).first();

  if (!reseller) {
    return new Response(JSON.stringify({ error: 'Not a reseller' }), { status: 403 });
  }

  const codes = await env.DB.prepare(`
    SELECT code, discount_type, uses_count, status, created_at
    FROM reseller_codes
    WHERE reseller_id = ?
    ORDER BY created_at DESC
  `).bind(reseller.id).all();

  return new Response(JSON.stringify({ codes: codes.results || [] }));
});

// DELETE /reseller/codes/:code - Disable a code
router.delete('/reseller/codes/:code', async (request, env) => {
  const owner = await getOwnerSession(request, env);
  if (!owner) {
    return new Response(JSON.stringify({ error: 'Not logged in' }), { status: 401 });
  }

  const reseller = await env.DB.prepare(
    'SELECT id FROM resellers WHERE owner_id = ?'
  ).bind(owner.owner_id).first();

  if (!reseller) {
    return new Response(JSON.stringify({ error: 'Not a reseller' }), { status: 403 });
  }

  const code = request.params.code;
  const result = await env.DB.prepare(`
    UPDATE reseller_codes SET status = 'disabled'
    WHERE code = ? AND reseller_id = ?
  `).bind(code, reseller.id).run();

  if (result.meta.changes === 0) {
    return new Response(JSON.stringify({ error: 'Code not found' }), { status: 404 });
  }

  return new Response(JSON.stringify({ success: true }));
});

// GET /reseller/referrals - List referrals and commissions
router.get('/reseller/referrals', async (request, env) => {
  const owner = await getOwnerSession(request, env);
  if (!owner) {
    return new Response(JSON.stringify({ error: 'Not logged in' }), { status: 401 });
  }

  const reseller = await env.DB.prepare(
    'SELECT id FROM resellers WHERE owner_id = ?'
  ).bind(owner.owner_id).first();

  if (!reseller) {
    return new Response(JSON.stringify({ error: 'Not a reseller' }), { status: 403 });
  }

  const referrals = await env.DB.prepare(`
    SELECT rr.id, rr.reseller_code, rr.app_subdomain, rr.discount_type,
           rr.tracking_ends_at, rr.total_paid, rr.commission_earned, rr.created_at,
           o.email as customer_email
    FROM reseller_referrals rr
    JOIN owners o ON rr.owner_id = o.id
    WHERE rr.reseller_id = ?
    ORDER BY rr.created_at DESC
  `).bind(reseller.id).all();

  return new Response(JSON.stringify({ referrals: referrals.results || [] }));
});

// GET /reseller/payouts - List payout history
router.get('/reseller/payouts', async (request, env) => {
  const owner = await getOwnerSession(request, env);
  if (!owner) {
    return new Response(JSON.stringify({ error: 'Not logged in' }), { status: 401 });
  }

  const reseller = await env.DB.prepare(
    'SELECT id FROM resellers WHERE owner_id = ?'
  ).bind(owner.owner_id).first();

  if (!reseller) {
    return new Response(JSON.stringify({ error: 'Not a reseller' }), { status: 403 });
  }

  const payouts = await env.DB.prepare(`
    SELECT id, amount, method, status, notes, paid_at, created_at
    FROM reseller_payouts
    WHERE reseller_id = ?
    ORDER BY created_at DESC
  `).bind(reseller.id).all();

  return new Response(JSON.stringify({ payouts: payouts.results || [] }));
});

// GET /reseller/validate/:code - Validate a reseller code (public, for checkout)
router.get('/reseller/validate/:code', async (request, env) => {
  const code = request.params.code.toUpperCase();

  const resellerCode = await env.DB.prepare(`
    SELECT rc.code, rc.discount_type, rc.status, r.status as reseller_status
    FROM reseller_codes rc
    JOIN resellers r ON rc.reseller_id = r.id
    WHERE rc.code = ?
  `).bind(code).first();

  if (!resellerCode) {
    return new Response(JSON.stringify({ valid: false, error: 'Code not found' }), { status: 404 });
  }

  if (resellerCode.status !== 'active' || resellerCode.reseller_status !== 'active') {
    return new Response(JSON.stringify({ valid: false, error: 'Code is not active' }), { status: 400 });
  }

  const discountDescriptions = {
    'free_1month': 'Free for the first month',
    'half_3months': '50% off for the first 3 months',
    'discount_year': '20% off for the first year'
  };

  return new Response(JSON.stringify({
    valid: true,
    code: resellerCode.code,
    discount_type: resellerCode.discount_type,
    description: discountDescriptions[resellerCode.discount_type]
  }));
});

// Admin emails that can access /admin endpoints
const ADMIN_EMAILS = ['s@swh.me', 'sam@itsalive.co', 'melih@itsalive.co'];

// GET /admin/sites - List ALL sites on the platform (admin only)
router.get('/admin/sites', async (request, env) => {
  const owner = await getOwnerSession(request, env);
  if (!owner) {
    return new Response(JSON.stringify({ error: 'Not logged in' }), { status: 401 });
  }

  if (!ADMIN_EMAILS.includes(owner.email)) {
    return new Response(JSON.stringify({ error: 'Not authorized' }), { status: 403 });
  }

  const url = new URL(request.url);
  const limit = Math.min(parseInt(url.searchParams.get('limit') || '100'), 500);
  const offset = parseInt(url.searchParams.get('offset') || '0');

  // Get all apps with owner info and stats
  const apps = await env.DB.prepare(`
    SELECT
      a.subdomain,
      a.custom_domain,
      a.created_at,
      o.email as owner_email,
      s.email_app_name,
      sub.plan,
      sub.status as subscription_status,
      (SELECT COUNT(*) FROM app_users WHERE app_subdomain = a.subdomain) as user_count,
      (SELECT COUNT(*) FROM app_data WHERE app_subdomain = a.subdomain) as data_count
    FROM apps a
    LEFT JOIN owners o ON a.owner_id = o.id
    LEFT JOIN app_settings s ON a.subdomain = s.app_subdomain
    LEFT JOIN subscriptions sub ON a.subdomain = sub.app_subdomain AND sub.status = 'active'
    ORDER BY a.created_at DESC
    LIMIT ? OFFSET ?
  `).bind(limit, offset).all();

  // Get total count
  const countResult = await env.DB.prepare('SELECT COUNT(*) as total FROM apps').first();

  // Get some aggregate stats
  const stats = await env.DB.prepare(`
    SELECT
      COUNT(DISTINCT a.subdomain) as total_sites,
      COUNT(DISTINCT o.id) as total_owners,
      COUNT(DISTINCT CASE WHEN sub.status = 'active' THEN a.subdomain END) as pro_sites,
      COUNT(DISTINCT a.custom_domain) as custom_domains
    FROM apps a
    LEFT JOIN owners o ON a.owner_id = o.id
    LEFT JOIN subscriptions sub ON a.subdomain = sub.app_subdomain
  `).first();

  return {
    sites: apps.results || [],
    total: countResult?.total || 0,
    limit,
    offset,
    stats,
  };
});

// GET /admin/stats - Platform-wide statistics (admin only)
router.get('/admin/stats', async (request, env) => {
  const owner = await getOwnerSession(request, env);
  if (!owner) {
    return new Response(JSON.stringify({ error: 'Not logged in' }), { status: 401 });
  }

  if (!ADMIN_EMAILS.includes(owner.email)) {
    return new Response(JSON.stringify({ error: 'Not authorized' }), { status: 403 });
  }

  const [sites, owners, subscriptions, recentSites, coupons] = await Promise.all([
    env.DB.prepare('SELECT COUNT(*) as count FROM apps').first(),
    env.DB.prepare('SELECT COUNT(*) as count FROM owners').first(),
    env.DB.prepare('SELECT COUNT(*) as count, plan FROM subscriptions WHERE status = ? GROUP BY plan').bind('active').all(),
    env.DB.prepare(`
      SELECT a.subdomain, a.created_at, o.email
      FROM apps a
      LEFT JOIN owners o ON a.owner_id = o.id
      ORDER BY a.created_at DESC
      LIMIT 10
    `).all(),
    env.DB.prepare('SELECT code, uses_remaining, max_uses FROM coupons').all(),
  ]);

  return {
    total_sites: sites?.count || 0,
    total_owners: owners?.count || 0,
    subscriptions: subscriptions.results || [],
    recent_sites: recentSites.results || [],
    coupons: coupons.results || [],
  };
});

// GET /owner/app/:subdomain - Get details for a specific app
router.get('/owner/app/:subdomain', async (request, env) => {
  const owner = await getOwnerSession(request, env);
  if (!owner) {
    return new Response(JSON.stringify({ error: 'Not logged in' }), { status: 401 });
  }

  const { subdomain } = request.params;

  const app = await env.DB.prepare(`
    SELECT a.subdomain, a.custom_domain, a.cf_zone_id, a.domain_status, a.created_at, a.owner_id
    FROM apps a
    WHERE a.subdomain = ?
  `).bind(subdomain).first();

  if (!app) {
    return new Response(JSON.stringify({ error: 'App not found' }), { status: 404 });
  }

  if (app.owner_id !== owner.owner_id) {
    return new Response(JSON.stringify({ error: 'Not your app' }), { status: 403 });
  }

  const branding = await getAppBranding(env, subdomain);

  // Get nameservers if domain is pending
  let nameservers = null;
  if (app.cf_zone_id && app.domain_status === 'pending_ns') {
    const zoneStatus = await getZoneStatus(env, app.cf_zone_id);
    if (zoneStatus.success) {
      nameservers = zoneStatus.nameservers;
    }
  }

  return new Response(JSON.stringify({
    subdomain: app.subdomain,
    custom_domain: app.custom_domain,
    domain_status: app.domain_status || 'none',
    nameservers,
    created_at: app.created_at,
    branding,
  }));
});

// PUT /owner/app/:subdomain - Update app settings from dashboard
router.put('/owner/app/:subdomain', async (request, env) => {
  const owner = await getOwnerSession(request, env);
  if (!owner) {
    return new Response(JSON.stringify({ error: 'Not logged in' }), { status: 401 });
  }

  const { subdomain } = request.params;

  const app = await env.DB.prepare(
    'SELECT owner_id, custom_domain FROM apps WHERE subdomain = ?'
  ).bind(subdomain).first();

  if (!app) {
    return new Response(JSON.stringify({ error: 'App not found' }), { status: 404 });
  }

  if (app.owner_id !== owner.owner_id) {
    return new Response(JSON.stringify({ error: 'Not your app' }), { status: 403 });
  }

  const body = await request.json();
  const { app_name, primary_color, button_color, tagline } = body;

  // Note: Custom domain is now managed via /setup-domain endpoint

  // Update branding if any branding fields provided
  if (app_name !== undefined || primary_color !== undefined || button_color !== undefined || tagline !== undefined) {
    const hexColorRegex = /^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$/;
    if (primary_color && !hexColorRegex.test(primary_color)) {
      return new Response(JSON.stringify({ error: 'Invalid primary_color format' }), { status: 400 });
    }
    if (button_color && !hexColorRegex.test(button_color)) {
      return new Response(JSON.stringify({ error: 'Invalid button_color format' }), { status: 400 });
    }

    await env.DB.prepare(`
      INSERT INTO app_settings (app_subdomain, email_app_name, email_primary_color, email_button_color, email_tagline, branding_configured, updated_at)
      VALUES (?, ?, ?, ?, ?, TRUE, datetime("now"))
      ON CONFLICT(app_subdomain) DO UPDATE SET
        email_app_name = COALESCE(excluded.email_app_name, email_app_name),
        email_primary_color = COALESCE(excluded.email_primary_color, email_primary_color),
        email_button_color = COALESCE(excluded.email_button_color, email_button_color),
        email_tagline = COALESCE(excluded.email_tagline, email_tagline),
        branding_configured = TRUE,
        updated_at = datetime("now")
    `).bind(
      subdomain,
      app_name || null,
      primary_color || null,
      button_color || null,
      tagline || null
    ).run();
  }

  // Return updated app info
  const updatedApp = await env.DB.prepare(
    'SELECT subdomain, custom_domain, created_at FROM apps WHERE subdomain = ?'
  ).bind(subdomain).first();

  const branding = await getAppBranding(env, subdomain);

  return new Response(JSON.stringify({
    success: true,
    subdomain: updatedApp.subdomain,
    custom_domain: updatedApp.custom_domain,
    branding,
  }));
});

// POST /owner/app/:subdomain/setup-domain - Start custom domain setup (creates Cloudflare zone)
router.post('/owner/app/:subdomain/setup-domain', async (request, env) => {
  const owner = await getOwnerSession(request, env);
  if (!owner) {
    return new Response(JSON.stringify({ error: 'Not logged in' }), { status: 401 });
  }

  const { subdomain } = request.params;
  const { domain } = await request.json();

  if (!domain) {
    return new Response(JSON.stringify({ error: 'Domain is required' }), { status: 400 });
  }

  // Validate domain format (must be a root domain, not a subdomain)
  const domainRegex = /^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$/i;
  if (!domainRegex.test(domain)) {
    return new Response(JSON.stringify({ error: 'Invalid domain format' }), { status: 400 });
  }

  // Don't allow itsalive.co subdomains
  if (domain.endsWith('.itsalive.co') || domain === 'itsalive.co') {
    return new Response(JSON.stringify({ error: 'Cannot use itsalive.co domains' }), { status: 400 });
  }

  const app = await env.DB.prepare(
    'SELECT owner_id, custom_domain, cf_zone_id, domain_status FROM apps WHERE subdomain = ?'
  ).bind(subdomain).first();

  if (!app) {
    return new Response(JSON.stringify({ error: 'App not found' }), { status: 404 });
  }

  if (app.owner_id !== owner.owner_id) {
    return new Response(JSON.stringify({ error: 'Not your app' }), { status: 403 });
  }

  // If there's an existing zone for a different domain, delete it
  if (app.cf_zone_id && app.custom_domain !== domain) {
    await deleteZone(env, app.cf_zone_id);
  }

  // Create zone for the domain
  const result = await createZoneForDomain(env, domain);

  if (!result.success) {
    return new Response(JSON.stringify({ error: result.error }), { status: 400 });
  }

  // Save to database
  await env.DB.prepare(
    'UPDATE apps SET custom_domain = ?, cf_zone_id = ?, domain_status = ? WHERE subdomain = ?'
  ).bind(domain, result.zone_id, 'pending_ns', subdomain).run();

  return new Response(JSON.stringify({
    success: true,
    nameservers: result.nameservers,
    status: 'pending_ns',
    message: 'Update your nameservers at your domain registrar to the ones shown above.'
  }));
});

// GET /owner/app/:subdomain/domain-status - Check custom domain setup status
router.get('/owner/app/:subdomain/domain-status', async (request, env) => {
  const owner = await getOwnerSession(request, env);
  if (!owner) {
    return new Response(JSON.stringify({ error: 'Not logged in' }), { status: 401 });
  }

  const { subdomain } = request.params;

  const app = await env.DB.prepare(
    'SELECT owner_id, custom_domain, cf_zone_id, domain_status FROM apps WHERE subdomain = ?'
  ).bind(subdomain).first();

  if (!app) {
    return new Response(JSON.stringify({ error: 'App not found' }), { status: 404 });
  }

  if (app.owner_id !== owner.owner_id) {
    return new Response(JSON.stringify({ error: 'Not your app' }), { status: 403 });
  }

  if (!app.cf_zone_id) {
    return new Response(JSON.stringify({
      status: 'none',
      custom_domain: null
    }));
  }

  // Check zone status with Cloudflare
  const zoneStatus = await getZoneStatus(env, app.cf_zone_id);

  if (!zoneStatus.success) {
    return new Response(JSON.stringify({ error: zoneStatus.error }), { status: 500 });
  }

  // If zone is active and we haven't set up routes yet, do it now
  if (zoneStatus.status === 'active' && app.domain_status !== 'active') {
    const setupResult = await setupZoneDNSAndRoutes(env, app.cf_zone_id, app.custom_domain, subdomain);

    if (setupResult.success) {
      await env.DB.prepare(
        'UPDATE apps SET domain_status = ? WHERE subdomain = ?'
      ).bind('active', subdomain).run();

      return new Response(JSON.stringify({
        status: 'active',
        custom_domain: app.custom_domain,
        message: 'Domain is now active!'
      }));
    } else {
      return new Response(JSON.stringify({
        status: 'pending_ns',
        custom_domain: app.custom_domain,
        nameservers: zoneStatus.nameservers,
        error: setupResult.error
      }));
    }
  }

  return new Response(JSON.stringify({
    status: zoneStatus.status === 'active' ? 'active' : 'pending_ns',
    custom_domain: app.custom_domain,
    nameservers: zoneStatus.nameservers,
    message: zoneStatus.status === 'active'
      ? 'Domain is active!'
      : 'Waiting for nameserver update. This can take up to 24 hours.'
  }));
});

// DELETE /owner/app/:subdomain/domain - Remove custom domain
router.delete('/owner/app/:subdomain/domain', async (request, env) => {
  const owner = await getOwnerSession(request, env);
  if (!owner) {
    return new Response(JSON.stringify({ error: 'Not logged in' }), { status: 401 });
  }

  const { subdomain } = request.params;

  const app = await env.DB.prepare(
    'SELECT owner_id, cf_zone_id FROM apps WHERE subdomain = ?'
  ).bind(subdomain).first();

  if (!app) {
    return new Response(JSON.stringify({ error: 'App not found' }), { status: 404 });
  }

  if (app.owner_id !== owner.owner_id) {
    return new Response(JSON.stringify({ error: 'Not your app' }), { status: 403 });
  }

  // Delete zone from Cloudflare if it exists
  if (app.cf_zone_id) {
    await deleteZone(env, app.cf_zone_id);
  }

  // Clear from database
  await env.DB.prepare(
    'UPDATE apps SET custom_domain = NULL, cf_zone_id = NULL, domain_status = ? WHERE subdomain = ?'
  ).bind('none', subdomain).run();

  return new Response(JSON.stringify({ success: true }));
});

// ============ DNS RECORD MANAGEMENT ============

// GET /owner/app/:subdomain/dns - List DNS records for custom domain
router.get('/owner/app/:subdomain/dns', async (request, env) => {
  const owner = await getOwnerSession(request, env);
  if (!owner) {
    return new Response(JSON.stringify({ error: 'Not logged in' }), { status: 401 });
  }

  const { subdomain } = request.params;

  const app = await env.DB.prepare(
    'SELECT owner_id, cf_zone_id, custom_domain FROM apps WHERE subdomain = ?'
  ).bind(subdomain).first();

  if (!app) {
    return new Response(JSON.stringify({ error: 'App not found' }), { status: 404 });
  }

  if (app.owner_id !== owner.owner_id) {
    return new Response(JSON.stringify({ error: 'Not your app' }), { status: 403 });
  }

  if (!app.cf_zone_id) {
    return new Response(JSON.stringify({ error: 'No custom domain configured' }), { status: 400 });
  }

  // Fetch DNS records from Cloudflare
  const response = await fetch(
    `https://api.cloudflare.com/client/v4/zones/${app.cf_zone_id}/dns_records?per_page=100`,
    {
      headers: {
        'Authorization': `Bearer ${env.CLOUDFLARE_API_TOKEN}`,
      },
    }
  );

  const result = await response.json();
  if (!result.success) {
    return new Response(JSON.stringify({ error: 'Failed to fetch DNS records' }), { status: 500 });
  }

  // Return simplified record format
  const records = result.result.map(r => ({
    id: r.id,
    type: r.type,
    name: r.name,
    content: r.content,
    ttl: r.ttl,
    proxied: r.proxied,
    priority: r.priority, // for MX records
  }));

  return new Response(JSON.stringify({ records, domain: app.custom_domain }));
});

// POST /owner/app/:subdomain/dns - Create DNS record
router.post('/owner/app/:subdomain/dns', async (request, env) => {
  const owner = await getOwnerSession(request, env);
  if (!owner) {
    return new Response(JSON.stringify({ error: 'Not logged in' }), { status: 401 });
  }

  const { subdomain } = request.params;
  const { type, name, content, ttl, proxied, priority } = await request.json();

  if (!type || !name || !content) {
    return new Response(JSON.stringify({ error: 'type, name, and content are required' }), { status: 400 });
  }

  // Validate record type
  const validTypes = ['A', 'AAAA', 'CNAME', 'TXT', 'MX', 'NS', 'SRV', 'CAA'];
  if (!validTypes.includes(type.toUpperCase())) {
    return new Response(JSON.stringify({ error: `Invalid record type. Valid types: ${validTypes.join(', ')}` }), { status: 400 });
  }

  const app = await env.DB.prepare(
    'SELECT owner_id, cf_zone_id, custom_domain FROM apps WHERE subdomain = ?'
  ).bind(subdomain).first();

  if (!app) {
    return new Response(JSON.stringify({ error: 'App not found' }), { status: 404 });
  }

  if (app.owner_id !== owner.owner_id) {
    return new Response(JSON.stringify({ error: 'Not your app' }), { status: 403 });
  }

  if (!app.cf_zone_id) {
    return new Response(JSON.stringify({ error: 'No custom domain configured' }), { status: 400 });
  }

  // Create DNS record via Cloudflare API
  const recordData = {
    type: type.toUpperCase(),
    name,
    content,
    ttl: ttl || 1, // 1 = auto
    proxied: proxied !== undefined ? proxied : false,
  };

  // Add priority for MX records
  if (type.toUpperCase() === 'MX' && priority !== undefined) {
    recordData.priority = priority;
  }

  const response = await fetch(
    `https://api.cloudflare.com/client/v4/zones/${app.cf_zone_id}/dns_records`,
    {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.CLOUDFLARE_API_TOKEN}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(recordData),
    }
  );

  const result = await response.json();
  if (!result.success) {
    const errorMsg = result.errors?.[0]?.message || 'Failed to create DNS record';
    return new Response(JSON.stringify({ error: errorMsg }), { status: 400 });
  }

  return new Response(JSON.stringify({
    success: true,
    record: {
      id: result.result.id,
      type: result.result.type,
      name: result.result.name,
      content: result.result.content,
      ttl: result.result.ttl,
      proxied: result.result.proxied,
      priority: result.result.priority,
    },
  }));
});

// PUT /owner/app/:subdomain/dns/:recordId - Update DNS record
router.put('/owner/app/:subdomain/dns/:recordId', async (request, env) => {
  const owner = await getOwnerSession(request, env);
  if (!owner) {
    return new Response(JSON.stringify({ error: 'Not logged in' }), { status: 401 });
  }

  const { subdomain, recordId } = request.params;
  const { type, name, content, ttl, proxied, priority } = await request.json();

  if (!type || !name || !content) {
    return new Response(JSON.stringify({ error: 'type, name, and content are required' }), { status: 400 });
  }

  const app = await env.DB.prepare(
    'SELECT owner_id, cf_zone_id FROM apps WHERE subdomain = ?'
  ).bind(subdomain).first();

  if (!app) {
    return new Response(JSON.stringify({ error: 'App not found' }), { status: 404 });
  }

  if (app.owner_id !== owner.owner_id) {
    return new Response(JSON.stringify({ error: 'Not your app' }), { status: 403 });
  }

  if (!app.cf_zone_id) {
    return new Response(JSON.stringify({ error: 'No custom domain configured' }), { status: 400 });
  }

  // Update DNS record via Cloudflare API
  const recordData = {
    type: type.toUpperCase(),
    name,
    content,
    ttl: ttl || 1,
    proxied: proxied !== undefined ? proxied : false,
  };

  if (type.toUpperCase() === 'MX' && priority !== undefined) {
    recordData.priority = priority;
  }

  const response = await fetch(
    `https://api.cloudflare.com/client/v4/zones/${app.cf_zone_id}/dns_records/${recordId}`,
    {
      method: 'PUT',
      headers: {
        'Authorization': `Bearer ${env.CLOUDFLARE_API_TOKEN}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(recordData),
    }
  );

  const result = await response.json();
  if (!result.success) {
    const errorMsg = result.errors?.[0]?.message || 'Failed to update DNS record';
    return new Response(JSON.stringify({ error: errorMsg }), { status: 400 });
  }

  return new Response(JSON.stringify({
    success: true,
    record: {
      id: result.result.id,
      type: result.result.type,
      name: result.result.name,
      content: result.result.content,
      ttl: result.result.ttl,
      proxied: result.result.proxied,
      priority: result.result.priority,
    },
  }));
});

// DELETE /owner/app/:subdomain/dns/:recordId - Delete DNS record
router.delete('/owner/app/:subdomain/dns/:recordId', async (request, env) => {
  const owner = await getOwnerSession(request, env);
  if (!owner) {
    return new Response(JSON.stringify({ error: 'Not logged in' }), { status: 401 });
  }

  const { subdomain, recordId } = request.params;

  const app = await env.DB.prepare(
    'SELECT owner_id, cf_zone_id FROM apps WHERE subdomain = ?'
  ).bind(subdomain).first();

  if (!app) {
    return new Response(JSON.stringify({ error: 'App not found' }), { status: 404 });
  }

  if (app.owner_id !== owner.owner_id) {
    return new Response(JSON.stringify({ error: 'Not your app' }), { status: 403 });
  }

  if (!app.cf_zone_id) {
    return new Response(JSON.stringify({ error: 'No custom domain configured' }), { status: 400 });
  }

  // Delete DNS record via Cloudflare API
  const response = await fetch(
    `https://api.cloudflare.com/client/v4/zones/${app.cf_zone_id}/dns_records/${recordId}`,
    {
      method: 'DELETE',
      headers: {
        'Authorization': `Bearer ${env.CLOUDFLARE_API_TOKEN}`,
      },
    }
  );

  const result = await response.json();
  if (!result.success) {
    const errorMsg = result.errors?.[0]?.message || 'Failed to delete DNS record';
    return new Response(JSON.stringify({ error: errorMsg }), { status: 400 });
  }

  return new Response(JSON.stringify({ success: true }));
});

// ============ BILLING ENDPOINTS ============

// Stripe price IDs
const STRIPE_PRICES = {
  pro_monthly: 'price_1Sr7svAE4eT6zpWACXWWO3B5',
  pro_annual: 'price_1Sr7swAE4eT6zpWAMLq5am4Y',
  credit_pack: 'price_1Sr7swAE4eT6zpWAeFxEC5Zd',
};

const PLAN_CREDITS = {
  pro_monthly: 1500,
  pro_annual: 20000,
  credit_pack: 50000,
};

// Helper to create or get Stripe customer for an owner
async function getOrCreateStripeCustomer(env, ownerId, email) {
  if (!ownerId) {
    throw new Error('getOrCreateStripeCustomer: ownerId is required');
  }
  if (!email) {
    throw new Error('getOrCreateStripeCustomer: email is required');
  }

  // Check if we have a Stripe customer for this owner
  const existing = await env.DB.prepare(
    'SELECT stripe_customer_id FROM stripe_customers WHERE owner_id = ?'
  ).bind(ownerId).first();

  if (existing) {
    return existing.stripe_customer_id;
  }

  // Create a new Stripe customer
  const response = await fetch('https://api.stripe.com/v1/customers', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${env.STRIPE_SECRET_KEY}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      email: email,
      'metadata[owner_id]': ownerId,
    }),
  });

  const customer = await response.json();
  if (customer.error) {
    throw new Error(customer.error.message);
  }

  // Save the customer mapping
  await env.DB.prepare(
    'INSERT INTO stripe_customers (owner_id, stripe_customer_id) VALUES (?, ?)'
  ).bind(ownerId, customer.id).run();

  return customer.id;
}

// Helper to add credits and log transaction
async function addCreditsWithTransaction(env, ownerId, amount, type, stripePaymentId, description) {
  const txId = generateId();

  // Add credits
  await env.DB.prepare(`
    INSERT INTO owner_credits (owner_id, balance, lifetime_purchased)
    VALUES (?, ?, ?)
    ON CONFLICT(owner_id) DO UPDATE SET
      balance = balance + excluded.balance,
      lifetime_purchased = lifetime_purchased + excluded.lifetime_purchased,
      updated_at = datetime('now')
  `).bind(ownerId, amount, amount).run();

  // Log transaction
  await env.DB.prepare(`
    INSERT INTO credit_transactions (id, owner_id, amount, type, stripe_payment_intent_id, description)
    VALUES (?, ?, ?, ?, ?, ?)
  `).bind(txId, ownerId, amount, type, stripePaymentId, description).run();

  return txId;
}

// Helper to trigger auto-refill if needed
async function checkAutoRefill(env, ownerId) {
  // Get auto-refill settings
  const settings = await env.DB.prepare(
    'SELECT * FROM auto_refill_settings WHERE owner_id = ? AND enabled = 1'
  ).bind(ownerId).first();

  if (!settings) return null;

  // Get current balance
  const credits = await env.DB.prepare(
    'SELECT balance FROM owner_credits WHERE owner_id = ?'
  ).bind(ownerId).first();

  const balance = credits?.balance || 0;

  // Check if balance is below threshold
  if (balance >= settings.threshold) return null;

  // Get Stripe customer with payment method
  const customer = await env.DB.prepare(
    'SELECT stripe_customer_id, default_payment_method FROM stripe_customers WHERE owner_id = ?'
  ).bind(ownerId).first();

  if (!customer || !customer.default_payment_method) return null;

  // Get owner email for receipt
  const owner = await env.DB.prepare(
    'SELECT email FROM owners WHERE id = ?'
  ).bind(ownerId).first();

  // Create a payment intent and charge immediately
  const params = new URLSearchParams({
    amount: settings.refill_price.toString(),  // in cents
    currency: 'usd',
    customer: customer.stripe_customer_id,
    payment_method: customer.default_payment_method,
    off_session: 'true',
    confirm: 'true',
    'metadata[owner_id]': ownerId,
    'metadata[type]': 'auto_refill',
    description: `itsalive.co credit refill - ${settings.refill_amount.toLocaleString()} credits`,
  });

  // Add receipt email if we have it
  if (owner?.email) {
    params.append('receipt_email', owner.email);
  }

  const paymentResponse = await fetch('https://api.stripe.com/v1/payment_intents', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${env.STRIPE_SECRET_KEY}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: params,
  });

  const payment = await paymentResponse.json();
  if (payment.error) {
    console.error('Auto-refill failed:', payment.error.message);
    return { error: payment.error.message };
  }

  if (payment.status === 'succeeded') {
    // Add credits
    await addCreditsWithTransaction(
      env,
      ownerId,
      settings.refill_amount,
      'auto_refill',
      payment.id,
      `Auto-refill: ${settings.refill_amount.toLocaleString()} credits for $${(settings.refill_price / 100).toFixed(2)}`
    );

    // Update last refill time
    await env.DB.prepare(
      'UPDATE auto_refill_settings SET last_refill_at = datetime(\'now\') WHERE owner_id = ?'
    ).bind(ownerId).run();

    return { success: true, credits_added: settings.refill_amount };
  }

  return { error: 'Payment not completed' };
}

// POST /billing/checkout - Create Stripe checkout session for subscription
router.post('/billing/checkout', async (request, env) => {
  const owner = await getOwnerSession(request, env);
  if (!owner) {
    return new Response(JSON.stringify({ error: 'Not logged in' }), { status: 401 });
  }

  const { plan } = await request.json();

  if (!plan || !['pro_monthly', 'pro_annual'].includes(plan)) {
    return new Response(JSON.stringify({ error: 'Invalid plan. Choose pro_monthly or pro_annual' }), { status: 400 });
  }

  // Get or create Stripe customer
  const stripeCustomerId = await getOrCreateStripeCustomer(env, owner.owner_id, owner.email);

  // Check for existing active subscription
  const existing = await env.DB.prepare(
    'SELECT * FROM subscriptions WHERE owner_id = ? AND status = \'active\''
  ).bind(owner.owner_id).first();

  if (existing) {
    return new Response(JSON.stringify({
      error: 'You already have an active subscription',
      current_plan: existing.plan,
    }), { status: 400 });
  }

  // Create Stripe checkout session
  const response = await fetch('https://api.stripe.com/v1/checkout/sessions', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${env.STRIPE_SECRET_KEY}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      customer: stripeCustomerId,
      mode: 'subscription',
      'line_items[0][price]': STRIPE_PRICES[plan],
      'line_items[0][quantity]': '1',
      success_url: 'https://dashboard.itsalive.co/?billing=success',
      cancel_url: 'https://dashboard.itsalive.co/?billing=canceled',
      'subscription_data[metadata][owner_id]': owner.owner_id,
      'subscription_data[metadata][plan]': plan,
      payment_method_collection: 'always',
    }),
  });

  const session = await response.json();
  if (session.error) {
    return new Response(JSON.stringify({ error: session.error.message }), { status: 400 });
  }

  return { checkout_url: session.url };
});

// POST /billing/setup-intent - Create a SetupIntent for collecting payment method
router.post('/billing/setup-intent', async (request, env) => {
  const owner = await getOwnerSession(request, env);
  if (!owner) {
    return new Response(JSON.stringify({ error: 'Not logged in' }), { status: 401 });
  }

  if (!owner.owner_id || !owner.email) {
    return new Response(JSON.stringify({ error: 'Invalid session: missing owner_id or email' }), { status: 401 });
  }

  const body = await request.json();
  const { plan, site, reseller_code } = body;

  if (!plan || !['pro_monthly', 'pro_annual'].includes(plan)) {
    return new Response(JSON.stringify({ error: 'Invalid plan. Choose pro_monthly or pro_annual' }), { status: 400 });
  }

  if (!site || typeof site !== 'string') {
    return new Response(JSON.stringify({ error: 'site is required' }), { status: 400 });
  }

  // Verify the site belongs to this owner
  let app;
  try {
    app = await env.DB.prepare(
      'SELECT subdomain FROM apps WHERE subdomain = ? AND owner_id = ?'
    ).bind(site, owner.owner_id).first();
  } catch (e) {
    return new Response(JSON.stringify({ error: 'DB error (app lookup): ' + e.message, site, owner_id: owner.owner_id }), { status: 500 });
  }

  if (!app) {
    return new Response(JSON.stringify({ error: 'Site not found or not owned by you' }), { status: 404 });
  }

  // Get or create Stripe customer
  let stripeCustomerId;
  try {
    stripeCustomerId = await getOrCreateStripeCustomer(env, owner.owner_id, owner.email);
  } catch (e) {
    return new Response(JSON.stringify({ error: 'DB error (stripe customer): ' + e.message }), { status: 500 });
  }

  // Check for existing active subscription for this site
  let existing;
  try {
    existing = await env.DB.prepare(
      'SELECT * FROM subscriptions WHERE app_subdomain = ? AND status = \'active\''
    ).bind(site).first();
  } catch (e) {
    return new Response(JSON.stringify({ error: 'DB error (subscription check): ' + e.message }), { status: 500 });
  }

  if (existing) {
    return new Response(JSON.stringify({
      error: 'This site already has an active subscription',
      current_plan: existing.plan,
    }), { status: 400 });
  }

  // Validate reseller code if provided
  let validatedResellerCode = null;
  if (reseller_code) {
    const rc = await env.DB.prepare(`
      SELECT rc.code, rc.discount_type, rc.reseller_id, rc.status, r.status as reseller_status
      FROM reseller_codes rc
      JOIN resellers r ON rc.reseller_id = r.id
      WHERE rc.code = ?
    `).bind(reseller_code.toUpperCase()).first();

    if (rc && rc.status === 'active' && rc.reseller_status === 'active') {
      validatedResellerCode = rc;
    }
  }

  // Create SetupIntent with automatic payment methods
  const params = new URLSearchParams();
  params.append('customer', stripeCustomerId);
  params.append('automatic_payment_methods[enabled]', 'true');
  params.append('automatic_payment_methods[allow_redirects]', 'never');
  params.append('usage', 'off_session');
  params.append('metadata[owner_id]', owner.owner_id);
  params.append('metadata[plan]', plan);
  params.append('metadata[site]', site);
  if (validatedResellerCode) {
    params.append('metadata[reseller_code]', validatedResellerCode.code);
    params.append('metadata[reseller_id]', validatedResellerCode.reseller_id);
    params.append('metadata[discount_type]', validatedResellerCode.discount_type);
  }

  const response = await fetch('https://api.stripe.com/v1/setup_intents', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${env.STRIPE_SECRET_KEY}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: params,
  });

  const setupIntent = await response.json();
  if (setupIntent.error) {
    console.error('Stripe SetupIntent error:', setupIntent.error);
    return new Response(JSON.stringify({ error: setupIntent.error.message }), { status: 400 });
  }

  return {
    client_secret: setupIntent.client_secret,
    setup_intent_id: setupIntent.id,
  };
});

// POST /billing/create-subscription - Create subscription after payment method is set up
router.post('/billing/create-subscription', async (request, env) => {
  const owner = await getOwnerSession(request, env);
  if (!owner) {
    return new Response(JSON.stringify({ error: 'Not logged in' }), { status: 401 });
  }

  if (!owner.owner_id) {
    return new Response(JSON.stringify({ error: 'Invalid session: missing owner_id' }), { status: 401 });
  }

  const body = await request.json();
  const { plan, setup_intent_id, site } = body;

  if (!plan || !['pro_monthly', 'pro_annual'].includes(plan)) {
    return new Response(JSON.stringify({ error: 'Invalid plan' }), { status: 400 });
  }

  if (!setup_intent_id) {
    return new Response(JSON.stringify({ error: 'setup_intent_id required' }), { status: 400 });
  }

  if (!site || typeof site !== 'string') {
    return new Response(JSON.stringify({ error: 'site is required' }), { status: 400 });
  }

  // Verify the site belongs to this owner
  let app;
  try {
    app = await env.DB.prepare(
      'SELECT subdomain FROM apps WHERE subdomain = ? AND owner_id = ?'
    ).bind(site, owner.owner_id).first();
  } catch (e) {
    console.error('create-subscription: app lookup failed', { site, owner_id: owner.owner_id, error: e.message });
    return new Response(JSON.stringify({ error: 'DB error (app lookup): ' + e.message }), { status: 500 });
  }

  if (!app) {
    return new Response(JSON.stringify({ error: 'Site not found or not owned by you' }), { status: 404 });
  }

  // Verify the SetupIntent succeeded
  const siResponse = await fetch(`https://api.stripe.com/v1/setup_intents/${setup_intent_id}`, {
    headers: { 'Authorization': `Bearer ${env.STRIPE_SECRET_KEY}` },
  });
  const setupIntent = await siResponse.json();

  if (setupIntent.error) {
    console.error('SetupIntent error:', setupIntent.error);
    return new Response(JSON.stringify({ error: 'SetupIntent error: ' + setupIntent.error.message }), { status: 400 });
  }

  if (setupIntent.status !== 'succeeded') {
    return new Response(JSON.stringify({ error: 'Payment method not confirmed. Status: ' + setupIntent.status }), { status: 400 });
  }

  const stripeCustomerId = setupIntent.customer;
  const paymentMethodId = setupIntent.payment_method;

  if (!stripeCustomerId || !paymentMethodId) {
    return new Response(JSON.stringify({
      error: 'Invalid SetupIntent: missing customer or payment_method',
      customerId: stripeCustomerId || 'missing',
      paymentMethodId: paymentMethodId || 'missing'
    }), { status: 400 });
  }

  // Set as default payment method
  await fetch(`https://api.stripe.com/v1/customers/${stripeCustomerId}`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${env.STRIPE_SECRET_KEY}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      'invoice_settings[default_payment_method]': paymentMethodId,
    }),
  });

  // Create the subscription
  const subParams = new URLSearchParams();
  subParams.append('customer', stripeCustomerId);
  subParams.append('items[0][price]', STRIPE_PRICES[plan]);
  subParams.append('default_payment_method', paymentMethodId);
  subParams.append('metadata[owner_id]', owner.owner_id);
  subParams.append('metadata[plan]', plan);
  subParams.append('metadata[site]', site);

  const subResponse = await fetch('https://api.stripe.com/v1/subscriptions', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${env.STRIPE_SECRET_KEY}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: subParams,
  });

  const subscription = await subResponse.json();
  if (subscription.error) {
    return new Response(JSON.stringify({ error: 'Stripe subscription error: ' + subscription.error.message }), { status: 400 });
  }

  // Validate subscription data before inserting
  if (!subscription.id || !subscription.status) {
    console.error('Invalid subscription response:', JSON.stringify(subscription));
    return new Response(JSON.stringify({ error: 'Invalid subscription response from Stripe' }), { status: 500 });
  }

  // Record in our database
  try {
    await env.DB.prepare(`
      INSERT INTO subscriptions (id, owner_id, app_subdomain, stripe_subscription_id, plan, status, current_period_start, current_period_end)
      VALUES (?, ?, ?, ?, ?, ?, datetime(?, 'unixepoch'), datetime(?, 'unixepoch'))
    `).bind(
      generateId(),
      owner.owner_id,
      site,
      subscription.id,
      plan,
      subscription.status,
      subscription.current_period_start || Math.floor(Date.now() / 1000),
      subscription.current_period_end || Math.floor(Date.now() / 1000) + 86400 * 30
    ).run();
  } catch (e) {
    console.error('create-subscription: insert subscription failed', { error: e.message });
    return new Response(JSON.stringify({ error: 'DB error (insert subscription): ' + e.message }), { status: 500 });
  }

  // Grant credits
  const credits = PLAN_CREDITS[plan] || 1500;
  try {
    await addCreditsWithTransaction(
      env,
      owner.owner_id,
      credits,
      'subscription',
      null,
      `${plan === 'pro_annual' ? 'Pro Annual' : 'Pro Monthly'} subscription - ${credits.toLocaleString()} credits`
    );
  } catch (e) {
    console.error('create-subscription: addCreditsWithTransaction failed', { error: e.message });
    return new Response(JSON.stringify({ error: 'DB error (add credits): ' + e.message }), { status: 500 });
  }

  // Save payment method and enable auto-refill
  try {
    await env.DB.prepare(
      'UPDATE stripe_customers SET default_payment_method = ? WHERE owner_id = ?'
    ).bind(paymentMethodId, owner.owner_id).run();
  } catch (e) {
    console.error('create-subscription: update payment method failed', { error: e.message });
    // Non-fatal, continue
  }

  try {
    await env.DB.prepare(`
      INSERT INTO auto_refill_settings (owner_id, enabled, threshold, refill_amount, refill_price)
      VALUES (?, 1, 10000, 50000, 5000)
      ON CONFLICT(owner_id) DO UPDATE SET enabled = 1
    `).bind(owner.owner_id).run();
  } catch (e) {
    console.error('create-subscription: auto_refill_settings failed', { error: e.message });
    // Non-fatal, continue
  }

  return {
    success: true,
    subscription_id: subscription.id,
    credits_added: credits,
  };
});

// POST /billing/confirm-subscription - Confirm subscription after payment succeeds
router.post('/billing/confirm-subscription', async (request, env) => {
  const owner = await getOwnerSession(request, env);
  if (!owner) {
    return new Response(JSON.stringify({ error: 'Not logged in' }), { status: 401 });
  }

  const { subscription_id } = await request.json();

  if (!subscription_id) {
    return new Response(JSON.stringify({ error: 'subscription_id required' }), { status: 400 });
  }

  // Fetch the subscription from Stripe
  const response = await fetch(`https://api.stripe.com/v1/subscriptions/${subscription_id}`, {
    headers: { 'Authorization': `Bearer ${env.STRIPE_SECRET_KEY}` },
  });

  const subscription = await response.json();
  if (subscription.error) {
    return new Response(JSON.stringify({ error: subscription.error.message }), { status: 400 });
  }

  if (subscription.status !== 'active') {
    return new Response(JSON.stringify({ error: 'Subscription not active', status: subscription.status }), { status: 400 });
  }

  const ownerId = subscription.metadata?.owner_id;
  const plan = subscription.metadata?.plan;
  const site = subscription.metadata?.site;

  if (ownerId !== owner.owner_id) {
    return new Response(JSON.stringify({ error: 'Subscription does not belong to you' }), { status: 403 });
  }

  if (!site) {
    return new Response(JSON.stringify({ error: 'Subscription missing site metadata' }), { status: 400 });
  }

  // Check if already recorded
  const existingSub = await env.DB.prepare(
    'SELECT id FROM subscriptions WHERE stripe_subscription_id = ?'
  ).bind(subscription.id).first();

  if (existingSub) {
    return { success: true, already_recorded: true };
  }

  // Create subscription record
  await env.DB.prepare(`
    INSERT INTO subscriptions (id, owner_id, app_subdomain, stripe_subscription_id, plan, status, current_period_start, current_period_end)
    VALUES (?, ?, ?, ?, ?, ?, datetime(?, 'unixepoch'), datetime(?, 'unixepoch'))
  `).bind(
    generateId(),
    ownerId,
    site,
    subscription.id,
    plan,
    subscription.status,
    subscription.current_period_start,
    subscription.current_period_end
  ).run();

  // Grant initial credits
  const credits = PLAN_CREDITS[plan] || 1500;
  await addCreditsWithTransaction(
    env,
    ownerId,
    credits,
    'subscription',
    null,
    `${plan === 'pro_annual' ? 'Pro Annual' : 'Pro Monthly'} subscription - ${credits.toLocaleString()} credits`
  );

  // Save payment method and enable auto-refill
  if (subscription.default_payment_method) {
    await env.DB.prepare(
      'UPDATE stripe_customers SET default_payment_method = ? WHERE owner_id = ?'
    ).bind(subscription.default_payment_method, ownerId).run();

    await env.DB.prepare(`
      INSERT INTO auto_refill_settings (owner_id, enabled, threshold, refill_amount, refill_price)
      VALUES (?, 1, 10000, 50000, 5000)
      ON CONFLICT(owner_id) DO UPDATE SET enabled = 1
    `).bind(ownerId).run();
  }

  return { success: true, credits_added: credits };
});

// GET /billing/config - Get Stripe publishable key for frontend
router.get('/billing/config', async (request, env) => {
  return {
    publishable_key: env.STRIPE_PUBLISHABLE_KEY || 'pk_live_51Sr77gAm9KmWcHbHQxQ5Z3lF2ZXO1ZVT3oy9SI651I51o1flVKSYtr1vthfNgUWonWgvpq7sfPiiDTBtNgE7Hfng00XH6LcFiI',
  };
});

// POST /billing/portal - Get Stripe customer portal URL
router.post('/billing/portal', async (request, env) => {
  const owner = await getOwnerSession(request, env);
  if (!owner) {
    return new Response(JSON.stringify({ error: 'Not logged in' }), { status: 401 });
  }

  // Get Stripe customer
  const customer = await env.DB.prepare(
    'SELECT stripe_customer_id FROM stripe_customers WHERE owner_id = ?'
  ).bind(owner.owner_id).first();

  if (!customer) {
    return new Response(JSON.stringify({ error: 'No billing account found' }), { status: 404 });
  }

  // Create portal session
  const response = await fetch('https://api.stripe.com/v1/billing_portal/sessions', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${env.STRIPE_SECRET_KEY}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      customer: customer.stripe_customer_id,
      return_url: 'https://dashboard.itsalive.co/',
    }),
  });

  const session = await response.json();
  if (session.error) {
    return new Response(JSON.stringify({ error: session.error.message }), { status: 400 });
  }

  return { portal_url: session.url };
});

// POST /billing/redeem-coupon - Redeem a coupon for free subscription
router.post('/billing/redeem-coupon', async (request, env) => {
  const owner = await getOwnerSession(request, env);
  if (!owner) {
    return new Response(JSON.stringify({ error: 'Not logged in' }), { status: 401 });
  }

  const { code, site } = await request.json();

  if (!code) {
    return new Response(JSON.stringify({ error: 'code is required' }), { status: 400 });
  }

  if (!site) {
    return new Response(JSON.stringify({ error: 'site is required' }), { status: 400 });
  }

  // Verify the site belongs to this owner
  const app = await env.DB.prepare(
    'SELECT subdomain FROM apps WHERE subdomain = ? AND owner_id = ?'
  ).bind(site, owner.owner_id).first();

  if (!app) {
    return new Response(JSON.stringify({ error: 'Site not found or not owned by you' }), { status: 404 });
  }

  // Check for existing active subscription for this site
  const existingSub = await env.DB.prepare(
    'SELECT id FROM subscriptions WHERE app_subdomain = ? AND status = ?'
  ).bind(site, 'active').first();

  if (existingSub) {
    return new Response(JSON.stringify({ error: 'This site already has an active subscription' }), { status: 400 });
  }

  // Get the coupon
  const coupon = await env.DB.prepare(
    'SELECT * FROM coupons WHERE code = ?'
  ).bind(code.toLowerCase()).first();

  if (!coupon) {
    return new Response(JSON.stringify({ error: 'Invalid coupon code' }), { status: 404 });
  }

  // Check if coupon has uses remaining
  if (coupon.uses_remaining !== null && coupon.uses_remaining <= 0) {
    return new Response(JSON.stringify({ error: 'This coupon has been fully redeemed' }), { status: 400 });
  }

  // Check if coupon has expired
  if (coupon.expires_at && new Date(coupon.expires_at) < new Date()) {
    return new Response(JSON.stringify({ error: 'This coupon has expired' }), { status: 400 });
  }

  // Check if user already redeemed this coupon
  const existingRedemption = await env.DB.prepare(
    'SELECT id FROM coupon_redemptions WHERE coupon_code = ? AND owner_id = ?'
  ).bind(code.toLowerCase(), owner.owner_id).first();

  if (existingRedemption) {
    return new Response(JSON.stringify({ error: 'You have already redeemed this coupon' }), { status: 400 });
  }

  // Calculate subscription period
  const now = Math.floor(Date.now() / 1000);
  const periodEnd = now + (coupon.duration_months * 30 * 24 * 60 * 60);

  // Create subscription record
  const subscriptionId = generateId();
  const fakeStripeId = `coupon_${code.toLowerCase()}_${subscriptionId}`;

  await env.DB.prepare(`
    INSERT INTO subscriptions (id, owner_id, app_subdomain, stripe_subscription_id, plan, status, current_period_start, current_period_end)
    VALUES (?, ?, ?, ?, ?, 'active', datetime(?, 'unixepoch'), datetime(?, 'unixepoch'))
  `).bind(
    subscriptionId,
    owner.owner_id,
    site,
    fakeStripeId,
    coupon.plan,
    now,
    periodEnd
  ).run();

  // Grant credits based on plan
  const PLAN_CREDITS = { pro_monthly: 1500, pro_annual: 20000 };
  const credits = PLAN_CREDITS[coupon.plan] || 1500;

  await addCreditsWithTransaction(
    env,
    owner.owner_id,
    credits,
    'coupon',
    null,
    `Coupon "${code}" redeemed - ${credits.toLocaleString()} credits`
  );

  // Record the redemption
  await env.DB.prepare(`
    INSERT INTO coupon_redemptions (id, coupon_code, owner_id, app_subdomain, subscription_id)
    VALUES (?, ?, ?, ?, ?)
  `).bind(generateId(), code.toLowerCase(), owner.owner_id, site, subscriptionId).run();

  // Decrement uses remaining
  if (coupon.uses_remaining !== null) {
    await env.DB.prepare(
      'UPDATE coupons SET uses_remaining = uses_remaining - 1 WHERE code = ?'
    ).bind(code.toLowerCase()).run();
  }

  return {
    success: true,
    subscription_id: subscriptionId,
    plan: coupon.plan,
    duration_months: coupon.duration_months,
    credits_added: credits,
    expires_at: new Date(periodEnd * 1000).toISOString(),
  };
});

// GET /billing/info - Get billing status
router.get('/billing/info', async (request, env) => {
  const owner = await getOwnerSession(request, env);
  if (!owner) {
    return new Response(JSON.stringify({ error: 'Not logged in' }), { status: 401 });
  }

  if (!owner.owner_id) {
    return new Response(JSON.stringify({ error: 'Invalid session: missing owner_id' }), { status: 401 });
  }

  // Get all subscriptions for this owner (keyed by site)
  const subscriptionRows = await env.DB.prepare(
    'SELECT app_subdomain, plan, status, current_period_end, cancel_at_period_end FROM subscriptions WHERE owner_id = ? AND status IN (\'active\', \'past_due\')'
  ).bind(owner.owner_id).all();

  // Build subscriptions object keyed by site subdomain
  const subscriptions = {};
  for (const sub of subscriptionRows.results || []) {
    subscriptions[sub.app_subdomain] = {
      plan: sub.plan,
      status: sub.status,
      current_period_end: sub.current_period_end,
      cancel_at_period_end: !!sub.cancel_at_period_end,
    };
  }

  // For backwards compatibility, also return first subscription as "subscription"
  const firstSub = subscriptionRows.results?.[0];
  const subscription = firstSub ? {
    plan: firstSub.plan,
    status: firstSub.status,
    current_period_end: firstSub.current_period_end,
    cancel_at_period_end: !!firstSub.cancel_at_period_end,
  } : null;

  // Get credits
  const credits = await env.DB.prepare(
    'SELECT balance, lifetime_purchased, lifetime_used FROM owner_credits WHERE owner_id = ?'
  ).bind(owner.owner_id).first();

  // Check if user has payment method for auto-refill
  const customer = await env.DB.prepare(
    'SELECT default_payment_method FROM stripe_customers WHERE owner_id = ?'
  ).bind(owner.owner_id).first();

  // Get auto-refill settings, auto-create with enabled=1 if user has subscription + payment method
  let autoRefill = await env.DB.prepare(
    'SELECT enabled, threshold, refill_amount, refill_price FROM auto_refill_settings WHERE owner_id = ?'
  ).bind(owner.owner_id).first();

  // Auto-enable for subscribers with payment method who don't have settings yet
  if (!autoRefill && subscription && customer?.default_payment_method) {
    await env.DB.prepare(`
      INSERT INTO auto_refill_settings (owner_id, enabled, threshold, refill_amount, refill_price)
      VALUES (?, 1, 10000, 50000, 5000)
    `).bind(owner.owner_id).run();
    autoRefill = { enabled: 1, threshold: 10000, refill_amount: 50000, refill_price: 5000 };
  }

  return {
    subscription, // First subscription (backwards compat)
    subscriptions, // All subscriptions keyed by site subdomain
    credits: {
      balance: credits?.balance || 0,
      lifetime_purchased: credits?.lifetime_purchased || 0,
      lifetime_used: credits?.lifetime_used || 0,
    },
    auto_refill: autoRefill ? {
      enabled: !!autoRefill.enabled,
      threshold: autoRefill.threshold,
      refill_amount: autoRefill.refill_amount,
      price_cents: autoRefill.refill_price,
    } : {
      enabled: false,
      threshold: 10000,
      refill_amount: 50000,
      price_cents: 5000,
    },
    has_payment_method: !!customer?.default_payment_method,
  };
});

// PUT /billing/auto-refill - Configure auto-refill settings
router.put('/billing/auto-refill', async (request, env) => {
  const owner = await getOwnerSession(request, env);
  if (!owner) {
    return new Response(JSON.stringify({ error: 'Not logged in' }), { status: 401 });
  }

  const { enabled, threshold } = await request.json();

  if (enabled !== undefined && typeof enabled !== 'boolean') {
    return new Response(JSON.stringify({ error: 'enabled must be a boolean' }), { status: 400 });
  }

  if (threshold !== undefined && (typeof threshold !== 'number' || threshold < 0)) {
    return new Response(JSON.stringify({ error: 'threshold must be a non-negative number' }), { status: 400 });
  }

  // If enabling, check for payment method
  if (enabled) {
    const customer = await env.DB.prepare(
      'SELECT default_payment_method FROM stripe_customers WHERE owner_id = ?'
    ).bind(owner.owner_id).first();

    if (!customer?.default_payment_method) {
      return new Response(JSON.stringify({
        error: 'Add a payment method first. Use the billing portal to add a card.',
      }), { status: 400 });
    }
  }

  // Upsert auto-refill settings
  await env.DB.prepare(`
    INSERT INTO auto_refill_settings (owner_id, enabled, threshold)
    VALUES (?, ?, ?)
    ON CONFLICT(owner_id) DO UPDATE SET
      enabled = COALESCE(excluded.enabled, enabled),
      threshold = COALESCE(excluded.threshold, threshold)
  `).bind(
    owner.owner_id,
    enabled !== undefined ? (enabled ? 1 : 0) : 1,
    threshold || 10000
  ).run();

  const settings = await env.DB.prepare(
    'SELECT * FROM auto_refill_settings WHERE owner_id = ?'
  ).bind(owner.owner_id).first();

  return {
    enabled: !!settings.enabled,
    threshold: settings.threshold,
    refill_amount: settings.refill_amount,
    price_cents: settings.refill_price,
  };
});

// POST /billing/webhook - Stripe webhook handler
router.post('/billing/webhook', async (request, env) => {
  const signature = request.headers.get('stripe-signature');
  const body = await request.text();

  // Verify webhook signature
  if (!signature || !env.STRIPE_WEBHOOK_SECRET) {
    return new Response(JSON.stringify({ error: 'Missing signature or webhook secret' }), { status: 400 });
  }

  // Parse signature header
  const sigParts = {};
  for (const part of signature.split(',')) {
    const [key, value] = part.split('=');
    sigParts[key] = value;
  }

  const timestamp = sigParts['t'];
  const v1Signature = sigParts['v1'];

  if (!timestamp || !v1Signature) {
    return new Response(JSON.stringify({ error: 'Invalid signature format' }), { status: 400 });
  }

  // Verify timestamp (within 5 minutes)
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - parseInt(timestamp)) > 300) {
    return new Response(JSON.stringify({ error: 'Timestamp too old' }), { status: 400 });
  }

  // Compute expected signature
  const signedPayload = `${timestamp}.${body}`;
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(env.STRIPE_WEBHOOK_SECRET),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signatureBytes = await crypto.subtle.sign('HMAC', key, encoder.encode(signedPayload));
  const expectedSignature = Array.from(new Uint8Array(signatureBytes))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');

  if (expectedSignature !== v1Signature) {
    return new Response(JSON.stringify({ error: 'Invalid signature' }), { status: 400 });
  }

  // Parse event
  const event = JSON.parse(body);
  console.log('Stripe webhook:', event.type);

  try {
    switch (event.type) {
      case 'checkout.session.completed': {
        const session = event.data.object;
        if (session.mode === 'subscription' && session.subscription) {
          // Fetch the subscription to get details
          const subResponse = await fetch(
            `https://api.stripe.com/v1/subscriptions/${session.subscription}`,
            {
              headers: { 'Authorization': `Bearer ${env.STRIPE_SECRET_KEY}` },
            }
          );
          const subscription = await subResponse.json();

          const ownerId = subscription.metadata?.owner_id;
          const plan = subscription.metadata?.plan;
          const site = subscription.metadata?.site;

          if (ownerId && plan && site) {
            // Create subscription record
            await env.DB.prepare(`
              INSERT INTO subscriptions (id, owner_id, app_subdomain, stripe_subscription_id, plan, status, current_period_start, current_period_end)
              VALUES (?, ?, ?, ?, ?, ?, datetime(?, 'unixepoch'), datetime(?, 'unixepoch'))
            `).bind(
              generateId(),
              ownerId,
              site,
              subscription.id,
              plan,
              subscription.status,
              subscription.current_period_start,
              subscription.current_period_end
            ).run();

            // Grant initial credits
            const credits = PLAN_CREDITS[plan] || 1500;
            await addCreditsWithTransaction(
              env,
              ownerId,
              credits,
              'subscription',
              session.payment_intent,
              `${plan === 'pro_annual' ? 'Pro Annual' : 'Pro Monthly'} subscription - ${credits.toLocaleString()} credits`
            );

            // Save payment method for auto-refill
            if (session.payment_method_collection === 'always' && subscription.default_payment_method) {
              await env.DB.prepare(
                'UPDATE stripe_customers SET default_payment_method = ? WHERE owner_id = ?'
              ).bind(subscription.default_payment_method, ownerId).run();

              // Enable auto-refill by default for new subscribers
              await env.DB.prepare(`
                INSERT INTO auto_refill_settings (owner_id, enabled, threshold, refill_amount, refill_price)
                VALUES (?, 1, 10000, 50000, 5000)
                ON CONFLICT(owner_id) DO UPDATE SET enabled = 1
              `).bind(ownerId).run();
            }
          }
        }
        break;
      }

      case 'invoice.paid': {
        const invoice = event.data.object;
        // Skip if this is the first invoice (handled by checkout.session.completed)
        if (invoice.billing_reason === 'subscription_cycle') {
          const subscription = await env.DB.prepare(
            'SELECT owner_id, plan FROM subscriptions WHERE stripe_subscription_id = ?'
          ).bind(invoice.subscription).first();

          if (subscription) {
            const credits = PLAN_CREDITS[subscription.plan] || 1500;
            await addCreditsWithTransaction(
              env,
              subscription.owner_id,
              credits,
              'subscription',
              invoice.payment_intent,
              `${subscription.plan === 'pro_annual' ? 'Pro Annual' : 'Pro Monthly'} renewal - ${credits.toLocaleString()} credits`
            );
          }
        }
        break;
      }

      case 'customer.subscription.updated': {
        const subscription = event.data.object;
        await env.DB.prepare(`
          UPDATE subscriptions
          SET status = ?, current_period_start = datetime(?, 'unixepoch'), current_period_end = datetime(?, 'unixepoch'), cancel_at_period_end = ?, updated_at = datetime('now')
          WHERE stripe_subscription_id = ?
        `).bind(
          subscription.status,
          subscription.current_period_start,
          subscription.current_period_end,
          subscription.cancel_at_period_end ? 1 : 0,
          subscription.id
        ).run();
        break;
      }

      case 'customer.subscription.deleted': {
        const subscription = event.data.object;
        await env.DB.prepare(
          'UPDATE subscriptions SET status = \'canceled\', updated_at = datetime(\'now\') WHERE stripe_subscription_id = ?'
        ).bind(subscription.id).run();
        break;
      }

      case 'payment_intent.succeeded': {
        const paymentIntent = event.data.object;
        // Handle auto-refill payments (already processed in checkAutoRefill, but log if missed)
        if (paymentIntent.metadata?.type === 'auto_refill') {
          console.log('Auto-refill payment confirmed:', paymentIntent.id);
        }
        break;
      }

      case 'payment_method.attached': {
        // Update default payment method when user adds one
        const paymentMethod = event.data.object;
        if (paymentMethod.customer) {
          await env.DB.prepare(
            'UPDATE stripe_customers SET default_payment_method = ? WHERE stripe_customer_id = ?'
          ).bind(paymentMethod.id, paymentMethod.customer).run();
        }
        break;
      }
    }

    return { received: true };
  } catch (e) {
    console.error('Webhook processing error:', e);
    return new Response(JSON.stringify({ error: 'Webhook processing failed' }), { status: 500 });
  }
});

// GET /billing/transactions - Get credit transaction history
router.get('/billing/transactions', async (request, env) => {
  const owner = await getOwnerSession(request, env);
  if (!owner) {
    return new Response(JSON.stringify({ error: 'Not logged in' }), { status: 401 });
  }

  const url = new URL(request.url);
  const limit = Math.min(parseInt(url.searchParams.get('limit') || '50'), 100);
  const offset = parseInt(url.searchParams.get('offset') || '0');

  const transactions = await env.DB.prepare(`
    SELECT id, amount, type, description, created_at
    FROM credit_transactions
    WHERE owner_id = ?
    ORDER BY created_at DESC
    LIMIT ? OFFSET ?
  `).bind(owner.owner_id, limit, offset).all();

  const total = await env.DB.prepare(
    'SELECT COUNT(*) as count FROM credit_transactions WHERE owner_id = ?'
  ).bind(owner.owner_id).first();

  return {
    transactions: transactions.results,
    total: total?.count || 0,
    limit,
    offset,
  };
});

// ============ APP SETTINGS ENDPOINTS ============

// GET /app/settings - Get app settings (custom domain, etc.)
router.get('/app/settings', async (request, env) => {
  const user = await getSession(request, env);
  if (!user) {
    return new Response(JSON.stringify({ error: 'Not logged in' }), { status: 401 });
  }

  const subdomain = getSubdomain(request);
  if (!subdomain) {
    return new Response(JSON.stringify({ error: 'Invalid origin' }), { status: 400 });
  }

  // Check if user is app owner
  const isOwner = await isAppOwner(env, subdomain, user.email);

  // Get app info
  const app = await env.DB.prepare(
    'SELECT subdomain, custom_domain, created_at FROM apps WHERE subdomain = ?'
  ).bind(subdomain).first();

  if (!app) {
    return new Response(JSON.stringify({ error: 'App not found' }), { status: 404 });
  }

  // Get branding
  const branding = await getAppBranding(env, subdomain);

  return {
    subdomain: app.subdomain,
    custom_domain: app.custom_domain,
    created_at: app.created_at,
    is_owner: isOwner,
    branding,
  };
});

// PUT /app/settings - Update app settings (owner only)
router.put('/app/settings', async (request, env) => {
  const user = await getSession(request, env);
  if (!user) {
    return new Response(JSON.stringify({ error: 'Not logged in' }), { status: 401 });
  }

  const subdomain = getSubdomain(request);
  if (!subdomain) {
    return new Response(JSON.stringify({ error: 'Invalid origin' }), { status: 400 });
  }

  // Check if user is app owner
  if (!await isAppOwner(env, subdomain, user.email)) {
    return new Response(JSON.stringify({ error: 'Only the app owner can change settings' }), { status: 403 });
  }

  const body = await request.json();
  const { custom_domain } = body;

  // Validate custom domain format
  if (custom_domain !== null && custom_domain !== undefined) {
    if (custom_domain === '') {
      // Clear custom domain
      await env.DB.prepare(
        'UPDATE apps SET custom_domain = NULL WHERE subdomain = ?'
      ).bind(subdomain).run();
    } else {
      // Validate domain format
      const domainRegex = /^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$/i;
      if (!domainRegex.test(custom_domain)) {
        return new Response(JSON.stringify({ error: 'Invalid domain format' }), { status: 400 });
      }

      // Check domain isn't already used by another app
      const existing = await env.DB.prepare(
        'SELECT subdomain FROM apps WHERE custom_domain = ? AND subdomain != ?'
      ).bind(custom_domain, subdomain).first();

      if (existing) {
        return new Response(JSON.stringify({ error: 'Domain is already in use by another app' }), { status: 400 });
      }

      // Update custom domain
      await env.DB.prepare(
        'UPDATE apps SET custom_domain = ? WHERE subdomain = ?'
      ).bind(custom_domain, subdomain).run();
    }
  }

  // Return updated settings
  const app = await env.DB.prepare(
    'SELECT subdomain, custom_domain, created_at FROM apps WHERE subdomain = ?'
  ).bind(subdomain).first();

  const branding = await getAppBranding(env, subdomain);

  return {
    success: true,
    subdomain: app.subdomain,
    custom_domain: app.custom_domain,
    branding,
  };
});

// GET /app/verify-domain - Check if custom domain DNS is configured correctly
router.get('/app/verify-domain', async (request, env) => {
  const user = await getSession(request, env);
  if (!user) {
    return new Response(JSON.stringify({ error: 'Not logged in' }), { status: 401 });
  }

  const subdomain = getSubdomain(request);
  if (!subdomain) {
    return new Response(JSON.stringify({ error: 'Invalid origin' }), { status: 400 });
  }

  const app = await env.DB.prepare(
    'SELECT custom_domain FROM apps WHERE subdomain = ?'
  ).bind(subdomain).first();

  if (!app?.custom_domain) {
    return { configured: false, error: 'No custom domain set' };
  }

  // Try to fetch the custom domain to verify it's pointing to us
  try {
    const res = await fetch(`https://${app.custom_domain}/_health`, {
      method: 'HEAD',
      headers: { 'User-Agent': 'itsalive-domain-check' },
    });
    // If we get any response, the domain is likely configured
    return {
      configured: true,
      domain: app.custom_domain,
      status: res.status,
    };
  } catch (e) {
    return {
      configured: false,
      domain: app.custom_domain,
      error: 'Domain not reachable - check DNS settings',
    };
  }
});

// ============ BRANDING ENDPOINTS ============

// GET /settings/branding - Get app branding settings
router.get('/settings/branding', async (request, env) => {
  const subdomain = getSubdomain(request);
  if (!subdomain) {
    return new Response(JSON.stringify({ error: 'Invalid origin' }), { status: 400 });
  }

  const branding = await getAppBranding(env, subdomain);
  return branding;
});

// PUT /settings/branding - Update app branding (deploy token or owner session)
router.put('/settings/branding', async (request, env) => {
  const body = await request.json();
  const { deploy_token, app_name, primary_color, button_color, tagline } = body;

  let subdomain;
  let authorized = false;

  // Option 1: Deploy token auth (for CLI/Claude)
  if (deploy_token) {
    const tokenData = await env.DB.prepare(
      'SELECT subdomain FROM deploy_tokens WHERE token = ?'
    ).bind(deploy_token).first();

    if (tokenData) {
      subdomain = tokenData.subdomain;
      authorized = true;
    }
  }

  // Option 2: Session auth (for browser)
  if (!authorized) {
    const user = await getSession(request, env);
    if (!user) {
      return new Response(JSON.stringify({ error: 'Not logged in or invalid deploy token' }), { status: 401 });
    }

    subdomain = getSubdomain(request);
    if (!subdomain) {
      return new Response(JSON.stringify({ error: 'Invalid origin' }), { status: 400 });
    }

    // Check if user is app owner
    if (!await isAppOwner(env, subdomain, user.email)) {
      return new Response(JSON.stringify({ error: 'Only the app owner can change branding' }), { status: 403 });
    }
    authorized = true;
  }

  if (!authorized) {
    return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 });
  }

  // Validate colors if provided
  const hexColorRegex = /^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$/;
  if (primary_color && !hexColorRegex.test(primary_color)) {
    return new Response(JSON.stringify({ error: 'primary_color must be a valid hex color (e.g., #00d4ff)' }), { status: 400 });
  }
  if (button_color && !hexColorRegex.test(button_color)) {
    return new Response(JSON.stringify({ error: 'button_color must be a valid hex color (e.g., #ffffff)' }), { status: 400 });
  }

  // Upsert branding settings
  await env.DB.prepare(`
    INSERT INTO app_settings (app_subdomain, email_app_name, email_primary_color, email_button_color, email_tagline, branding_configured, updated_at)
    VALUES (?, ?, ?, ?, ?, TRUE, datetime("now"))
    ON CONFLICT(app_subdomain) DO UPDATE SET
      email_app_name = COALESCE(excluded.email_app_name, email_app_name),
      email_primary_color = COALESCE(excluded.email_primary_color, email_primary_color),
      email_button_color = COALESCE(excluded.email_button_color, email_button_color),
      email_tagline = COALESCE(excluded.email_tagline, email_tagline),
      branding_configured = TRUE,
      updated_at = datetime("now")
  `).bind(
    subdomain,
    app_name || null,
    primary_color || null,
    button_color || null,
    tagline || null
  ).run();

  const branding = await getAppBranding(env, subdomain);
  return { success: true, branding };
});

// ============ DOCS ENDPOINTS ============

// GET /docs/itsalive-md - Returns ITSALIVE.md template for CLI
router.get('/docs/itsalive-md', async (request, env) => {
  const template = `## Instructions for Claude

### Re-read After Deploy
**IMPORTANT:** After every deploy (running \`npx itsalive\`), you MUST re-read this ITSALIVE.md file completely. The itsalive platform is actively improved with new features, APIs, and capabilities. When reviewing:

1. **Check for new features** - Look for endpoints or capabilities that could improve the app
2. **Look for better patterns** - New documentation may show simpler ways to do things
3. **Consider implementing upgrades** - If a new feature would benefit users (e.g., file uploads, email notifications, real-time updates), proactively suggest or implement it
4. **Report any issues** - If something doesn't work as documented, report it via the bug reporting endpoint

Think of each deploy as an opportunity to level up the app with new platform capabilities.

### Required: Powered by Footer (Free Accounts)
All free tier apps must include a "Powered by" attribution in the footer of every page:

\`\`\`html
<footer style="text-align: center; padding: 2rem; font-size: 0.85rem;">
  <a href="https://itsalive.co?ref=SUBDOMAIN" style="text-decoration: none;">
    Powered by itsalive.co
  </a>
</footer>
\`\`\`

**Customization:** You may adjust colors to match the site design, but the footer must remain clearly visible and readable. Replace \`SUBDOMAIN\` with the app's subdomain from the \`.itsalive\` file.

## Reporting Bugs and Feedback to itsalive

itsalive improves through feedback from Claude Code instances. **You are encouraged to automatically report bugs and suggestions as you encounter them.**

### Report a bug
\`\`\`javascript
await fetch('/_itsalive/bugs', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    title: 'Brief description of the bug',
    description: 'Detailed explanation of what went wrong',
    code_context: '// The code that triggered the bug',
    error_message: 'Any error message received',
    severity: 'medium'  // 'low', 'medium', 'high', 'critical'
  })
});
\`\`\`

### Submit feedback
\`\`\`javascript
await fetch('/_itsalive/feedback', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    category: 'feature',  // 'feature', 'improvement', 'documentation', 'other'
    title: 'Brief title',
    description: 'Detailed description',
    use_case: 'Why this would be useful',
    priority_suggestion: 'important'
  })
});
\`\`\`

**Best practices:** Report bugs immediately when encountered. Submit feedback when you wish for a feature.

## Configuring Collection Settings (for Claude)

Claude can configure collections automatically using the deploy token from the \`.itsalive\` file.

\`\`\`javascript
// Read .itsalive file to get deploy token
const config = JSON.parse(require('fs').readFileSync('.itsalive', 'utf8'));

// Configure collection settings using deploy token (no user login needed)
await fetch('https://api.itsalive.co/db/completions/_settings', {
  method: 'PUT',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    public_read: true,  // Make collection publicly readable
    deploy_token: config.deployToken
  })
});
\`\`\`

## Authentication

### Login
\`\`\`javascript
const res = await fetch('/_auth/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  credentials: 'include',
  body: JSON.stringify({ email: userEmail })
});
// Sends magic link, returns { success: true }
\`\`\`

### Check if logged in
\`\`\`javascript
const res = await fetch('/_auth/me', { credentials: 'include' });
if (res.ok) {
  const { user } = await res.json(); // { id, email }
}
\`\`\`

### Logout
\`\`\`javascript
await fetch('/_auth/logout', { method: 'POST', credentials: 'include' });
\`\`\`

## Database

Shared app data. Organized by collections.

### Permissions
- **Write**: Login required by default. Enable \`public_write\` for anonymous submissions.
- **Ownership**: Users can only edit/delete docs they created
- **Read**: Private by default. Enable \`public_read\` for public access.
- **Delete**: Always requires login and ownership (never anonymous)
- **Deploy token**: Bypasses all restrictions for automation scripts

### Save data with deploy_token (for automation)
\`\`\`javascript
// Use deploy_token for scripts that need to write without browser auth
const config = JSON.parse(require('fs').readFileSync('.itsalive', 'utf8'));

await fetch('https://api.itsalive.co/db/recipes/my-recipe', {
  method: 'PUT',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    title: 'Updated Recipe',
    image: 'https://...',
    deploy_token: config.deployToken  // Include in body
  })
});

// Bulk update with deploy_token
await fetch('https://api.itsalive.co/db/recipes/_bulk', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    deploy_token: config.deployToken,
    docs: [
      { id: 'recipe-1', data: { title: 'Recipe 1', image: '...' } },
      { id: 'recipe-2', data: { title: 'Recipe 2', image: '...' } }
    ]
  })
});

// Partial update with merge (preserves existing fields)
await fetch('https://api.itsalive.co/db/recipes/_bulk', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    deploy_token: config.deployToken,
    merge: true,  // Only updates specified fields, keeps the rest
    docs: [
      { id: 'recipe-1', data: { image: 'new.png' } }  // title, ingredients etc preserved
    ]
  })
});
\`\`\`

### Save data
\`\`\`javascript
await fetch('/_db/{collection}/{id}', {
  method: 'PUT',
  headers: { 'Content-Type': 'application/json' },
  credentials: 'include',
  body: JSON.stringify({ title: 'Hello', done: false })
});
\`\`\`

### Save data with location (for geo queries)
\`\`\`javascript
// Include lat/lng fields to enable location queries
await fetch('/_db/venues/venue123', {
  method: 'PUT',
  headers: { 'Content-Type': 'application/json' },
  credentials: 'include',
  body: JSON.stringify({
    name: 'Coffee Shop',
    lat: 37.7749,
    lng: -122.4194
  })
});
\`\`\`

### Get single document
\`\`\`javascript
const res = await fetch('/_db/{collection}/{id}', { credentials: 'include' });
const data = await res.json();
\`\`\`

### List collection with filtering, sorting, pagination
\`\`\`javascript
// Basic list (newest first by default)
const res = await fetch('/_db/{collection}', { credentials: 'include' });
const { items, total, limit, offset } = await res.json();

// Filter by field value
await fetch('/_db/posts?status=published')

// Get only current user's documents
await fetch('/_db/completions?mine=true', { credentials: 'include' })

// Sort by field (prefix with - for descending)
await fetch('/_db/posts?sort=-created_at')
await fetch('/_db/posts?sort=title')

// Pagination
await fetch('/_db/posts?limit=10&offset=20')

// Combine filters
await fetch('/_db/posts?status=published&sort=-created_at&limit=10')
\`\`\`

### Batch read (up to 100 IDs)
\`\`\`javascript
// Fetch multiple documents by ID in one request
const res = await fetch('/_db/posts?id=abc,def,ghi', { credentials: 'include' });
const { items } = await res.json();
// Returns items in same order as requested IDs
\`\`\`

### Location queries
\`\`\`javascript
// Find documents near a location (requires lat/lng in saved docs)
const res = await fetch('/_db/venues?near=37.77,-122.42&radius=10mi');
const { items, center, radius_km } = await res.json();
// Items sorted by distance, includes _meta.distance_km

// Radius can be in miles (mi) or kilometers (km, default)
await fetch('/_db/venues?near=37.77,-122.42&radius=25km')
\`\`\`

### Aggregation queries
\`\`\`javascript
// Get count with optional filters
const { count } = await fetch('/_db/posts/_count?status=published').then(r => r.json());

// Get statistics with grouping
const stats = await fetch('/_db/posts/_stats?group=status').then(r => r.json());
// { total: 150, oldest: '2024-01-01', newest: '2024-06-15', groups: [{value: 'draft', count: 50}, ...] }
\`\`\`

### Delete (must be creator)
\`\`\`javascript
await fetch('/_db/{collection}/{id}', { method: 'DELETE', credentials: 'include' });
\`\`\`

### Bulk create/update (up to 100 docs)
\`\`\`javascript
const res = await fetch('/_db/{collection}/_bulk', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  credentials: 'include',
  body: JSON.stringify({
    docs: [
      { id: 'doc1', data: { title: 'First' } },
      { id: 'doc2', data: { title: 'Second' } }
    ]
  })
});
const { results, succeeded, failed } = await res.json();
\`\`\`

### Collection Settings

Configure collection visibility, write access, and validation. Use deploy token (for Claude) or session auth (for browser).

\`\`\`javascript
// Using deploy token (Claude can do this directly)
const config = JSON.parse(require('fs').readFileSync('.itsalive', 'utf8'));
await fetch('https://api.itsalive.co/db/{collection}/_settings', {
  method: 'PUT',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    public_read: true,   // Anyone can read without login
    public_write: true,  // Anyone can write without login
    schema: {
      title: { type: 'string', required: true, maxLength: 100 },
      score: { type: 'number', min: 0 },
      status: { type: 'string', enum: ['draft', 'published'] }
    },
    deploy_token: config.deployToken
  })
});

// Check settings
const res = await fetch('/_db/{collection}/_settings');
const { public_read, public_write, schema } = await res.json();
\`\`\`

Schema validation rules:
- \`type\`: 'string', 'number', 'boolean', 'array', 'object'
- \`required\`: true/false
- \`minLength\`, \`maxLength\`: for strings
- \`min\`, \`max\`: for numbers
- \`pattern\`: 'email' or 'url' for strings
- \`enum\`: array of allowed values
- \`minItems\`, \`maxItems\`: for arrays

## File Uploads

Allow your users to upload images and files.

### Upload a file (requires login)
\`\`\`javascript
const formData = new FormData();
formData.append('file', fileInput.files[0]);

const res = await fetch('/_uploads', {
  method: 'POST',
  credentials: 'include',
  body: formData
});
const { id, url, filename, content_type, size } = await res.json();
// url: "https://myapp.itsalive.co/uploads/user123/abc456.jpg"
\`\`\`

### Upload with privacy setting
\`\`\`javascript
formData.append('public', 'false');  // Only uploader can access
\`\`\`

### List user's uploads
\`\`\`javascript
const { items } = await fetch('/_uploads?limit=20', {
  credentials: 'include'
}).then(r => r.json());
\`\`\`

### Delete an upload
\`\`\`javascript
await fetch('/_uploads/abc456', { method: 'DELETE', credentials: 'include' });
\`\`\`

### Supported formats
- Images: JPEG, PNG, GIF, WebP, SVG (max 10MB)
- Documents: PDF (max 25MB), TXT, CSV

## Image Optimization

Serve optimized, resized images on-the-fly with edge caching. Perfect for responsive images and faster mobile loading.

### Basic usage
\`\`\`html
<!-- Original upload -->
<img src="/uploads/user123/photo.jpg">

<!-- Optimized: 400px wide, WebP format, 80% quality -->
<img src="/_images/user123/photo.jpg?w=400&q=80&f=webp">
\`\`\`

### Parameters
| Param | Description | Default |
|-------|-------------|---------|
| \`w\` or \`width\` | Target width (1-4000px) | original |
| \`h\` or \`height\` | Target height (1-4000px) | original |
| \`q\` or \`quality\` | Compression quality (1-100) | 80 |
| \`f\` or \`format\` | Output format: \`webp\`, \`avif\`, \`jpeg\`, \`png\`, \`auto\` | webp |
| \`fit\` | Resize mode: \`cover\`, \`contain\`, \`scale-down\`, \`crop\` | scale-down |

### Responsive images with srcset
\`\`\`html
<img
  src="/_images/user123/photo.jpg?w=800&f=webp"
  srcset="
    /_images/user123/photo.jpg?w=400&f=webp 400w,
    /_images/user123/photo.jpg?w=800&f=webp 800w,
    /_images/user123/photo.jpg?w=1200&f=webp 1200w
  "
  sizes="(max-width: 600px) 400px, (max-width: 1000px) 800px, 1200px"
>
\`\`\`

### Auto format (serves best format for browser)
\`\`\`html
<!-- Serves AVIF to Chrome, WebP to Safari, JPEG to older browsers -->
<img src="/_images/user123/photo.jpg?w=600&f=auto">
\`\`\`

### Thumbnail grid example
\`\`\`javascript
const thumbnails = images.map(img =>
  \`<img src="/_images/\${img.path}?w=200&h=200&fit=cover&q=75">\`
).join('');
\`\`\`

### Performance notes
- Transformed images are cached at the edge for 1 year
- First request transforms the image; subsequent requests are instant
- Original images remain unchanged in storage

## Email Sending

Send transactional emails, updates, and newsletters to your users.

### Send a single email
\`\`\`javascript
await fetch('/_email/send', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  credentials: 'include',
  body: JSON.stringify({
    to: 'user@example.com',
    subject: 'Your order has shipped!',
    html: '<h1>Good news!</h1><p>Your order #123 is on its way.</p>'
  })
});
\`\`\`

### Using deploy token (for automated/backend sends)
\`\`\`javascript
const config = JSON.parse(require('fs').readFileSync('.itsalive', 'utf8'));
await fetch('https://api.itsalive.co/email/send', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    deploy_token: config.deployToken,
    to: 'user@example.com',
    subject: 'Weekly digest',
    html: '<p>Here is what happened this week...</p>'
  })
});
\`\`\`

### Create reusable email templates
\`\`\`javascript
// Save a template
await fetch('/_email/templates/welcome', {
  method: 'PUT',
  headers: { 'Content-Type': 'application/json' },
  credentials: 'include',
  body: JSON.stringify({
    subject: 'Welcome to {{app_name}}!',
    html_body: '<h1>Hi {{name}}!</h1><p>Thanks for joining {{app_name}}.</p>'
  })
});

// Use the template
await fetch('/_email/send', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  credentials: 'include',
  body: JSON.stringify({
    to: 'newuser@example.com',
    subject: 'Welcome!',
    template: 'welcome',
    template_data: { name: 'Alice', app_name: 'My App' }
  })
});
\`\`\`

### Send bulk emails (up to 100 recipients)
\`\`\`javascript
await fetch('/_email/send-bulk', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  credentials: 'include',
  body: JSON.stringify({
    recipients: [
      { email: 'user1@example.com', name: 'Alice' },
      { email: 'user2@example.com', name: 'Bob' }
    ],
    subject: 'Weekly Newsletter',
    template: 'newsletter',
    template_data: { week: 'Jan 15-21' }
  })
});
\`\`\`

Emails are sent from noreply@itsalive.co with your app's branding applied automatically.

## User-Private Data

Data only the logged-in user can see.

\`\`\`javascript
// Save
await fetch('/_me/{key}', {
  method: 'PUT',
  headers: { 'Content-Type': 'application/json' },
  credentials: 'include',
  body: JSON.stringify({ theme: 'dark' })
});

// Read
const res = await fetch('/_me/{key}', { credentials: 'include' });
\`\`\`

## Dynamic OG Images

Generate Open Graph images dynamically for social sharing.

\`\`\`html
<!-- Add to your HTML head -->
<meta property="og:image" content="/_og?title=My Page Title&description=A brief description&theme=dark" />
\`\`\`

Parameters:
- \`title\`: Main text (max 40 chars shown)
- \`description\`: Secondary text (max 80 chars)
- \`theme\`: 'dark' (default) or 'light'

## Location API

Convert city strings to normalized locations with coordinates.

\`\`\`javascript
const res = await fetch('https://api.itsalive.co/location', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  credentials: 'include',
  body: JSON.stringify({ city: 'san francisco' })
});
const location = await res.json();
// { city: "San Francisco", normalized: "San Francisco, California, United States",
//   lat: 37.7790262, lng: -122.4199061, country: "United States", state: "California" }
\`\`\`

## Email Branding (Initial Setup)

Configure how login emails look for your app. Claude should do this once during initial setup.

\`\`\`javascript
const config = JSON.parse(require('fs').readFileSync('.itsalive', 'utf8'));

await fetch('https://api.itsalive.co/settings/branding', {
  method: 'PUT',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    app_name: 'My App',
    primary_color: '#00d4ff',
    button_color: '#ffffff',
    tagline: 'Your tagline here',
    deploy_token: config.deployToken
  })
});
\`\`\`

## Common Patterns

### Public leaderboard with location
\`\`\`javascript
// Setup: make leaderboard public
const config = JSON.parse(require('fs').readFileSync('.itsalive', 'utf8'));
await fetch('https://api.itsalive.co/db/leaderboard/_settings', {
  method: 'PUT',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ public_read: true, deploy_token: config.deployToken })
});

// Query: top 10 nearest players
const { items } = await fetch('/_db/leaderboard?near=37.77,-122.42&radius=50mi&limit=10')
  .then(r => r.json());
\`\`\`

### Anonymous RSVP with email confirmation
\`\`\`javascript
// Setup
await fetch('https://api.itsalive.co/db/rsvps/_settings', {
  method: 'PUT',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    public_read: true, public_write: true,
    schema: { name: { type: 'string', required: true }, email: { type: 'string', required: true, pattern: 'email' } },
    deploy_token: config.deployToken
  })
});

// Submit and send confirmation (owner must be logged in for email)
const rsvp = { name: 'Jane', email: 'jane@example.com', attending: true };
await fetch('/_db/rsvps/guest-' + Date.now(), {
  method: 'PUT',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(rsvp)
});
\`\`\`

## AI Integration

Access AI models (Claude, GPT, Gemini) through the itsalive proxy. Apps use prepaid token credits.

### Model Tiers
- **good**: Cost-effective models for most tasks (Claude Sonnet, GPT-4o-mini, Gemini Flash)
- **best**: Most capable models for complex tasks (Claude Opus, GPT-4o, Gemini Pro)

### Send a chat request
\`\`\`javascript
const res = await fetch('/_ai/chat', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  credentials: 'include',  // or use deploy_token
  body: JSON.stringify({
    provider: 'claude',     // 'claude', 'gpt', or 'gemini'
    tier: 'good',           // 'good' or 'best'
    messages: [
      { role: 'user', content: 'What is the capital of France?' }
    ],
    system: 'You are a helpful assistant.',  // optional
    max_tokens: 1024  // optional, default from app settings
  })
});
const { content, usage } = await res.json();
// content: "The capital of France is Paris."
// usage: { input_tokens: 15, output_tokens: 12, total_tokens: 27 }
\`\`\`

### JSON Response Format
When requesting structured JSON data, use \`response_format: 'json'\` to automatically strip markdown code blocks:

\`\`\`javascript
const res = await fetch('/_ai/chat', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  credentials: 'include',
  body: JSON.stringify({
    provider: 'claude',
    tier: 'good',
    response_format: 'json',  // Strips \\\`\\\`\\\`json blocks automatically
    messages: [
      { role: 'user', content: 'Return a JSON object with fields: name, age, city' }
    ]
  })
});
const { content } = await res.json();
// content is clean JSON: {"name": "John", "age": 30, "city": "NYC"}
// Without response_format, it might be wrapped in \\\`\\\`\\\`json blocks
\`\`\`

### Send an image for analysis (vision)
\`\`\`javascript
const res = await fetch('/_ai/chat', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  credentials: 'include',
  body: JSON.stringify({
    provider: 'claude',
    tier: 'good',
    messages: [{
      role: 'user',
      content: [
        { type: 'text', text: 'What is in this image?' },
        { type: 'image', url: 'https://example.com/photo.jpg' }
        // or: { type: 'image', base64: '...', media_type: 'image/jpeg' }
      ]
    }]
  })
});
\`\`\`

### Check credit balance
\`\`\`javascript
const { balance, lifetime_used } = await fetch('/_ai/credits', {
  credentials: 'include'
}).then(r => r.json());
\`\`\`

### Add credits (owner only)
\`\`\`javascript
await fetch('/_ai/credits', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  credentials: 'include',
  body: JSON.stringify({ amount: 100000 })  // tokens
});
\`\`\`

### View usage history
\`\`\`javascript
const { items, totals } = await fetch('/_ai/usage', {
  credentials: 'include'
}).then(r => r.json());
// totals: { requests, input_tokens, output_tokens, total_tokens, estimated_cost }
\`\`\`

### Configure AI settings
\`\`\`javascript
await fetch('/_ai/settings', {
  method: 'PUT',
  headers: { 'Content-Type': 'application/json' },
  credentials: 'include',
  body: JSON.stringify({
    max_input_tokens: 8192,
    max_output_tokens: 4096,
    allowed_tiers: 'good,best',  // or just 'good'
    enabled: true
  })
});
\`\`\`

### Generate images with DALL-E
\`\`\`javascript
const res = await fetch('/_ai/image', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  credentials: 'include',
  body: JSON.stringify({
    prompt: 'A cute robot waving hello, digital art style',
    model: 'dall-e-3',         // 'dall-e-2' or 'dall-e-3'
    size: '1024x1024',         // dall-e-2: 256x256, 512x512, 1024x1024
                               // dall-e-3: 1024x1024, 1024x1792, 1792x1024
    quality: 'standard',       // dall-e-3 only: 'standard' or 'hd'
    n: 1                       // number of images (dall-e-3 max: 1, dall-e-2 max: 10)
  })
});
const { images, credits_used } = await res.json();
// images: [{ url: 'https://...', revised_prompt: '...' }]
\`\`\`

### Transcribe audio with Whisper
\`\`\`javascript
const formData = new FormData();
formData.append('file', audioFile);
formData.append('language', 'en');  // optional: ISO 639-1 code
formData.append('response_format', 'json');  // json, text, srt, vtt

const res = await fetch('/_ai/transcribe', {
  method: 'POST',
  credentials: 'include',
  body: formData
});
const { text, duration, credits_used } = await res.json();
\`\`\`

### Text-to-speech
\`\`\`javascript
const res = await fetch('/_ai/tts', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  credentials: 'include',
  body: JSON.stringify({
    input: 'Hello! This is a test of text to speech.',
    model: 'tts-1',            // 'tts-1' or 'tts-1-hd' (higher quality)
    voice: 'nova',             // alloy, echo, fable, onyx, nova, shimmer
    response_format: 'mp3',    // mp3, opus, aac, flac, wav, pcm
    speed: 1.0                 // 0.25 to 4.0
  })
});
// Response is audio binary
const audioBlob = await res.blob();
const audioUrl = URL.createObjectURL(audioBlob);
\`\`\`

### Credit costs
- **Chat (good tier)**: Claude ~75 tokens/credit, GPT ~1800/credit, Gemini ~1500/credit
- **Chat (best tier)**: Claude ~15 tokens/credit, GPT ~135/credit, Gemini ~100/credit
- **Image generation**: 20-150 credits per image depending on model/size/quality
- **Transcription**: ~10 credits per minute of audio
- **TTS**: ~20 credits per 1000 characters (40 for HD)

### Error handling
\`\`\`javascript
const res = await fetch('/_ai/chat', { ... });
if (res.status === 402) {
  const { balance, required } = await res.json();
  console.log('Insufficient credits. Balance:', balance, 'Required:', required);
}
\`\`\`

## Dynamic OG Tags (Social Sharing for SPAs)

SPAs with client-side routing can't have proper social sharing previews because crawlers don't execute JavaScript. Configure OG routes to inject dynamic meta tags based on your database content.

### How It Works
1. Configure URL patterns that map to database collections
2. When a crawler visits \`/recipe/abc123\`, the server matches the pattern, fetches the document, and injects og:title, og:description, og:image into the HTML

### Configure OG Routes
\`\`\`javascript
const config = JSON.parse(require('fs').readFileSync('.itsalive', 'utf8'));

await fetch('/_og/routes', {
  method: 'PUT',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    deploy_token: config.deployToken,
    routes: [
      {
        pattern: '/recipe/:id',        // URL pattern with :param placeholders
        collection: 'recipes',         // Database collection to query
        id_param: 'id',                // URL param for document ID (default: 'id')
        title_field: 'title',          // Document field for og:title
        description_field: 'description',
        image_field: 'image_url'
      }
    ]
  })
});
\`\`\`

### List OG Routes
\`\`\`javascript
const { routes } = await fetch('/_og/routes').then(r => r.json());
\`\`\`

### Clear OG Routes
\`\`\`javascript
await fetch('/_og/routes', {
  method: 'DELETE',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ deploy_token: config.deployToken })
});
\`\`\`

### OG Route Parameters
| Field | Required | Description |
|-------|----------|-------------|
| \`pattern\` | Yes | URL pattern with \`:param\` placeholders (e.g., \`/recipe/:id\`) |
| \`collection\` | Yes | Database collection to fetch document from |
| \`id_param\` | No | URL param name for document ID (default: \`'id'\`) |
| \`title_field\` | No | Document field for og:title |
| \`description_field\` | No | Document field for og:description |
| \`image_field\` | No | Document field for og:image |
`;

  return new Response(template, {
    headers: { 'content-type': 'text/plain' }
  });
});

// ============ DEPLOY ENDPOINTS ============

// POST /check-subdomain - Check if subdomain is available
router.post('/check-subdomain', async (request, env) => {
  const { subdomain, email } = await request.json();

  // Validate subdomain format
  if (!/^[a-z0-9-]+$/.test(subdomain) || subdomain.length < 3 || subdomain.length > 30) {
    return { available: false, reason: 'invalid' };
  }

  // Check reserved subdomains
  const reserved = ['api', 'www', 'admin', 'app', 'dashboard', 'mail', 'smtp', 'fallback'];
  if (reserved.includes(subdomain)) {
    return { available: false, reason: 'reserved' };
  }

  // Reserve -stg suffix for staging environments
  if (subdomain.endsWith('-stg')) {
    return { available: false, reason: 'reserved' };
  }

  // Check if subdomain is taken by someone else
  const existingApp = await env.DB.prepare(
    'SELECT owner_id FROM apps WHERE subdomain = ?'
  ).bind(subdomain).first();

  if (existingApp) {
    const owner = await env.DB.prepare(
      'SELECT email FROM owners WHERE id = ?'
    ).bind(existingApp.owner_id).first();

    if (owner && owner.email !== email) {
      return { available: false, reason: 'taken' };
    }
  }

  return { available: true };
});

// POST /deploy/init - Start deployment, send verification email
router.post('/deploy/init', async (request, env) => {
  const { subdomain, email, files } = await request.json();

  // Validate subdomain format
  if (!/^[a-z0-9-]+$/.test(subdomain) || subdomain.length < 3 || subdomain.length > 30) {
    return { error: 'Invalid subdomain. Use 3-30 lowercase letters, numbers, or hyphens.' };
  }

  // Check reserved subdomains
  const reserved = ['api', 'www', 'admin', 'app', 'dashboard', 'mail', 'smtp', 'fallback'];
  if (reserved.includes(subdomain)) {
    return { error: 'This subdomain is reserved.' };
  }

  // Reserve -stg suffix for staging environments
  if (subdomain.endsWith('-stg')) {
    return { error: 'This subdomain is reserved for staging environments.' };
  }

  // Check if subdomain is taken by someone else
  const existingApp = await env.DB.prepare(
    'SELECT owner_id FROM apps WHERE subdomain = ?'
  ).bind(subdomain).first();

  if (existingApp) {
    const owner = await env.DB.prepare(
      'SELECT email FROM owners WHERE id = ?'
    ).bind(existingApp.owner_id).first();

    if (owner && owner.email !== email) {
      return { error: 'This subdomain is already taken.' };
    }
  }

  // Create pending deployment
  const deployId = generateId();
  const token = generateToken();
  const expiresAt = new Date(Date.now() + 30 * 60 * 1000).toISOString(); // 30 min

  await env.DB.prepare(
    'INSERT INTO pending_deploys (id, subdomain, email, token, files_manifest, expires_at) VALUES (?, ?, ?, ?, ?, ?)'
  ).bind(deployId, subdomain, email, token, JSON.stringify(files), expiresAt).run();

  // Send verification email
  const verifyUrl = `https://api.itsalive.co/verify?token=${token}`;
  await sendEmail(
    env,
    email,
    `Verify your deployment to ${subdomain}.itsalive.co`,
    emailTemplate({
      buttonText: 'Verify & Deploy',
      buttonUrl: verifyUrl,
      footer: 'This link expires in 30 minutes.',
      branding: {
        appName: `${subdomain}.itsalive.co`,
        tagline: 'Click below to verify your deployment',
      },
    })
  );

  return { deploy_id: deployId };
});

// GET /deploy/:id/status - Poll for verification status
router.get('/deploy/:id/status', async (request, env) => {
  const { id } = request.params;

  const pending = await env.DB.prepare(
    'SELECT * FROM pending_deploys WHERE id = ?'
  ).bind(id).first();

  if (!pending) {
    return { error: 'Deployment not found' };
  }

  // Check if verified (token cleared means verified)
  const verified = !pending.token;

  return { verified, subdomain: pending.subdomain };
});

// GET /preview/error/expired - Preview expired link error
router.get('/preview/error/expired', async (request, env) => {
  return new Response(errorPage({
    title: 'Link Expired',
    message: 'This verification link has expired. Please run npx itsalive-co again to get a new link.',
    icon: '&#9203;',
  }), { headers: { 'content-type': 'text/html' } });
});

// GET /preview/error/invalid - Preview invalid link error
router.get('/preview/error/invalid', async (request, env) => {
  return new Response(errorPage({
    title: 'Invalid Link',
    message: 'This verification link is invalid. Please try deploying again.',
  }), { headers: { 'content-type': 'text/html' } });
});

// GET /preview/email/deploy - Preview deploy verification email
router.get('/preview/email/deploy', async (request, env) => {
  return new Response(emailTemplate({
    buttonText: 'Verify & Deploy',
    buttonUrl: 'https://api.itsalive.co/verify?token=example',
    footer: 'This link expires in 30 minutes.',
    branding: {
      appName: 'my-awesome-app.itsalive.co',
      tagline: 'Click below to verify your deployment',
    },
  }), { headers: { 'content-type': 'text/html; charset=utf-8' } });
});

// GET /preview/email/login - Preview login email
router.get('/preview/email/login', async (request, env) => {
  return new Response(emailTemplate({
    buttonText: 'Log In',
    buttonUrl: 'https://api.itsalive.co/auth/verify?token=example',
    footer: 'This link expires in 10 minutes.',
    branding: {
      appName: 'My Awesome App',
      primaryColor: '#ff6b6b',
      tagline: 'Your productivity companion',
    },
  }), { headers: { 'content-type': 'text/html; charset=utf-8' } });
});

// GET /preview/email/welcome - Preview welcome email
router.get('/preview/email/welcome', async (request, env) => {
  const subdomain = 'my-awesome-app';
  const email = 'user@example.com';
  const welcomeEmailHtml = `
    <div style="font-family: system-ui, sans-serif; max-width: 600px; line-height: 1.6;">
      <h1 style="font-size: 32px; margin: 0 0 24px 0;">Your site is live! 🎉</h1>

      <p style="font-size: 18px; margin: 0 0 16px 0;">
        <a href="https://${subdomain}.itsalive.co" style="color: #00d4ff; font-weight: bold;">${subdomain}.itsalive.co</a> is now live on the internet.
      </p>

      <p style="margin: 0 0 16px 0;">
        We're so excited you're here! Honestly, we just launched itsalive.co and you're one of our earliest users. That means a lot to us.
      </p>

      <p style="margin: 0 0 24px 0;">
        If anything feels weird, confusing, or broken — or if you have ideas for how we could make this better — please just reply to this email. We read everything and we genuinely want to hear from you.
      </p>

      <div style="background: #f5f5f5; border-radius: 8px; padding: 20px; margin: 0 0 24px 0;">
        <h3 style="margin: 0 0 12px 0; font-size: 16px;">What's next?</h3>
        <p style="margin: 0 0 12px 0;">
          <strong>Dashboard:</strong> Manage your site at <a href="https://dashboard.itsalive.co" style="color: #00d4ff;">dashboard.itsalive.co</a><br>
          <small style="color: #666;">Log in with the same email you used to deploy (${email})</small>
        </p>
        <p style="margin: 0;">
          <strong>Re-deploy anytime:</strong> Just run <code style="background: #e0e0e0; padding: 2px 6px; border-radius: 4px;">npx itsalive</code> again in your project folder.
        </p>
      </div>

      <div style="background: linear-gradient(135deg, #00d4ff22, #ff00ff22); border-radius: 8px; padding: 20px; margin: 0 0 24px 0;">
        <h3 style="margin: 0 0 12px 0; font-size: 16px;">Upgrade to Pro</h3>
        <p style="margin: 0 0 8px 0;">
          With Pro you get AI credits, custom domains, custom email sending, and more. Check it out in your dashboard if you're curious!
        </p>
      </div>

      <p style="margin: 0 0 8px 0;">
        Thanks for building with us,
      </p>
      <p style="margin: 0; font-weight: bold;">
        Melih & Sam
      </p>
      <p style="margin: 8px 0 0 0; font-size: 14px; color: #666;">
        Founders, itsalive.co
      </p>
    </div>`;
  return new Response(welcomeEmailHtml, { headers: { 'content-type': 'text/html; charset=utf-8' } });
});

// POST /test/send-welcome - Send test welcome email (internal use only)
router.post('/test/send-welcome', async (request, env) => {
  const { to, subdomain } = await request.json();

  if (!to || !subdomain) {
    return new Response(JSON.stringify({ error: 'to and subdomain required' }), { status: 400 });
  }

  const welcomeEmailHtml = `
    <div style="font-family: system-ui, sans-serif; max-width: 600px; line-height: 1.6;">
      <h1 style="font-size: 32px; margin: 0 0 24px 0;">Your site is live! 🎉</h1>

      <p style="font-size: 18px; margin: 0 0 16px 0;">
        <a href="https://${subdomain}.itsalive.co" style="color: #00d4ff; font-weight: bold;">${subdomain}.itsalive.co</a> is now live on the internet.
      </p>

      <p style="margin: 0 0 16px 0;">
        We're so excited you're here! Honestly, we just launched itsalive.co and you're one of our earliest users. That means a lot to us.
      </p>

      <p style="margin: 0 0 24px 0;">
        If anything feels weird, confusing, or broken — or if you have ideas for how we could make this better — please just reply to this email. We read everything and we genuinely want to hear from you.
      </p>

      <div style="background: #f5f5f5; border-radius: 8px; padding: 20px; margin: 0 0 24px 0;">
        <h3 style="margin: 0 0 12px 0; font-size: 16px;">What's next?</h3>
        <p style="margin: 0 0 12px 0;">
          <strong>Dashboard:</strong> Manage your site at <a href="https://dashboard.itsalive.co" style="color: #00d4ff;">dashboard.itsalive.co</a><br>
          <small style="color: #666;">Log in with the same email you used to deploy (${to})</small>
        </p>
        <p style="margin: 0;">
          <strong>Re-deploy anytime:</strong> Just run <code style="background: #e0e0e0; padding: 2px 6px; border-radius: 4px;">npx itsalive</code> again in your project folder.
        </p>
      </div>

      <div style="background: linear-gradient(135deg, #00d4ff22, #ff00ff22); border-radius: 8px; padding: 20px; margin: 0 0 24px 0;">
        <h3 style="margin: 0 0 12px 0; font-size: 16px;">Upgrade to Pro</h3>
        <p style="margin: 0 0 8px 0;">
          With Pro you get AI credits, custom domains, custom email sending, and more. Check it out in your dashboard if you're curious!
        </p>
      </div>

      <p style="margin: 0 0 8px 0;">
        Thanks for building with us,
      </p>
      <p style="margin: 0; font-weight: bold;">
        Melih & Sam
      </p>
      <p style="margin: 8px 0 0 0; font-size: 14px; color: #666;">
        Founders, itsalive.co
      </p>
    </div>`;

  // Direct Resend API call for debugging
  const fromName = "Melih & Sam from itsalive.co";
  const replyTo = "sam@itsalive.co";
  const subject = `Your site is live: ${subdomain}.itsalive.co`;

  try {
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.RESEND_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: `${fromName} <noreply@itsalive.co>`,
        to,
        subject,
        html: welcomeEmailHtml,
        reply_to: replyTo,
      }),
    });

    const responseText = await res.text();
    let responseData;
    try {
      responseData = JSON.parse(responseText);
    } catch {
      responseData = responseText;
    }

    return {
      success: res.ok,
      status: res.status,
      to,
      subdomain,
      resend_response: responseData,
    };
  } catch (e) {
    return { success: false, error: e.message, to, subdomain };
  }
});

// GET /preview/verify - Preview verification page design
router.get('/preview/verify', async (request, env) => {
  const pending = { subdomain: 'my-awesome-app' };
  return new Response(`
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Email Verified - itsalive.co</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: system-ui, -apple-system, sans-serif;
      background: #0a0a0b;
      color: #fff;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      justify-content: center;
      align-items: center;
      padding: 2rem;
    }
    .card {
      background: rgba(255,255,255,0.02);
      border: 1px solid rgba(255,255,255,0.08);
      border-radius: 16px;
      padding: 3rem;
      text-align: center;
      max-width: 440px;
    }
    .icon {
      font-size: 4rem;
      margin-bottom: 1.5rem;
    }
    h1 {
      font-size: 1.75rem;
      font-weight: 700;
      margin-bottom: 0.75rem;
      background: linear-gradient(135deg, #00d4ff 0%, #7b2dff 50%, #ff2d7b 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
    }
    p {
      color: #888;
      line-height: 1.6;
    }
    .subdomain {
      display: inline-block;
      margin-top: 1.5rem;
      padding: 0.5rem 1rem;
      background: #1a1a1a;
      border-radius: 6px;
      font-family: 'SF Mono', Monaco, monospace;
      font-size: 0.9rem;
      color: #00d4ff;
      text-decoration: none;
      transition: background 0.2s;
    }
    .subdomain:hover {
      background: #252525;
    }
    .footer {
      margin-top: 2rem;
      color: #444;
      font-size: 0.85rem;
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">&#10003;</div>
    <h1>Email Verified!</h1>
    <p>You're all set. Return to your terminal to complete the deployment.</p>
    <a href="https://${pending.subdomain}.itsalive.co" class="subdomain">${pending.subdomain}.itsalive.co</a>
  </div>
  <p class="footer">itsalive.co</p>
</body>
</html>
  `, { headers: { 'content-type': 'text/html' } });
});

// GET /verify - Email click verification
router.get('/verify', async (request, env) => {
  const url = new URL(request.url);
  const token = url.searchParams.get('token');

  if (!token) {
    return new Response(errorPage({
      title: 'Invalid Link',
      message: 'This verification link is invalid. Please try deploying again.',
    }), { status: 400, headers: { 'content-type': 'text/html' } });
  }

  const pending = await env.DB.prepare(
    'SELECT * FROM pending_deploys WHERE token = ? AND expires_at > datetime("now")'
  ).bind(token).first();

  if (!pending) {
    return new Response(errorPage({
      title: 'Link Expired',
      message: 'This verification link has expired. Please run npx itsalive-co again to get a new link.',
      icon: '&#9203;',
    }), { status: 400, headers: { 'content-type': 'text/html' } });
  }

  // Mark as verified by clearing the token
  await env.DB.prepare(
    'UPDATE pending_deploys SET token = NULL WHERE id = ?'
  ).bind(pending.id).run();

  // Create or get owner
  let owner = await env.DB.prepare(
    'SELECT id FROM owners WHERE email = ?'
  ).bind(pending.email).first();

  if (!owner) {
    const ownerId = generateId();
    await env.DB.prepare(
      'INSERT INTO owners (id, email) VALUES (?, ?)'
    ).bind(ownerId, pending.email).run();
    owner = { id: ownerId };

    // Give new owners 2500 free credits
    const FREE_CREDITS = 2500;
    await env.DB.prepare(`
      INSERT INTO owner_credits (owner_id, balance, lifetime_purchased)
      VALUES (?, ?, ?)
    `).bind(ownerId, FREE_CREDITS, FREE_CREDITS).run();
  }

  // Create or update app
  await env.DB.prepare(
    'INSERT OR REPLACE INTO apps (subdomain, owner_id) VALUES (?, ?)'
  ).bind(pending.subdomain, owner.id).run();

  return new Response(`
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Email Verified - itsalive.co</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: system-ui, -apple-system, sans-serif;
      background: #0a0a0b;
      color: #fff;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      justify-content: center;
      align-items: center;
      padding: 2rem;
    }
    .card {
      background: rgba(255,255,255,0.02);
      border: 1px solid rgba(255,255,255,0.08);
      border-radius: 16px;
      padding: 3rem;
      text-align: center;
      max-width: 440px;
    }
    .icon {
      font-size: 4rem;
      margin-bottom: 1.5rem;
    }
    h1 {
      font-size: 1.75rem;
      font-weight: 700;
      margin-bottom: 0.75rem;
      background: linear-gradient(135deg, #00d4ff 0%, #7b2dff 50%, #ff2d7b 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
    }
    p {
      color: #888;
      line-height: 1.6;
    }
    .subdomain {
      display: inline-block;
      margin-top: 1.5rem;
      padding: 0.5rem 1rem;
      background: #1a1a1a;
      border-radius: 6px;
      font-family: 'SF Mono', Monaco, monospace;
      font-size: 0.9rem;
      color: #00d4ff;
      text-decoration: none;
      transition: background 0.2s;
    }
    .subdomain:hover {
      background: #252525;
    }
    .footer {
      margin-top: 2rem;
      color: #444;
      font-size: 0.85rem;
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">&#10003;</div>
    <h1>Email Verified!</h1>
    <p>You're all set. Return to your terminal to complete the deployment.</p>
    <a href="https://${pending.subdomain}.itsalive.co" class="subdomain">${pending.subdomain}.itsalive.co</a>
  </div>
  <p class="footer">itsalive.co</p>
</body>
</html>
  `, { headers: { 'content-type': 'text/html' } });
});

// POST /deploy/:id/upload-urls - Get presigned R2 upload URLs
router.post('/deploy/:id/upload-urls', async (request, env) => {
  const { id } = request.params;

  const pending = await env.DB.prepare(
    'SELECT * FROM pending_deploys WHERE id = ? AND token IS NULL'
  ).bind(id).first();

  if (!pending) {
    return { error: 'Deployment not found or not verified' };
  }

  const files = JSON.parse(pending.files_manifest || '[]');
  const urls = {};

  for (const file of files) {
    const key = `${pending.subdomain}/${file}`;
    // Generate presigned URL for upload
    const url = await env.SITES.createMultipartUpload(key);
    urls[file] = {
      key,
      // For simplicity, we'll use direct PUT with the worker as proxy
      upload_url: `https://api.itsalive.co/deploy/${id}/upload?file=${encodeURIComponent(file)}`,
    };
  }

  return { urls, subdomain: pending.subdomain };
});

// PUT /deploy/:id/upload - Upload a file (proxy to R2)
router.put('/deploy/:id/upload', async (request, env) => {
  const { id } = request.params;
  const url = new URL(request.url);
  const file = url.searchParams.get('file');

  const pending = await env.DB.prepare(
    'SELECT * FROM pending_deploys WHERE id = ? AND token IS NULL'
  ).bind(id).first();

  if (!pending) {
    return { error: 'Deployment not found or not verified' };
  }

  const key = `${pending.subdomain}/${file}`;
  await env.SITES.put(key, request.body);

  return { success: true, key };
});

// POST /deploy/:id/finalize - Mark deployment complete
router.post('/deploy/:id/finalize', async (request, env) => {
  const { id } = request.params;

  const pending = await env.DB.prepare(
    'SELECT * FROM pending_deploys WHERE id = ? AND token IS NULL'
  ).bind(id).first();

  if (!pending) {
    return { error: 'Deployment not found or not verified' };
  }

  // Create deploy token for future deploys
  const deployToken = generateToken();
  await env.DB.prepare(
    'INSERT OR REPLACE INTO deploy_tokens (token, subdomain, email) VALUES (?, ?, ?)'
  ).bind(deployToken, pending.subdomain, pending.email).run();

  // Clean up pending deployment
  await env.DB.prepare(
    'DELETE FROM pending_deploys WHERE id = ?'
  ).bind(id).run();

  // Notify about new site launch (internal)
  const filesManifest = pending.files_manifest ? JSON.parse(pending.files_manifest) : [];
  const launchEmailHtml = `
    <div style="font-family: system-ui, sans-serif; max-width: 500px;">
      <h1 style="font-size: 48px; margin: 0 0 20px 0;">🎉🚀🎊</h1>
      <h2 style="margin: 0 0 20px 0; color: #00d4ff;">IT'S ALIVE!</h2>
      <p style="font-size: 18px; margin: 0 0 24px 0;">A brand new site just launched into the world!</p>
      <p style="font-size: 24px; margin: 0 0 24px 0;">
        <a href="https://${pending.subdomain}.itsalive.co" style="color: #00d4ff; font-weight: bold;">${pending.subdomain}.itsalive.co</a>
      </p>
      <p style="color: #666; margin: 0;">
        <strong>Creator:</strong> ${pending.email}<br>
        <strong>Files deployed:</strong> ${filesManifest.length}
      </p>
    </div>`;

  // Welcome email to the user
  const welcomeEmailHtml = `
    <div style="font-family: system-ui, sans-serif; max-width: 600px; line-height: 1.6;">
      <h1 style="font-size: 32px; margin: 0 0 24px 0;">Your site is live! 🎉</h1>

      <p style="font-size: 18px; margin: 0 0 16px 0;">
        <a href="https://${pending.subdomain}.itsalive.co" style="color: #00d4ff; font-weight: bold;">${pending.subdomain}.itsalive.co</a> is now live on the internet.
      </p>

      <p style="margin: 0 0 16px 0;">
        We're so excited you're here! Honestly, we just launched itsalive.co and you're one of our earliest users. That means a lot to us.
      </p>

      <p style="margin: 0 0 24px 0;">
        If anything feels weird, confusing, or broken — or if you have ideas for how we could make this better — please just reply to this email. We read everything and we genuinely want to hear from you.
      </p>

      <div style="background: #f5f5f5; border-radius: 8px; padding: 20px; margin: 0 0 24px 0;">
        <h3 style="margin: 0 0 12px 0; font-size: 16px;">What's next?</h3>
        <p style="margin: 0 0 12px 0;">
          <strong>Dashboard:</strong> Manage your site at <a href="https://dashboard.itsalive.co" style="color: #00d4ff;">dashboard.itsalive.co</a><br>
          <small style="color: #666;">Log in with the same email you used to deploy (${pending.email})</small>
        </p>
        <p style="margin: 0;">
          <strong>Re-deploy anytime:</strong> Just run <code style="background: #e0e0e0; padding: 2px 6px; border-radius: 4px;">npx itsalive</code> again in your project folder.
        </p>
      </div>

      <div style="background: linear-gradient(135deg, #00d4ff22, #ff00ff22); border-radius: 8px; padding: 20px; margin: 0 0 24px 0;">
        <h3 style="margin: 0 0 12px 0; font-size: 16px;">Upgrade to Pro</h3>
        <p style="margin: 0 0 8px 0;">
          With Pro you get AI credits, custom domains, custom email sending, and more. Check it out in your dashboard if you're curious!
        </p>
      </div>

      <p style="margin: 0 0 8px 0;">
        Thanks for building with us,
      </p>
      <p style="margin: 0; font-weight: bold;">
        Melih & Sam
      </p>
      <p style="margin: 8px 0 0 0; font-size: 14px; color: #666;">
        Founders, itsalive.co
      </p>
    </div>`;

  await Promise.all([
    sendEmail(env, 'sam@itsalive.co', `New site launched: ${pending.subdomain}.itsalive.co`, launchEmailHtml),
    sendEmail(env, 'melih@itsalive.co', `New site launched: ${pending.subdomain}.itsalive.co`, launchEmailHtml),
    sendEmail(env, pending.email, `Your site is live: ${pending.subdomain}.itsalive.co`, welcomeEmailHtml, {
      fromName: "Melih & Sam from itsalive.co",
      replyTo: "sam@itsalive.co"
    }),
  ]);

  return {
    success: true,
    url: `https://${pending.subdomain}.itsalive.co`,
    deployToken,
    subdomain: pending.subdomain,
    email: pending.email,
  };
});

// POST /push - Push update using deploy token (no email verification needed)
router.post('/push', async (request, env) => {
  const { deployToken, files } = await request.json();

  if (!deployToken) {
    return { error: 'Deploy token required' };
  }

  const tokenData = await env.DB.prepare(
    'SELECT * FROM deploy_tokens WHERE token = ?'
  ).bind(deployToken).first();

  if (!tokenData) {
    return { error: 'Invalid deploy token' };
  }

  return {
    success: true,
    subdomain: tokenData.subdomain,
    email: tokenData.email,
    domain: `${tokenData.subdomain}.itsalive.co`,
  };
});

// PUT /push/upload - Upload file using deploy token
router.put('/push/upload', async (request, env) => {
  const url = new URL(request.url);
  const deployToken = url.searchParams.get('token');
  const file = url.searchParams.get('file');

  if (!deployToken) {
    return { error: 'Deploy token required' };
  }

  const tokenData = await env.DB.prepare(
    'SELECT * FROM deploy_tokens WHERE token = ?'
  ).bind(deployToken).first();

  if (!tokenData) {
    return { error: 'Invalid deploy token' };
  }

  const key = `${tokenData.subdomain}/${file}`;
  await env.SITES.put(key, request.body);

  return { success: true, key };
});

// ============ AUTH ENDPOINTS ============

// POST /auth/login - Send magic link
router.post('/auth/login', async (request, env) => {
  const { email } = await request.json();
  const subdomain = getSubdomain(request);
  const customDomain = request.customDomain || null;

  if (!subdomain) {
    return { error: 'Invalid origin' };
  }

  // Check if app exists
  const app = await env.DB.prepare(
    'SELECT subdomain FROM apps WHERE subdomain = ?'
  ).bind(subdomain).first();

  if (!app) {
    return { error: 'App not found' };
  }

  // Generate login token - include custom domain if present
  const token = generateToken();
  await env.EMAIL_TOKENS.put(`login:${token}`, JSON.stringify({
    email,
    subdomain,
    customDomain, // Store custom domain for cookie setting
  }), {
    expirationTtl: 600, // 10 minutes
  });

  // Determine display domain for email
  const displayDomain = customDomain || `${subdomain}.itsalive.co`;

  // Get app branding
  const branding = await getAppBranding(env, subdomain);

  // Send magic link
  const loginUrl = `https://api.itsalive.co/auth/verify?token=${token}`;
  const emailSent = await sendEmail(
    env,
    email,
    `Login to ${branding.appName}`,
    emailTemplate({
      buttonText: 'Log In',
      buttonUrl: loginUrl,
      footer: 'This link expires in 10 minutes.',
      branding,
    }),
    branding.appName
  );

  if (!emailSent) {
    return new Response(JSON.stringify({ error: 'Failed to send email' }), { status: 500 });
  }

  return { success: true };
});

// GET /auth/verify - Magic link verification
router.get('/auth/verify', async (request, env) => {
  const url = new URL(request.url);
  const token = url.searchParams.get('token');

  if (!token) {
    return new Response(errorPage({
      title: 'Invalid Link',
      message: 'This login link is invalid. Please request a new one.',
    }), { status: 400, headers: { 'content-type': 'text/html' } });
  }

  const data = await env.EMAIL_TOKENS.get(`login:${token}`);
  if (!data) {
    return new Response(errorPage({
      title: 'Link Expired',
      message: 'This login link has expired. Please request a new one from the app.',
      icon: '&#9203;',
    }), { status: 400, headers: { 'content-type': 'text/html' } });
  }

  const { email, subdomain, customDomain } = JSON.parse(data);

  // Delete used token
  await env.EMAIL_TOKENS.delete(`login:${token}`);

  // Create or get user
  let user = await env.DB.prepare(
    'SELECT id FROM app_users WHERE app_subdomain = ? AND email = ?'
  ).bind(subdomain, email).first();

  if (!user) {
    const userId = generateId();
    await env.DB.prepare(
      'INSERT INTO app_users (id, app_subdomain, email) VALUES (?, ?, ?)'
    ).bind(userId, subdomain, email).run();
    user = { id: userId };
  }

  // Create session
  const sessionToken = generateToken();
  const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(); // 30 days

  await env.DB.prepare(
    'INSERT INTO sessions (token, app_subdomain, user_id, expires_at) VALUES (?, ?, ?, ?)'
  ).bind(sessionToken, subdomain, user.id, expiresAt).run();

  if (customDomain) {
    // Custom domain: can't set cookie from api.itsalive.co for another domain
    // Store session token temporarily and redirect to custom domain's callback
    const callbackToken = generateToken();
    await env.EMAIL_TOKENS.put(`callback:${callbackToken}`, sessionToken, { expirationTtl: 60 }); // 1 minute TTL

    return new Response(null, {
      status: 302,
      headers: {
        'Location': `https://${customDomain}/_auth/callback?token=${callbackToken}`,
      },
    });
  } else {
    // itsalive.co subdomain: set cookie for .itsalive.co (same parent domain)
    const redirectUrl = `https://${subdomain}.itsalive.co`;
    const cookieHeader = `itsalive_session=${sessionToken}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${30 * 24 * 60 * 60}; Domain=.itsalive.co`;

    return new Response(null, {
      status: 302,
      headers: {
        'Location': redirectUrl,
        'Set-Cookie': cookieHeader,
      },
    });
  }
});

// GET /auth/me - Check if logged in
router.get('/auth/me', async (request, env) => {
  const user = await getSession(request, env);

  if (!user) {
    return new Response(JSON.stringify({ error: 'Not logged in' }), { status: 401 });
  }

  return { user: { id: user.id, email: user.email } };
});

// POST /auth/logout - Logout
router.post('/auth/logout', async (request, env) => {
  const cookie = request.headers.get('cookie') || '';
  const match = cookie.match(/itsalive_session=([^;]+)/);

  if (match) {
    const token = match[1];
    await env.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run();
  }

  return new Response(JSON.stringify({ success: true }), {
    headers: {
      'Set-Cookie': 'itsalive_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Domain=.itsalive.co',
    },
  });
});

// ============ DATABASE ENDPOINTS ============

// Helper to check if collection is public
async function isCollectionPublic(env, subdomain, collection) {
  const settings = await env.DB.prepare(
    'SELECT public_read FROM collection_settings WHERE app_subdomain = ? AND collection = ?'
  ).bind(subdomain, collection).first();
  return settings?.public_read === 1;
}

// Helper to get collection settings including schema
async function getCollectionSettings(env, subdomain, collection) {
  const settings = await env.DB.prepare(
    'SELECT public_read, public_write, schema FROM collection_settings WHERE app_subdomain = ? AND collection = ?'
  ).bind(subdomain, collection).first();
  return {
    public_read: settings?.public_read === 1,
    public_write: settings?.public_write === 1,
    schema: settings?.schema ? JSON.parse(settings.schema) : null,
  };
}

// Validate data against schema
function validateData(data, schema) {
  if (!schema) return { valid: true };

  const errors = [];

  for (const [field, rules] of Object.entries(schema)) {
    const value = data[field];

    // Required check
    if (rules.required && (value === undefined || value === null || value === '')) {
      errors.push(`${field} is required`);
      continue;
    }

    // Skip other checks if value is not present and not required
    if (value === undefined || value === null) continue;

    // Type check
    if (rules.type) {
      const actualType = Array.isArray(value) ? 'array' : typeof value;
      if (rules.type !== actualType) {
        errors.push(`${field} must be a ${rules.type}`);
        continue;
      }
    }

    // String validations
    if (typeof value === 'string') {
      if (rules.minLength && value.length < rules.minLength) {
        errors.push(`${field} must be at least ${rules.minLength} characters`);
      }
      if (rules.maxLength && value.length > rules.maxLength) {
        errors.push(`${field} must be at most ${rules.maxLength} characters`);
      }
      if (rules.pattern === 'email' && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
        errors.push(`${field} must be a valid email`);
      }
      if (rules.pattern === 'url' && !/^https?:\/\/.+/.test(value)) {
        errors.push(`${field} must be a valid URL`);
      }
      if (rules.enum && !rules.enum.includes(value)) {
        errors.push(`${field} must be one of: ${rules.enum.join(', ')}`);
      }
    }

    // Number validations
    if (typeof value === 'number') {
      if (rules.min !== undefined && value < rules.min) {
        errors.push(`${field} must be at least ${rules.min}`);
      }
      if (rules.max !== undefined && value > rules.max) {
        errors.push(`${field} must be at most ${rules.max}`);
      }
    }

    // Array validations
    if (Array.isArray(value)) {
      if (rules.minItems && value.length < rules.minItems) {
        errors.push(`${field} must have at least ${rules.minItems} items`);
      }
      if (rules.maxItems && value.length > rules.maxItems) {
        errors.push(`${field} must have at most ${rules.maxItems} items`);
      }
    }
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

// Helper to check if user is app owner
async function isAppOwner(env, subdomain, userEmail) {
  const app = await env.DB.prepare(
    'SELECT owner_id FROM apps WHERE subdomain = ?'
  ).bind(subdomain).first();
  if (!app) return false;

  const owner = await env.DB.prepare(
    'SELECT email FROM owners WHERE id = ?'
  ).bind(app.owner_id).first();
  return owner?.email === userEmail;
}

// PUT /db/:collection/_settings - Configure collection settings (owner only)
// Supports both session auth AND deploy token auth (for CLI/Claude setup)
router.put('/db/:collection/_settings', async (request, env) => {
  const { collection } = request.params;

  // Clone request to read body (since we need to read it twice potentially)
  const body = await request.json();
  const { public_read, public_write, schema, deploy_token } = body;

  let subdomain;
  let authorized = false;

  // Option 1: Deploy token auth (for CLI/Claude)
  if (deploy_token) {
    const tokenData = await env.DB.prepare(
      'SELECT subdomain FROM deploy_tokens WHERE token = ?'
    ).bind(deploy_token).first();

    if (tokenData) {
      subdomain = tokenData.subdomain;
      authorized = true;
    }
  }

  // Option 2: Session auth (for browser)
  if (!authorized) {
    const user = await getSession(request, env);
    if (!user) {
      return new Response(JSON.stringify({ error: 'Not logged in or invalid deploy token' }), { status: 401 });
    }

    subdomain = getSubdomain(request);
    if (!subdomain) {
      return new Response(JSON.stringify({ error: 'Invalid origin' }), { status: 400 });
    }

    // Check if user is app owner
    if (!await isAppOwner(env, subdomain, user.email)) {
      return new Response(JSON.stringify({ error: 'Only the app owner can change collection settings' }), { status: 403 });
    }
    authorized = true;
  }

  if (!authorized) {
    return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 });
  }

  const publicRead = public_read ? 1 : 0;
  const publicWrite = public_write ? 1 : 0;
  const schemaJson = schema ? JSON.stringify(schema) : null;

  await env.DB.prepare(`
    INSERT INTO collection_settings (app_subdomain, collection, public_read, public_write, schema, updated_at)
    VALUES (?, ?, ?, ?, ?, datetime("now"))
    ON CONFLICT(app_subdomain, collection) DO UPDATE SET
      public_read = excluded.public_read,
      public_write = excluded.public_write,
      schema = excluded.schema,
      updated_at = datetime("now")
  `).bind(subdomain, collection, publicRead, publicWrite, schemaJson).run();

  return { success: true, public_read: !!publicRead, public_write: !!publicWrite, schema: schema || null };
});

// GET /db/:collection/_settings - Get collection settings
// Supports deploy_token query param for CLI/direct API access
router.get('/db/:collection/_settings', async (request, env) => {
  const { collection } = request.params;
  const url = new URL(request.url);
  const deploy_token = url.searchParams.get('deploy_token');

  let subdomain = getSubdomain(request);

  // If no subdomain from headers, try deploy_token
  if (!subdomain && deploy_token) {
    const tokenData = await env.DB.prepare(
      'SELECT subdomain FROM deploy_tokens WHERE token = ?'
    ).bind(deploy_token).first();

    if (tokenData) {
      subdomain = tokenData.subdomain;
    }
  }

  if (!subdomain) {
    return new Response(JSON.stringify({ error: 'Could not determine app. Use deploy_token param or call from app origin.' }), { status: 400 });
  }

  const settings = await getCollectionSettings(env, subdomain, collection);
  return settings;
});

// GET /db/:collection - List documents in collection with filtering, sorting, pagination
// Supports deploy_token query param for direct API access
// Supports batch reads with ?id=abc,def,ghi
// Supports location queries with ?near=lat,lng&radius=50mi (or km)
router.get('/db/:collection', async (request, env) => {
  const { collection } = request.params;
  const url = new URL(request.url);
  const deploy_token = url.searchParams.get('deploy_token');

  let subdomain = getSubdomain(request);

  // If no subdomain from headers, try deploy_token
  if (!subdomain && deploy_token) {
    const tokenData = await env.DB.prepare(
      'SELECT subdomain FROM deploy_tokens WHERE token = ?'
    ).bind(deploy_token).first();

    if (tokenData) {
      subdomain = tokenData.subdomain;
    }
  }

  if (!subdomain) {
    return new Response(JSON.stringify({ error: 'Could not determine app. Use deploy_token param or call from app origin.' }), { status: 400 });
  }

  // Check if public read is allowed
  const isPublic = await isCollectionPublic(env, subdomain, collection);
  const user = await getSession(request, env);

  // Deploy token grants access (owner), or public read, or logged-in user
  if (!deploy_token && !isPublic && !user) {
    return new Response(JSON.stringify({ error: 'Not logged in' }), { status: 401 });
  }

  // Parse query params
  const limit = Math.min(parseInt(url.searchParams.get('limit')) || 100, 1000);
  const offset = parseInt(url.searchParams.get('offset')) || 0;
  const sort = url.searchParams.get('sort'); // field or -field for descending
  const mine = url.searchParams.get('mine') === 'true'; // Filter to current user's docs only
  const batchIds = url.searchParams.get('id'); // Batch read: ?id=abc,def,ghi
  const near = url.searchParams.get('near'); // Location: ?near=lat,lng
  const radius = url.searchParams.get('radius'); // Radius: ?radius=50mi or ?radius=80km

  // Build WHERE clause for filters
  const reservedParams = ['limit', 'offset', 'sort', 'mine', 'deploy_token', 'id', 'near', 'radius'];
  const filters = [];
  const filterValues = [];

  // Handle batch reads: ?id=abc,def,ghi
  if (batchIds) {
    const ids = batchIds.split(',').map(id => id.trim()).filter(id => id.length > 0);
    if (ids.length === 0) {
      return new Response(JSON.stringify({ error: 'No valid IDs provided' }), { status: 400 });
    }
    if (ids.length > 100) {
      return new Response(JSON.stringify({ error: 'Maximum 100 IDs per batch read' }), { status: 400 });
    }

    // Use parameterized IN clause
    const placeholders = ids.map(() => '?').join(', ');
    const batchQuery = `
      SELECT doc_id, data, created_by, lat, lng, created_at, updated_at
      FROM app_data
      WHERE app_subdomain = ? AND collection = ? AND doc_id IN (${placeholders})
    `;

    const results = await env.DB.prepare(batchQuery).bind(subdomain, collection, ...ids).all();

    const items = results.results.map((row) => ({
      id: row.doc_id,
      ...JSON.parse(row.data),
      _meta: {
        created_by: row.created_by,
        created_at: row.created_at,
        updated_at: row.updated_at,
        lat: row.lat,
        lng: row.lng,
      },
    }));

    // Return in same order as requested
    const orderedItems = ids.map(id => items.find(item => item.id === id)).filter(Boolean);

    return { items: orderedItems, total: orderedItems.length };
  }

  // Handle location queries: ?near=lat,lng&radius=50mi
  if (near) {
    const [latStr, lngStr] = near.split(',');
    const lat = parseFloat(latStr);
    const lng = parseFloat(lngStr);

    if (isNaN(lat) || isNaN(lng)) {
      return new Response(JSON.stringify({ error: 'Invalid near parameter. Use: near=lat,lng' }), { status: 400 });
    }

    // Parse radius (default 50km)
    let radiusKm = 50;
    if (radius) {
      const match = radius.match(/^([\d.]+)(mi|km)?$/);
      if (match) {
        radiusKm = parseFloat(match[1]);
        if (match[2] === 'mi') {
          radiusKm *= 1.60934; // Convert miles to km
        }
      }
    }

    // Use Haversine formula approximation for SQLite
    // For small distances, we can use a bounding box + distance calculation
    const latDelta = radiusKm / 111.0; // ~111km per degree latitude
    const lngDelta = radiusKm / (111.0 * Math.cos(lat * Math.PI / 180));

    const geoQuery = `
      SELECT * FROM (
        SELECT doc_id, data, created_by, lat, lng, created_at, updated_at,
          (6371 * acos(
            max(-1, min(1,
              cos(? * 3.14159265359 / 180) *
              cos(lat * 3.14159265359 / 180) *
              cos((lng - ?) * 3.14159265359 / 180) +
              sin(? * 3.14159265359 / 180) *
              sin(lat * 3.14159265359 / 180)
            ))
          )) AS distance
        FROM app_data
        WHERE app_subdomain = ? AND collection = ?
          AND lat IS NOT NULL AND lng IS NOT NULL
          AND lat BETWEEN ? AND ?
          AND lng BETWEEN ? AND ?
      ) WHERE distance <= ?
      ORDER BY distance ASC
      LIMIT ?
    `;

    const geoResults = await env.DB.prepare(geoQuery).bind(
      lat, lng, lat, // Haversine params
      subdomain, collection, // WHERE params
      lat - latDelta, lat + latDelta, // lat bounds
      lng - lngDelta, lng + lngDelta, // lng bounds
      radiusKm, // WHERE distance filter
      limit // LIMIT
    ).all();

    const items = geoResults.results.map((row) => ({
      id: row.doc_id,
      ...JSON.parse(row.data),
      _meta: {
        created_by: row.created_by,
        created_at: row.created_at,
        updated_at: row.updated_at,
        lat: row.lat,
        lng: row.lng,
        distance_km: Math.round(row.distance * 100) / 100,
      },
    }));

    return { items, total: items.length, center: { lat, lng }, radius_km: radiusKm };
  }

  // Filter by current user if ?mine=true
  if (mine) {
    if (!user) {
      return new Response(JSON.stringify({ error: 'Must be logged in to use mine=true filter' }), { status: 401 });
    }
    filters.push('created_by = ?');
    filterValues.push(user.id);
  }

  for (const [key, value] of url.searchParams.entries()) {
    if (!reservedParams.includes(key)) {
      // Validate field name to prevent SQL injection
      if (!/^[a-zA-Z0-9_]+$/.test(key)) continue;
      // Filter on JSON field: json_extract(data, '$.field') = value
      filters.push(`json_extract(data, '$.${key}') = ?`);
      filterValues.push(value);
    }
  }

  // Build query
  let query = 'SELECT doc_id, data, created_by, lat, lng, created_at, updated_at FROM app_data WHERE app_subdomain = ? AND collection = ?';
  const params = [subdomain, collection];

  if (filters.length > 0) {
    query += ' AND ' + filters.join(' AND ');
    params.push(...filterValues);
  }

  // Sorting
  if (sort) {
    const descending = sort.startsWith('-');
    const sortField = descending ? sort.slice(1) : sort;
    // Validate sort field to prevent SQL injection
    if (!/^[a-zA-Z0-9_]+$/.test(sortField)) {
      return new Response(JSON.stringify({ error: 'Invalid sort field name' }), { status: 400 });
    }
    // Sort by JSON field or meta field
    if (['created_at', 'updated_at'].includes(sortField)) {
      query += ` ORDER BY ${sortField} ${descending ? 'DESC' : 'ASC'}`;
    } else {
      query += ` ORDER BY json_extract(data, '$.${sortField}') ${descending ? 'DESC' : 'ASC'}`;
    }
  } else {
    query += ' ORDER BY created_at DESC'; // Default: newest first
  }

  // Pagination
  query += ' LIMIT ? OFFSET ?';
  params.push(limit, offset);

  const results = await env.DB.prepare(query).bind(...params).all();

  // Get total count for pagination
  let countQuery = 'SELECT COUNT(*) as total FROM app_data WHERE app_subdomain = ? AND collection = ?';
  const countParams = [subdomain, collection];
  if (filters.length > 0) {
    countQuery += ' AND ' + filters.join(' AND ');
    countParams.push(...filterValues);
  }
  const countResult = await env.DB.prepare(countQuery).bind(...countParams).first();

  const items = results.results.map((row) => ({
    id: row.doc_id,
    ...JSON.parse(row.data),
    _meta: {
      created_by: row.created_by,
      created_at: row.created_at,
      updated_at: row.updated_at,
      lat: row.lat,
      lng: row.lng,
    },
  }));

  return {
    items,
    total: countResult?.total || 0,
    limit,
    offset,
  };
});

// ==================== AGGREGATION ENDPOINTS ====================
// These MUST be before /db/:collection/:id to avoid matching _count/_stats as IDs

// GET /db/:collection/_count - Get count of documents
router.get('/db/:collection/_count', async (request, env) => {
  const subdomain = getSubdomain(request);
  const { collection } = request.params;
  const url = new URL(request.url);

  if (!subdomain) {
    return new Response(JSON.stringify({ error: 'Could not determine app' }), { status: 400 });
  }

  // Check if public read is allowed
  const isPublic = await isCollectionPublic(env, subdomain, collection);
  if (!isPublic) {
    const user = await getSession(request, env);
    if (!user) {
      return new Response(JSON.stringify({ error: 'Not logged in' }), { status: 401 });
    }
  }

  // Build filter conditions
  const filters = [];
  const filterValues = [];

  for (const [key, value] of url.searchParams) {
    if (['limit', 'offset', 'sort', 'order', 'group'].includes(key)) continue;

    // Validate field name
    if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(key)) continue;

    if (key === 'created_by') {
      filters.push('created_by = ?');
      filterValues.push(value);
    } else {
      filters.push(`json_extract(data, '$.${key}') = ?`);
      filterValues.push(value);
    }
  }

  let query = 'SELECT COUNT(*) as count FROM app_data WHERE app_subdomain = ? AND collection = ?';
  const params = [subdomain, collection];

  if (filters.length > 0) {
    query += ' AND ' + filters.join(' AND ');
    params.push(...filterValues);
  }

  // Support grouping
  const groupBy = url.searchParams.get('group');
  if (groupBy && /^[a-zA-Z_][a-zA-Z0-9_]*$/.test(groupBy)) {
    query = `SELECT json_extract(data, '$.${groupBy}') as group_value, COUNT(*) as count
             FROM app_data WHERE app_subdomain = ? AND collection = ?`;
    if (filters.length > 0) {
      query += ' AND ' + filters.join(' AND ');
    }
    query += ` GROUP BY json_extract(data, '$.${groupBy}')`;

    const results = await env.DB.prepare(query).bind(...params).all();
    return {
      groups: results.results.map(r => ({ value: r.group_value, count: r.count })),
      total: results.results.reduce((sum, r) => sum + r.count, 0)
    };
  }

  const result = await env.DB.prepare(query).bind(...params).first();
  return { count: result?.count || 0 };
});

// GET /db/:collection/_stats - Get statistics for numeric fields
router.get('/db/:collection/_stats', async (request, env) => {
  const subdomain = getSubdomain(request);
  const { collection } = request.params;
  const url = new URL(request.url);

  if (!subdomain) {
    return new Response(JSON.stringify({ error: 'Could not determine app' }), { status: 400 });
  }

  // Check if public read is allowed
  const isPublic = await isCollectionPublic(env, subdomain, collection);
  if (!isPublic) {
    const user = await getSession(request, env);
    if (!user) {
      return new Response(JSON.stringify({ error: 'Not logged in' }), { status: 401 });
    }
  }

  // Get field to compute stats for
  const field = url.searchParams.get('field');
  if (!field) {
    return new Response(JSON.stringify({ error: 'field parameter required' }), { status: 400 });
  }

  // Validate field name
  if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(field)) {
    return new Response(JSON.stringify({ error: 'Invalid field name' }), { status: 400 });
  }

  // Build filter conditions
  const filters = [];
  const filterValues = [];

  for (const [key, value] of url.searchParams) {
    if (['limit', 'offset', 'sort', 'order', 'field', 'group'].includes(key)) continue;

    if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(key)) continue;

    if (key === 'created_by') {
      filters.push('created_by = ?');
      filterValues.push(value);
    } else {
      filters.push(`json_extract(data, '$.${key}') = ?`);
      filterValues.push(value);
    }
  }

  const fieldPath = `json_extract(data, '$.${field}')`;

  // Support grouping
  const groupBy = url.searchParams.get('group');
  if (groupBy && /^[a-zA-Z_][a-zA-Z0-9_]*$/.test(groupBy)) {
    let query = `SELECT json_extract(data, '$.${groupBy}') as group_value,
                 COUNT(*) as count,
                 AVG(CAST(${fieldPath} AS REAL)) as avg,
                 MIN(CAST(${fieldPath} AS REAL)) as min,
                 MAX(CAST(${fieldPath} AS REAL)) as max,
                 SUM(CAST(${fieldPath} AS REAL)) as sum
                 FROM app_data WHERE app_subdomain = ? AND collection = ?
                 AND ${fieldPath} IS NOT NULL`;
    const params = [subdomain, collection];

    if (filters.length > 0) {
      query += ' AND ' + filters.join(' AND ');
      params.push(...filterValues);
    }
    query += ` GROUP BY json_extract(data, '$.${groupBy}')`;

    const results = await env.DB.prepare(query).bind(...params).all();
    return {
      field,
      groups: results.results.map(r => ({
        value: r.group_value,
        count: r.count,
        avg: r.avg,
        min: r.min,
        max: r.max,
        sum: r.sum
      }))
    };
  }

  let query = `SELECT COUNT(*) as count,
               AVG(CAST(${fieldPath} AS REAL)) as avg,
               MIN(CAST(${fieldPath} AS REAL)) as min,
               MAX(CAST(${fieldPath} AS REAL)) as max,
               SUM(CAST(${fieldPath} AS REAL)) as sum
               FROM app_data WHERE app_subdomain = ? AND collection = ?
               AND ${fieldPath} IS NOT NULL`;
  const params = [subdomain, collection];

  if (filters.length > 0) {
    query += ' AND ' + filters.join(' AND ');
    params.push(...filterValues);
  }

  const result = await env.DB.prepare(query).bind(...params).first();
  return {
    field,
    count: result?.count || 0,
    avg: result?.avg,
    min: result?.min,
    max: result?.max,
    sum: result?.sum
  };
});

// GET /db/:collection/:id - Get single document
// Supports deploy_token query param for direct API access
router.get('/db/:collection/:id', async (request, env) => {
  const { collection, id } = request.params;
  const url = new URL(request.url);
  const deploy_token = url.searchParams.get('deploy_token');

  let subdomain = getSubdomain(request);

  // If no subdomain from headers, try deploy_token
  if (!subdomain && deploy_token) {
    const tokenData = await env.DB.prepare(
      'SELECT subdomain FROM deploy_tokens WHERE token = ?'
    ).bind(deploy_token).first();

    if (tokenData) {
      subdomain = tokenData.subdomain;
    }
  }

  if (!subdomain) {
    return new Response(JSON.stringify({ error: 'Could not determine app. Use deploy_token param or call from app origin.' }), { status: 400 });
  }

  // Check if public read is allowed
  const isPublic = await isCollectionPublic(env, subdomain, collection);

  // Deploy token grants access (owner), or public read, or logged-in user
  if (!deploy_token && !isPublic) {
    const user = await getSession(request, env);
    if (!user) {
      return new Response(JSON.stringify({ error: 'Not logged in' }), { status: 401 });
    }
  }

  const doc = await env.DB.prepare(
    'SELECT data FROM app_data WHERE app_subdomain = ? AND collection = ? AND doc_id = ?'
  ).bind(subdomain, collection, id).first();

  if (!doc) {
    return new Response(JSON.stringify({ error: 'Not found' }), { status: 404 });
  }

  return JSON.parse(doc.data);
});

// PUT /db/:collection/:id - Save document
// Supports location data via lat/lng fields in the document
// Supports deploy_token for automation scripts
router.put('/db/:collection/:id', async (request, env) => {
  const { collection, id } = request.params;
  const body = await request.json();

  // Extract deploy_token and merge flag from body if present
  const { deploy_token, merge, ...data } = body;

  let subdomain = getSubdomain(request);
  let isOwner = false;

  // Deploy token auth (owner/admin access - can write any doc)
  if (deploy_token) {
    const tokenData = await env.DB.prepare(
      'SELECT subdomain FROM deploy_tokens WHERE token = ?'
    ).bind(deploy_token).first();

    if (tokenData) {
      subdomain = tokenData.subdomain;
      isOwner = true;
    }
  }

  if (!subdomain) {
    return new Response(JSON.stringify({ error: 'Could not determine app. Use deploy_token or call from app origin.' }), { status: 400 });
  }

  // Get collection settings (for public_write and schema)
  const settings = await getCollectionSettings(env, subdomain, collection);

  // Check auth - deploy_token, session, or public_write
  const user = await getSession(request, env);
  if (!isOwner && !user && !settings.public_write) {
    return new Response(JSON.stringify({ error: 'Not logged in' }), { status: 401 });
  }

  // Validate against schema if one exists
  if (settings.schema) {
    const validation = validateData(data, settings.schema);
    if (!validation.valid) {
      return new Response(JSON.stringify({ error: 'Validation failed', errors: validation.errors }), { status: 400 });
    }
  }

  // Check if doc exists and who owns it
  const existing = await env.DB.prepare(
    'SELECT created_by FROM app_data WHERE app_subdomain = ? AND collection = ? AND doc_id = ?'
  ).bind(subdomain, collection, id).first();

  // Ownership check: deploy_token bypasses, logged-in users can only edit their own docs
  // Anonymous writes can only create new docs or update anonymous docs
  if (!isOwner && existing && existing.created_by) {
    if (!user || existing.created_by !== user.id) {
      return new Response(JSON.stringify({ error: 'Not authorized to edit this document' }), { status: 403 });
    }
  }

  const createdBy = isOwner ? (existing?.created_by || 'owner') : (user ? user.id : null);

  // Extract lat/lng for geo queries if present in data
  const lat = typeof data.lat === 'number' ? data.lat : (typeof data.latitude === 'number' ? data.latitude : null);
  const lng = typeof data.lng === 'number' ? data.lng : (typeof data.longitude === 'number' ? data.longitude : null);

  if (merge) {
    // Merge: only update specified fields, preserve existing data
    await env.DB.prepare(`
      INSERT INTO app_data (app_subdomain, collection, doc_id, data, created_by, lat, lng, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, datetime("now"))
      ON CONFLICT(app_subdomain, collection, doc_id) DO UPDATE SET
        data = json_patch(app_data.data, excluded.data),
        lat = COALESCE(excluded.lat, app_data.lat),
        lng = COALESCE(excluded.lng, app_data.lng),
        updated_at = datetime("now")
    `).bind(subdomain, collection, id, JSON.stringify(data), createdBy, lat, lng).run();
  } else {
    // Replace: full document replacement (default)
    await env.DB.prepare(`
      INSERT INTO app_data (app_subdomain, collection, doc_id, data, created_by, lat, lng, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, datetime("now"))
      ON CONFLICT(app_subdomain, collection, doc_id) DO UPDATE SET
        data = excluded.data,
        lat = excluded.lat,
        lng = excluded.lng,
        updated_at = datetime("now")
    `).bind(subdomain, collection, id, JSON.stringify(data), createdBy, lat, lng).run();
  }

  return { success: true, merged: !!merge };
});

// DELETE /db/:collection/:id - Delete document
router.delete('/db/:collection/:id', async (request, env) => {
  const { collection, id } = request.params;

  let subdomain = getSubdomain(request);
  let isOwner = false;
  let user = null;

  // Try to get deploy_token from body (DELETE can have body)
  let deploy_token = null;
  try {
    const body = await request.clone().json();
    deploy_token = body.deploy_token;
  } catch (e) {
    // No body or not JSON, that's fine
  }

  // Option 1: Deploy token auth (owner/admin access)
  if (deploy_token) {
    const tokenData = await env.DB.prepare(
      'SELECT subdomain FROM deploy_tokens WHERE token = ?'
    ).bind(deploy_token).first();

    if (tokenData) {
      subdomain = tokenData.subdomain;
      isOwner = true;
    }
  }

  // Option 2: Session auth
  if (!isOwner) {
    user = await getSession(request, env);
    if (!user) {
      return new Response(JSON.stringify({ error: 'Not logged in' }), { status: 401 });
    }
  }

  if (!subdomain) {
    return new Response(JSON.stringify({ error: 'Could not determine app' }), { status: 400 });
  }

  // Check document exists
  const existing = await env.DB.prepare(
    'SELECT created_by FROM app_data WHERE app_subdomain = ? AND collection = ? AND doc_id = ?'
  ).bind(subdomain, collection, id).first();

  if (!existing) {
    return new Response(JSON.stringify({ error: 'Not found' }), { status: 404 });
  }

  // Deploy token = owner, can delete anything
  // Session user = can only delete their own docs
  if (!isOwner && existing.created_by !== user.id) {
    return new Response(JSON.stringify({ error: 'Not authorized to delete this document' }), { status: 403 });
  }

  await env.DB.prepare(
    'DELETE FROM app_data WHERE app_subdomain = ? AND collection = ? AND doc_id = ?'
  ).bind(subdomain, collection, id).run();

  return { success: true };
});

// POST /db/:collection/_bulk - Bulk create/update documents
// Supports deploy_token for automation scripts
// Supports merge: true for partial updates
router.post('/db/:collection/_bulk', async (request, env) => {
  const { collection } = request.params;
  const body = await request.json();
  const { docs, deploy_token, merge } = body;

  let subdomain = getSubdomain(request);
  let isOwner = false;

  // Deploy token auth (owner/admin access - can write any doc)
  if (deploy_token) {
    const tokenData = await env.DB.prepare(
      'SELECT subdomain FROM deploy_tokens WHERE token = ?'
    ).bind(deploy_token).first();

    if (tokenData) {
      subdomain = tokenData.subdomain;
      isOwner = true;
    }
  }

  if (!subdomain) {
    return new Response(JSON.stringify({ error: 'Could not determine app. Use deploy_token or call from app origin.' }), { status: 400 });
  }

  // Get collection settings (for public_write and schema)
  const settings = await getCollectionSettings(env, subdomain, collection);

  // Check auth - deploy_token, session, or public_write
  const user = await getSession(request, env);
  if (!isOwner && !user && !settings.public_write) {
    return new Response(JSON.stringify({ error: 'Not logged in' }), { status: 401 });
  }

  if (!Array.isArray(docs) || docs.length === 0) {
    return new Response(JSON.stringify({ error: 'docs must be a non-empty array' }), { status: 400 });
  }

  if (docs.length > 100) {
    return new Response(JSON.stringify({ error: 'Maximum 100 documents per bulk operation' }), { status: 400 });
  }

  const results = [];

  for (const doc of docs) {
    const { id, data } = doc;

    if (!id || !data) {
      results.push({ id, success: false, error: 'id and data are required' });
      continue;
    }

    // Validate against schema
    if (settings.schema) {
      const validation = validateData(data, settings.schema);
      if (!validation.valid) {
        results.push({ id, success: false, error: 'Validation failed', errors: validation.errors });
        continue;
      }
    }

    // Check ownership
    const existing = await env.DB.prepare(
      'SELECT created_by FROM app_data WHERE app_subdomain = ? AND collection = ? AND doc_id = ?'
    ).bind(subdomain, collection, id).first();

    // Ownership check: deploy_token bypasses, logged-in users can only edit their own docs
    // Anonymous writes can only create new docs or update anonymous docs
    if (!isOwner && existing && existing.created_by) {
      if (!user || existing.created_by !== user.id) {
        results.push({ id, success: false, error: 'Not authorized to edit this document' });
        continue;
      }
    }

    const createdBy = isOwner ? (existing?.created_by || 'owner') : (user ? user.id : null);

    // Save document
    if (merge) {
      // Merge: only update specified fields, preserve existing data
      await env.DB.prepare(`
        INSERT INTO app_data (app_subdomain, collection, doc_id, data, created_by, updated_at)
        VALUES (?, ?, ?, ?, ?, datetime("now"))
        ON CONFLICT(app_subdomain, collection, doc_id) DO UPDATE SET
          data = json_patch(app_data.data, excluded.data),
          updated_at = datetime("now")
      `).bind(subdomain, collection, id, JSON.stringify(data), createdBy).run();
    } else {
      // Replace: full document replacement (default)
      await env.DB.prepare(`
        INSERT INTO app_data (app_subdomain, collection, doc_id, data, created_by, updated_at)
        VALUES (?, ?, ?, ?, ?, datetime("now"))
        ON CONFLICT(app_subdomain, collection, doc_id) DO UPDATE SET
          data = excluded.data,
          updated_at = datetime("now")
      `).bind(subdomain, collection, id, JSON.stringify(data), createdBy).run();
    }

    results.push({ id, success: true });
  }

  const succeeded = results.filter(r => r.success).length;
  const failed = results.filter(r => !r.success).length;

  return { results, succeeded, failed, merged: !!merge };
});

// ============ USER DATA ENDPOINTS ============

// GET /me/:key - Get user-private data
router.get('/me/:key', async (request, env) => {
  const user = await getSession(request, env);
  if (!user) {
    return new Response(JSON.stringify({ error: 'Not logged in' }), { status: 401 });
  }

  const subdomain = getSubdomain(request);
  const { key } = request.params;

  const doc = await env.DB.prepare(
    'SELECT data FROM user_data WHERE app_subdomain = ? AND user_id = ? AND key = ?'
  ).bind(subdomain, user.id, key).first();

  if (!doc) {
    return new Response(JSON.stringify({ error: 'Not found' }), { status: 404 });
  }

  return JSON.parse(doc.data);
});

// PUT /me/:key - Save user-private data
router.put('/me/:key', async (request, env) => {
  const user = await getSession(request, env);
  if (!user) {
    return new Response(JSON.stringify({ error: 'Not logged in' }), { status: 401 });
  }

  const subdomain = getSubdomain(request);
  const { key } = request.params;
  const data = await request.json();

  await env.DB.prepare(`
    INSERT INTO user_data (app_subdomain, user_id, key, data, updated_at)
    VALUES (?, ?, ?, ?, datetime("now"))
    ON CONFLICT(app_subdomain, user_id, key) DO UPDATE SET
      data = excluded.data,
      updated_at = datetime("now")
  `).bind(subdomain, user.id, key, JSON.stringify(data)).run();

  return { success: true };
});

// ============ CRON JOB ENDPOINTS ============

// Helper to parse cron expression and get next run time
function getNextCronRun(schedule, fromDate = new Date()) {
  // Simple cron parser for: minute hour day month weekday
  // Supports: * (any), specific numbers, */n (every n)
  const parts = schedule.split(' ');
  if (parts.length !== 5) return null;

  const [minute, hour, day, month, weekday] = parts;
  const next = new Date(fromDate);
  next.setSeconds(0);
  next.setMilliseconds(0);

  // Simple implementation: find next matching time within 7 days
  for (let i = 0; i < 7 * 24 * 60; i++) {
    next.setMinutes(next.getMinutes() + 1);

    const matchMinute = minute === '*' || parseInt(minute) === next.getMinutes() ||
      (minute.startsWith('*/') && next.getMinutes() % parseInt(minute.slice(2)) === 0);
    const matchHour = hour === '*' || parseInt(hour) === next.getHours() ||
      (hour.startsWith('*/') && next.getHours() % parseInt(hour.slice(2)) === 0);
    const matchDay = day === '*' || parseInt(day) === next.getDate();
    const matchMonth = month === '*' || parseInt(month) === (next.getMonth() + 1);
    const matchWeekday = weekday === '*' || parseInt(weekday) === next.getDay();

    if (matchMinute && matchHour && matchDay && matchMonth && matchWeekday) {
      return next;
    }
  }
  return null;
}

// GET /cron - List cron jobs for this app
router.get('/cron', async (request, env) => {
  const user = await getSession(request, env);
  if (!user) {
    return new Response(JSON.stringify({ error: 'Not logged in' }), { status: 401 });
  }

  const subdomain = getSubdomain(request);

  // Only app owner can view cron jobs
  if (!await isAppOwner(env, subdomain, user.email)) {
    return new Response(JSON.stringify({ error: 'Only the app owner can manage cron jobs' }), { status: 403 });
  }

  const results = await env.DB.prepare(
    'SELECT id, name, schedule, url, method, enabled, last_run, next_run, created_at FROM cron_jobs WHERE app_subdomain = ?'
  ).bind(subdomain).all();

  return { jobs: results.results };
});

// POST /cron - Create a cron job
router.post('/cron', async (request, env) => {
  const user = await getSession(request, env);
  if (!user) {
    return new Response(JSON.stringify({ error: 'Not logged in' }), { status: 401 });
  }

  const subdomain = getSubdomain(request);

  if (!await isAppOwner(env, subdomain, user.email)) {
    return new Response(JSON.stringify({ error: 'Only the app owner can create cron jobs' }), { status: 403 });
  }

  const { name, schedule, url, method = 'POST', headers, body } = await request.json();

  if (!schedule || !url) {
    return new Response(JSON.stringify({ error: 'schedule and url are required' }), { status: 400 });
  }

  const nextRun = getNextCronRun(schedule);
  if (!nextRun) {
    return new Response(JSON.stringify({ error: 'Invalid cron schedule' }), { status: 400 });
  }

  const id = generateId();
  await env.DB.prepare(`
    INSERT INTO cron_jobs (id, app_subdomain, name, schedule, url, method, headers, body, next_run)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(id, subdomain, name || null, schedule, url, method, headers ? JSON.stringify(headers) : null, body || null, nextRun.toISOString()).run();

  return { id, next_run: nextRun.toISOString() };
});

// PUT /cron/:id - Update a cron job
router.put('/cron/:id', async (request, env) => {
  const user = await getSession(request, env);
  if (!user) {
    return new Response(JSON.stringify({ error: 'Not logged in' }), { status: 401 });
  }

  const subdomain = getSubdomain(request);
  const { id } = request.params;

  if (!await isAppOwner(env, subdomain, user.email)) {
    return new Response(JSON.stringify({ error: 'Only the app owner can update cron jobs' }), { status: 403 });
  }

  const existing = await env.DB.prepare(
    'SELECT id FROM cron_jobs WHERE id = ? AND app_subdomain = ?'
  ).bind(id, subdomain).first();

  if (!existing) {
    return new Response(JSON.stringify({ error: 'Cron job not found' }), { status: 404 });
  }

  const updates = await request.json();
  const fields = [];
  const values = [];

  if (updates.name !== undefined) { fields.push('name = ?'); values.push(updates.name); }
  if (updates.schedule !== undefined) {
    const nextRun = getNextCronRun(updates.schedule);
    if (!nextRun) {
      return new Response(JSON.stringify({ error: 'Invalid cron schedule' }), { status: 400 });
    }
    fields.push('schedule = ?', 'next_run = ?');
    values.push(updates.schedule, nextRun.toISOString());
  }
  if (updates.url !== undefined) { fields.push('url = ?'); values.push(updates.url); }
  if (updates.method !== undefined) { fields.push('method = ?'); values.push(updates.method); }
  if (updates.headers !== undefined) { fields.push('headers = ?'); values.push(JSON.stringify(updates.headers)); }
  if (updates.body !== undefined) { fields.push('body = ?'); values.push(updates.body); }
  if (updates.enabled !== undefined) { fields.push('enabled = ?'); values.push(updates.enabled ? 1 : 0); }

  if (fields.length === 0) {
    return new Response(JSON.stringify({ error: 'No updates provided' }), { status: 400 });
  }

  values.push(id, subdomain);
  await env.DB.prepare(`UPDATE cron_jobs SET ${fields.join(', ')} WHERE id = ? AND app_subdomain = ?`).bind(...values).run();

  return { success: true };
});

// DELETE /cron/:id - Delete a cron job
router.delete('/cron/:id', async (request, env) => {
  const user = await getSession(request, env);
  if (!user) {
    return new Response(JSON.stringify({ error: 'Not logged in' }), { status: 401 });
  }

  const subdomain = getSubdomain(request);
  const { id } = request.params;

  if (!await isAppOwner(env, subdomain, user.email)) {
    return new Response(JSON.stringify({ error: 'Only the app owner can delete cron jobs' }), { status: 403 });
  }

  await env.DB.prepare('DELETE FROM cron_jobs WHERE id = ? AND app_subdomain = ?').bind(id, subdomain).run();
  return { success: true };
});

// ============ JOB QUEUE ENDPOINTS ============

// POST /jobs - Queue a new job
router.post('/jobs', async (request, env) => {
  const user = await getSession(request, env);
  if (!user) {
    return new Response(JSON.stringify({ error: 'Not logged in' }), { status: 401 });
  }

  const subdomain = getSubdomain(request);
  const { type, data, runAt, maxAttempts = 3 } = await request.json();

  if (!type) {
    return new Response(JSON.stringify({ error: 'type is required' }), { status: 400 });
  }

  const id = generateId();
  const runAtDate = runAt ? new Date(runAt).toISOString() : new Date().toISOString();

  await env.DB.prepare(`
    INSERT INTO jobs (id, app_subdomain, type, data, run_at, max_attempts)
    VALUES (?, ?, ?, ?, ?, ?)
  `).bind(id, subdomain, type, data ? JSON.stringify(data) : null, runAtDate, maxAttempts).run();

  return { id, status: 'pending', run_at: runAtDate };
});

// GET /jobs - List jobs for this app
router.get('/jobs', async (request, env) => {
  const user = await getSession(request, env);
  if (!user) {
    return new Response(JSON.stringify({ error: 'Not logged in' }), { status: 401 });
  }

  const subdomain = getSubdomain(request);
  const url = new URL(request.url);
  const status = url.searchParams.get('status');
  const limit = Math.min(parseInt(url.searchParams.get('limit')) || 50, 100);

  let query = 'SELECT id, type, data, status, run_at, attempts, last_error, created_at, completed_at FROM jobs WHERE app_subdomain = ?';
  const params = [subdomain];

  if (status) {
    query += ' AND status = ?';
    params.push(status);
  }

  query += ' ORDER BY created_at DESC LIMIT ?';
  params.push(limit);

  const results = await env.DB.prepare(query).bind(...params).all();

  const jobs = results.results.map(job => ({
    ...job,
    data: job.data ? JSON.parse(job.data) : null,
  }));

  return { jobs };
});

// GET /jobs/:id - Get job status
router.get('/jobs/:id', async (request, env) => {
  const user = await getSession(request, env);
  if (!user) {
    return new Response(JSON.stringify({ error: 'Not logged in' }), { status: 401 });
  }

  const subdomain = getSubdomain(request);
  const { id } = request.params;

  const job = await env.DB.prepare(
    'SELECT id, type, data, status, run_at, attempts, max_attempts, last_error, created_at, completed_at FROM jobs WHERE id = ? AND app_subdomain = ?'
  ).bind(id, subdomain).first();

  if (!job) {
    return new Response(JSON.stringify({ error: 'Job not found' }), { status: 404 });
  }

  return {
    ...job,
    data: job.data ? JSON.parse(job.data) : null,
  };
});

// DELETE /jobs/:id - Cancel a pending job
router.delete('/jobs/:id', async (request, env) => {
  const user = await getSession(request, env);
  if (!user) {
    return new Response(JSON.stringify({ error: 'Not logged in' }), { status: 401 });
  }

  const subdomain = getSubdomain(request);
  const { id } = request.params;

  const job = await env.DB.prepare(
    'SELECT status FROM jobs WHERE id = ? AND app_subdomain = ?'
  ).bind(id, subdomain).first();

  if (!job) {
    return new Response(JSON.stringify({ error: 'Job not found' }), { status: 404 });
  }

  if (job.status !== 'pending') {
    return new Response(JSON.stringify({ error: 'Can only cancel pending jobs' }), { status: 400 });
  }

  await env.DB.prepare('DELETE FROM jobs WHERE id = ? AND app_subdomain = ?').bind(id, subdomain).run();
  return { success: true };
});

// ============ LOCATION API ============

// POST /location - Convert city string to normalized location with lat/lng
router.post('/location', async (request, env) => {
  // Only allow requests from itsalive-hosted sites
  const subdomain = getSubdomain(request);
  if (!subdomain) {
    return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 });
  }

  const { city } = await request.json();

  if (!city || typeof city !== 'string') {
    return new Response(JSON.stringify({ error: 'city string is required' }), { status: 400 });
  }

  const query = city.trim();
  if (query.length < 2) {
    return new Response(JSON.stringify({ error: 'city must be at least 2 characters' }), { status: 400 });
  }

  try {
    // Use OpenStreetMap Nominatim for geocoding
    const nominatimUrl = new URL('https://nominatim.openstreetmap.org/search');
    nominatimUrl.searchParams.set('q', query);
    nominatimUrl.searchParams.set('format', 'json');
    nominatimUrl.searchParams.set('limit', '1');
    nominatimUrl.searchParams.set('addressdetails', '1');

    const response = await fetch(nominatimUrl.toString(), {
      headers: {
        'User-Agent': 'itsalive.co/1.0',
      },
    });

    if (!response.ok) {
      return new Response(JSON.stringify({ error: 'Geocoding service unavailable' }), { status: 502 });
    }

    const results = await response.json();

    if (!results || results.length === 0) {
      return new Response(JSON.stringify({ error: 'Location not found' }), { status: 404 });
    }

    const result = results[0];
    const address = result.address || {};

    // Build normalized city name
    const cityName = address.city || address.town || address.village || address.municipality || address.county || query;
    const state = address.state;
    const country = address.country;

    // Build display name
    let normalized = cityName;
    if (state && state !== cityName) {
      normalized += `, ${state}`;
    }
    if (country) {
      normalized += `, ${country}`;
    }

    return {
      city: cityName,
      normalized,
      lat: parseFloat(result.lat),
      lng: parseFloat(result.lon),
      country: country || null,
      country_code: address.country_code?.toUpperCase() || null,
      state: state || null,
    };
  } catch (e) {
    return new Response(JSON.stringify({ error: 'Geocoding failed' }), { status: 500 });
  }
});

// ============ PLATFORM FEEDBACK ENDPOINTS ============

// POST /_itsalive/bugs - Report a bug (from Claude instances)
router.post('/_itsalive/bugs', async (request, env) => {
  const subdomain = getSubdomain(request);
  const { title, description, code_context, error_message, severity } = await request.json();

  if (!title || !description) {
    return new Response(JSON.stringify({ error: 'title and description required' }), { status: 400 });
  }

  // Validate severity
  const validSeverities = ['low', 'medium', 'high', 'critical'];
  const sev = validSeverities.includes(severity) ? severity : 'medium';

  const id = generateId();
  await env.DB.prepare(`
    INSERT INTO platform_bugs (id, app_subdomain, title, description, code_context, error_message, severity)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).bind(id, subdomain || 'unknown', title, description, code_context || null, error_message || null, sev).run();

  // Notify about new bug report
  await sendEmail(
    env,
    'sam@itsalive.co',
    `[Bug Report] ${title}`,
    `<div style="font-family: system-ui, sans-serif;">
      <h2>New Bug Report from ${subdomain || 'unknown'}.itsalive.co</h2>
      <p><strong>Severity:</strong> ${sev}</p>
      <p><strong>Title:</strong> ${title}</p>
      <p><strong>Description:</strong> ${description}</p>
      ${error_message ? `<p><strong>Error:</strong> <code>${error_message}</code></p>` : ''}
      ${code_context ? `<pre style="background:#f5f5f5;padding:1rem;overflow-x:auto;">${code_context}</pre>` : ''}
    </div>`
  );

  return { id, status: 'received', message: 'Bug report submitted for review' };
});

// POST /_itsalive/feedback - Submit feedback (from Claude instances)
router.post('/_itsalive/feedback', async (request, env) => {
  const subdomain = getSubdomain(request);
  const { category, title, description, use_case, priority_suggestion } = await request.json();

  if (!title || !description) {
    return new Response(JSON.stringify({ error: 'title and description required' }), { status: 400 });
  }

  // Validate category
  const validCategories = ['feature', 'improvement', 'documentation', 'other'];
  const cat = validCategories.includes(category) ? category : 'other';

  const id = generateId();
  await env.DB.prepare(`
    INSERT INTO platform_feedback (id, app_subdomain, category, title, description, use_case, priority_suggestion)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).bind(id, subdomain || 'unknown', cat, title, description, use_case || null, priority_suggestion || null).run();

  // Notify about new feedback
  await sendEmail(
    env,
    'sam@itsalive.co',
    `[Feedback] ${title}`,
    `<div style="font-family: system-ui, sans-serif;">
      <h2>New Feedback from ${subdomain || 'unknown'}.itsalive.co</h2>
      <p><strong>Category:</strong> ${cat}</p>
      <p><strong>Title:</strong> ${title}</p>
      <p><strong>Description:</strong> ${description}</p>
      ${use_case ? `<p><strong>Use Case:</strong> ${use_case}</p>` : ''}
      ${priority_suggestion ? `<p><strong>Suggested Priority:</strong> ${priority_suggestion}</p>` : ''}
    </div>`
  );

  return { id, status: 'received', message: 'Feedback submitted for review' };
});

// ============ FILE UPLOAD ENDPOINTS ============

// POST /uploads - Upload a file (requires login, costs 5 credits)
router.post('/uploads', async (request, env) => {
  const subdomain = getSubdomain(request);
  if (!subdomain) {
    return new Response(JSON.stringify({ error: 'Invalid origin' }), { status: 400 });
  }

  const user = await getSession(request, env);
  if (!user) {
    return new Response(JSON.stringify({ error: 'Login required' }), { status: 401 });
  }

  // Check and deduct 5 credits for upload
  const UPLOAD_COST = 5;
  const creditResult = await checkAndDeductCredits(env, subdomain, UPLOAD_COST);
  if (!creditResult.success) {
    return new Response(JSON.stringify({
      error: 'Insufficient credits',
      balance: creditResult.balance,
      required: UPLOAD_COST
    }), { status: 402 });
  }

  const formData = await request.formData();
  const file = formData.get('file');
  const isPublic = formData.get('public') !== 'false';

  if (!file) {
    // Refund credits if no file
    await refundCredits(env, subdomain, UPLOAD_COST);
    return new Response(JSON.stringify({ error: 'No file provided' }), { status: 400 });
  }

  // Validate file type
  const allowedTypes = [
    'image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/svg+xml',
    'application/pdf', 'text/plain', 'text/csv'
  ];
  if (!allowedTypes.includes(file.type)) {
    // Refund credits if invalid type
    await refundCredits(env, subdomain, UPLOAD_COST);
    return new Response(JSON.stringify({ error: `File type not allowed. Allowed: ${allowedTypes.join(', ')}` }), { status: 400 });
  }

  // Size limit: 10MB for images, 25MB for PDFs
  const maxSize = file.type === 'application/pdf' ? 25 * 1024 * 1024 : 10 * 1024 * 1024;
  if (file.size > maxSize) {
    // Refund credits if file too large
    await refundCredits(env, subdomain, UPLOAD_COST);
    return new Response(JSON.stringify({ error: `File too large (max ${maxSize / 1024 / 1024}MB)` }), { status: 413 });
  }

  const id = generateId();
  const ext = file.name.split('.').pop()?.toLowerCase() || 'bin';
  const filename = `${id}.${ext}`;
  const path = `${subdomain}/uploads/${user.id}/${filename}`;

  // Upload to R2
  await env.SITES.put(path, file.stream(), {
    httpMetadata: { contentType: file.type }
  });

  // Store metadata
  await env.DB.prepare(`
    INSERT INTO uploads (id, app_subdomain, filename, original_filename, content_type, size, created_by, public)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(id, subdomain, filename, file.name, file.type, file.size, user.id, isPublic ? 1 : 0).run();

  // Track upload usage for stats
  await env.DB.prepare(`
    INSERT INTO upload_usage (id, app_subdomain, user_id, filename, content_type, size, credits_used)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).bind(id, subdomain, user.id, filename, file.type, file.size, UPLOAD_COST).run();

  // Build public URL
  const app = await env.DB.prepare('SELECT custom_domain FROM apps WHERE subdomain = ?').bind(subdomain).first();
  const baseUrl = app?.custom_domain ? `https://${app.custom_domain}` : `https://${subdomain}.itsalive.co`;

  return {
    id,
    url: `${baseUrl}/uploads/${user.id}/${filename}`,
    filename: file.name,
    content_type: file.type,
    size: file.size,
    credits_used: UPLOAD_COST
  };
});

// GET /uploads - List user's uploads
router.get('/uploads', async (request, env) => {
  const subdomain = getSubdomain(request);
  if (!subdomain) {
    return new Response(JSON.stringify({ error: 'Invalid origin' }), { status: 400 });
  }

  const user = await getSession(request, env);
  if (!user) {
    return new Response(JSON.stringify({ error: 'Login required' }), { status: 401 });
  }

  const url = new URL(request.url);
  const limit = Math.min(parseInt(url.searchParams.get('limit') || '50'), 100);
  const offset = parseInt(url.searchParams.get('offset') || '0');

  const uploads = await env.DB.prepare(`
    SELECT id, filename, original_filename, content_type, size, created_at
    FROM uploads
    WHERE app_subdomain = ? AND created_by = ?
    ORDER BY created_at DESC
    LIMIT ? OFFSET ?
  `).bind(subdomain, user.id, limit, offset).all();

  // Build URLs
  const app = await env.DB.prepare('SELECT custom_domain FROM apps WHERE subdomain = ?').bind(subdomain).first();
  const baseUrl = app?.custom_domain ? `https://${app.custom_domain}` : `https://${subdomain}.itsalive.co`;

  const items = uploads.results.map(u => ({
    ...u,
    url: `${baseUrl}/uploads/${user.id}/${u.filename}`
  }));

  return { items, limit, offset };
});

// DELETE /uploads/:id - Delete an upload
router.delete('/uploads/:id', async (request, env) => {
  const subdomain = getSubdomain(request);
  if (!subdomain) {
    return new Response(JSON.stringify({ error: 'Invalid origin' }), { status: 400 });
  }

  const user = await getSession(request, env);
  const { id } = request.params;

  const upload = await env.DB.prepare(
    'SELECT * FROM uploads WHERE id = ? AND app_subdomain = ?'
  ).bind(id, subdomain).first();

  if (!upload) {
    return new Response(JSON.stringify({ error: 'Not found' }), { status: 404 });
  }

  // Only creator or app owner can delete
  const isOwner = user && await isAppOwner(env, subdomain, user.email);
  if (upload.created_by !== user?.id && !isOwner) {
    return new Response(JSON.stringify({ error: 'Not authorized' }), { status: 403 });
  }

  // Delete from R2
  const path = `${subdomain}/uploads/${upload.created_by}/${upload.filename}`;
  await env.SITES.delete(path);

  // Delete metadata
  await env.DB.prepare('DELETE FROM uploads WHERE id = ?').bind(id).run();

  return { success: true };
});

// ============ EMAIL SENDING ENDPOINTS ============

// Helper to render template with {{variable}} replacement
function renderTemplate(template, data) {
  return template.replace(/\{\{(\w+)\}\}/g, (match, key) => {
    return data[key] !== undefined ? String(data[key]) : match;
  });
}

// Helper to validate deploy token
async function validateDeployToken(env, subdomain, token) {
  const tokenData = await env.DB.prepare(
    'SELECT subdomain FROM deploy_tokens WHERE token = ?'
  ).bind(token).first();
  return tokenData && tokenData.subdomain === subdomain;
}

// POST /email/send - Send an email (owner or deploy_token only)
router.post('/email/send', async (request, env) => {
  const subdomain = getSubdomain(request);
  if (!subdomain) {
    return new Response(JSON.stringify({ error: 'Invalid origin' }), { status: 400 });
  }

  const { to, subject, html, text, template, template_data, deploy_token, reply_to } = await request.json();

  // Auth: deploy_token or logged-in owner
  const user = await getSession(request, env);
  const isOwner = user && await isAppOwner(env, subdomain, user.email);
  const validToken = deploy_token && await validateDeployToken(env, subdomain, deploy_token);

  if (!isOwner && !validToken) {
    return new Response(JSON.stringify({ error: 'Only app owner can send emails' }), { status: 403 });
  }

  if (!to) {
    return new Response(JSON.stringify({ error: 'to is required' }), { status: 400 });
  }

  // Validate email format
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(to)) {
    return new Response(JSON.stringify({ error: 'Invalid email address' }), { status: 400 });
  }

  // Check rate limit
  const rateLimit = await checkEmailRateLimit(env, subdomain);
  if (!rateLimit.allowed) {
    return new Response(JSON.stringify({ error: 'Rate limit exceeded: 100 emails per hour' }), { status: 429 });
  }

  // Get branding and settings
  const branding = await getAppBranding(env, subdomain);

  // Get app settings for reply-to and custom domain
  const settings = await env.DB.prepare(
    'SELECT email_reply_to, email_from_name FROM app_settings WHERE app_subdomain = ?'
  ).bind(subdomain).first();

  // Build HTML content
  let emailHtml = html || '';
  let emailSubject = subject;

  if (template) {
    const tpl = await env.DB.prepare(
      'SELECT * FROM email_templates WHERE app_subdomain = ? AND name = ?'
    ).bind(subdomain, template).first();

    if (tpl) {
      emailHtml = renderTemplate(tpl.html_body, template_data || {});
      // Use template subject if no subject provided
      if (!emailSubject) {
        emailSubject = renderTemplate(tpl.subject, template_data || {});
      }
    } else {
      return new Response(JSON.stringify({ error: `Template '${template}' not found` }), { status: 404 });
    }
  }

  // Ensure we have a subject (either from request or template)
  if (!emailSubject) {
    return new Response(JSON.stringify({ error: 'subject is required (or use a template)' }), { status: 400 });
  }

  // Spam check
  const spamResult = await checkSpam(env, emailSubject, emailHtml, subdomain);
  if (spamResult.blocked) {
    return new Response(JSON.stringify({
      error: 'Email blocked by spam filter',
      reason: spamResult.reason,
      score: spamResult.score
    }), { status: 400 });
  }

  // Check for verified custom domain
  const verifiedDomain = await env.DB.prepare(
    'SELECT domain FROM email_domains WHERE app_subdomain = ? AND status = ?'
  ).bind(subdomain, 'verified').first();

  // Check if recipient is a subscriber and add unsubscribe link
  const subscriber = await env.DB.prepare(
    'SELECT unsubscribe_token FROM subscribers WHERE app_subdomain = ? AND email = ? AND status = ?'
  ).bind(subdomain, to, 'active').first();

  // Wrap in branded template
  let finalHtml = emailTemplate({
    buttonText: null,
    buttonUrl: null,
    footer: emailHtml,
    branding,
  });

  // Add unsubscribe link if sending to a subscriber
  if (subscriber) {
    const unsubUrl = `https://api.itsalive.co/unsubscribe?token=${subscriber.unsubscribe_token}`;
    finalHtml = addUnsubscribeFooter(finalHtml, unsubUrl);
  }

  // Send via Resend
  const id = generateId();
  try {
    const emailOptions = {
      fromName: settings?.email_from_name || branding.appName || subdomain,
      replyTo: reply_to || settings?.email_reply_to,
      fromDomain: verifiedDomain?.domain,
    };

    const sent = await sendEmail(env, to, emailSubject, finalHtml, emailOptions);

    await env.DB.prepare(`
      INSERT INTO email_log (id, app_subdomain, to_email, subject, template, status, sent_at)
      VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
    `).bind(id, subdomain, to, emailSubject, template || 'custom', sent ? 'sent' : 'failed').run();

    if (!sent) {
      return new Response(JSON.stringify({ error: 'Failed to send email' }), { status: 500 });
    }

    return { id, status: 'sent', rate_limit_remaining: rateLimit.remaining };
  } catch (e) {
    await env.DB.prepare(`
      INSERT INTO email_log (id, app_subdomain, to_email, subject, template, status, error_message)
      VALUES (?, ?, ?, ?, ?, 'failed', ?)
    `).bind(id, subdomain, to, emailSubject, template || 'custom', e.message).run();

    return new Response(JSON.stringify({ error: 'Failed to send email', details: e.message }), { status: 500 });
  }
});

// POST /email/send-bulk - Send to multiple recipients
router.post('/email/send-bulk', async (request, env) => {
  const subdomain = getSubdomain(request);
  if (!subdomain) {
    return new Response(JSON.stringify({ error: 'Invalid origin' }), { status: 400 });
  }

  const { recipients, subject, html, template, template_data, deploy_token } = await request.json();

  // Auth check
  const user = await getSession(request, env);
  const isOwner = user && await isAppOwner(env, subdomain, user.email);
  const validToken = deploy_token && await validateDeployToken(env, subdomain, deploy_token);

  if (!isOwner && !validToken) {
    return new Response(JSON.stringify({ error: 'Only app owner can send emails' }), { status: 403 });
  }

  if (!recipients || !Array.isArray(recipients) || recipients.length === 0) {
    return new Response(JSON.stringify({ error: 'recipients array required' }), { status: 400 });
  }

  if (recipients.length > 100) {
    return new Response(JSON.stringify({ error: 'Maximum 100 recipients per request' }), { status: 400 });
  }

  if (!subject) {
    return new Response(JSON.stringify({ error: 'subject required' }), { status: 400 });
  }

  const results = [];
  for (const recipient of recipients) {
    const to = typeof recipient === 'string' ? recipient : recipient.email;
    const personalized = typeof recipient === 'object' ? { ...template_data, ...recipient } : template_data;

    // Queue each email as a job for async processing
    const jobId = generateId();
    await env.DB.prepare(`
      INSERT INTO jobs (id, app_subdomain, type, data, run_at)
      VALUES (?, ?, 'email', ?, datetime('now'))
    `).bind(jobId, subdomain, JSON.stringify({ to, subject, html, template, template_data: personalized })).run();

    results.push({ email: to, job_id: jobId, status: 'queued' });
  }

  return { queued: results.length, results };
});

// GET /email/templates - List email templates
router.get('/email/templates', async (request, env) => {
  const subdomain = getSubdomain(request);
  if (!subdomain) {
    return new Response(JSON.stringify({ error: 'Invalid origin' }), { status: 400 });
  }

  const user = await getSession(request, env);
  const url = new URL(request.url);
  const deploy_token = url.searchParams.get('deploy_token');

  const isOwner = user && await isAppOwner(env, subdomain, user.email);
  const validToken = deploy_token && await validateDeployToken(env, subdomain, deploy_token);

  if (!isOwner && !validToken) {
    return new Response(JSON.stringify({ error: 'Not authorized' }), { status: 403 });
  }

  const templates = await env.DB.prepare(
    'SELECT id, name, subject, created_at, updated_at FROM email_templates WHERE app_subdomain = ?'
  ).bind(subdomain).all();

  return { templates: templates.results };
});

// PUT /email/templates/:name - Create/update email template
router.put('/email/templates/:name', async (request, env) => {
  const subdomain = getSubdomain(request);
  if (!subdomain) {
    return new Response(JSON.stringify({ error: 'Invalid origin' }), { status: 400 });
  }

  const { name } = request.params;
  const { subject, html_body, deploy_token } = await request.json();

  // Auth check
  const user = await getSession(request, env);
  const isOwner = user && await isAppOwner(env, subdomain, user.email);
  const validToken = deploy_token && await validateDeployToken(env, subdomain, deploy_token);

  if (!isOwner && !validToken) {
    return new Response(JSON.stringify({ error: 'Not authorized' }), { status: 403 });
  }

  if (!subject || !html_body) {
    return new Response(JSON.stringify({ error: 'subject and html_body required' }), { status: 400 });
  }

  await env.DB.prepare(`
    INSERT INTO email_templates (id, app_subdomain, name, subject, html_body)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(app_subdomain, name) DO UPDATE SET
      subject = excluded.subject,
      html_body = excluded.html_body,
      updated_at = datetime('now')
  `).bind(generateId(), subdomain, name, subject, html_body).run();

  return { success: true, name };
});

// DELETE /email/templates/:name - Delete email template
router.delete('/email/templates/:name', async (request, env) => {
  const subdomain = getSubdomain(request);
  if (!subdomain) {
    return new Response(JSON.stringify({ error: 'Invalid origin' }), { status: 400 });
  }

  const { name } = request.params;

  // Auth check
  const user = await getSession(request, env);
  const isOwner = user && await isAppOwner(env, subdomain, user.email);

  if (!isOwner) {
    return new Response(JSON.stringify({ error: 'Not authorized' }), { status: 403 });
  }

  await env.DB.prepare(
    'DELETE FROM email_templates WHERE app_subdomain = ? AND name = ?'
  ).bind(subdomain, name).run();

  return { success: true };
});

// GET /email/log - Get email sending history
router.get('/email/log', async (request, env) => {
  const subdomain = getSubdomain(request);
  if (!subdomain) {
    return new Response(JSON.stringify({ error: 'Invalid origin' }), { status: 400 });
  }

  const url = new URL(request.url);
  const deploy_token = url.searchParams.get('deploy_token');

  const user = await getSession(request, env);
  const isOwner = user && await isAppOwner(env, subdomain, user.email);
  const validToken = deploy_token && await validateDeployToken(env, subdomain, deploy_token);

  if (!isOwner && !validToken) {
    return new Response(JSON.stringify({ error: 'Not authorized' }), { status: 403 });
  }
  const limit = Math.min(parseInt(url.searchParams.get('limit') || '50'), 100);
  const offset = parseInt(url.searchParams.get('offset') || '0');

  const logs = await env.DB.prepare(`
    SELECT id, to_email, subject, template, status, error_message, created_at, sent_at
    FROM email_log
    WHERE app_subdomain = ?
    ORDER BY created_at DESC
    LIMIT ? OFFSET ?
  `).bind(subdomain, limit, offset).all();

  return { items: logs.results, limit, offset };
});

// ============ SUBSCRIBER MANAGEMENT ENDPOINTS ============

// POST /subscribers - Add a subscriber (public, rate limited)
router.post('/subscribers', async (request, env) => {
  const subdomain = getSubdomain(request);
  if (!subdomain) {
    return new Response(JSON.stringify({ error: 'Invalid origin' }), { status: 400 });
  }

  // Rate limit: 10 subscribes per minute per IP
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const rateLimitKey = `subscribe_rate:${subdomain}:${ip}`;
  const currentRate = await env.RATE_LIMITS.get(rateLimitKey);
  const rateCount = currentRate ? parseInt(currentRate) : 0;

  if (rateCount >= 10) {
    return new Response(JSON.stringify({ error: 'Rate limit exceeded' }), { status: 429 });
  }

  await env.RATE_LIMITS.put(rateLimitKey, String(rateCount + 1), { expirationTtl: 60 });

  const { email, tags, metadata } = await request.json();

  if (!email) {
    return new Response(JSON.stringify({ error: 'email is required' }), { status: 400 });
  }

  // Validate email format
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return new Response(JSON.stringify({ error: 'Invalid email address' }), { status: 400 });
  }

  // Check if subscriber already exists
  const existing = await env.DB.prepare(
    'SELECT id, status FROM subscribers WHERE app_subdomain = ? AND email = ?'
  ).bind(subdomain, email).first();

  if (existing) {
    if (existing.status === 'active') {
      return { id: existing.id, status: 'already_subscribed' };
    }
    // Reactivate unsubscribed subscriber
    await env.DB.prepare(
      'UPDATE subscribers SET status = ?, unsubscribed_at = NULL, updated_at = datetime("now") WHERE id = ?'
    ).bind('active', existing.id).run();
    return { id: existing.id, status: 'resubscribed' };
  }

  const id = generateId();
  const unsubscribeToken = generateToken();

  await env.DB.prepare(`
    INSERT INTO subscribers (id, app_subdomain, email, tags, metadata, source, unsubscribe_token)
    VALUES (?, ?, ?, ?, ?, 'form', ?)
  `).bind(
    id,
    subdomain,
    email,
    tags ? JSON.stringify(tags) : null,
    metadata ? JSON.stringify(metadata) : null,
    unsubscribeToken
  ).run();

  return { id, status: 'subscribed' };
});

// GET /subscribers - List subscribers (owner/deploy_token only)
router.get('/subscribers', async (request, env) => {
  const subdomain = getSubdomain(request);
  if (!subdomain) {
    return new Response(JSON.stringify({ error: 'Invalid origin' }), { status: 400 });
  }

  const url = new URL(request.url);
  const deploy_token = url.searchParams.get('deploy_token');

  const user = await getSession(request, env);
  const isOwner = user && await isAppOwner(env, subdomain, user.email);
  const validToken = deploy_token && await validateDeployToken(env, subdomain, deploy_token);

  if (!isOwner && !validToken) {
    return new Response(JSON.stringify({ error: 'Not authorized' }), { status: 403 });
  }

  const tag = url.searchParams.get('tag');
  const status = url.searchParams.get('status') || 'active';
  const limit = Math.min(parseInt(url.searchParams.get('limit') || '100'), 1000);
  const offset = parseInt(url.searchParams.get('offset') || '0');

  let query = 'SELECT id, email, tags, status, metadata, source, subscribed_at, unsubscribed_at FROM subscribers WHERE app_subdomain = ?';
  const params = [subdomain];

  if (status && status !== 'all') {
    query += ' AND status = ?';
    params.push(status);
  }

  if (tag) {
    query += ' AND tags LIKE ?';
    params.push(`%"${tag}"%`);
  }

  // Get total count
  const countQuery = query.replace('SELECT id, email, tags, status, metadata, source, subscribed_at, unsubscribed_at', 'SELECT COUNT(*) as total');
  const countResult = await env.DB.prepare(countQuery).bind(...params).first();

  query += ' ORDER BY subscribed_at DESC LIMIT ? OFFSET ?';
  params.push(limit, offset);

  const subscribers = await env.DB.prepare(query).bind(...params).all();

  // Parse JSON fields
  const items = subscribers.results.map(s => ({
    ...s,
    tags: s.tags ? JSON.parse(s.tags) : [],
    metadata: s.metadata ? JSON.parse(s.metadata) : {},
  }));

  return { items, total: countResult?.total || 0, limit, offset };
});

// PUT /subscribers/:id - Update subscriber (owner/deploy_token only)
router.put('/subscribers/:id', async (request, env) => {
  const subdomain = getSubdomain(request);
  if (!subdomain) {
    return new Response(JSON.stringify({ error: 'Invalid origin' }), { status: 400 });
  }

  const { id } = request.params;
  const { tags, metadata, status, deploy_token } = await request.json();

  const user = await getSession(request, env);
  const isOwner = user && await isAppOwner(env, subdomain, user.email);
  const validToken = deploy_token && await validateDeployToken(env, subdomain, deploy_token);

  if (!isOwner && !validToken) {
    return new Response(JSON.stringify({ error: 'Not authorized' }), { status: 403 });
  }

  // Check subscriber exists
  const existing = await env.DB.prepare(
    'SELECT * FROM subscribers WHERE id = ? AND app_subdomain = ?'
  ).bind(id, subdomain).first();

  if (!existing) {
    return new Response(JSON.stringify({ error: 'Subscriber not found' }), { status: 404 });
  }

  const updates = [];
  const updateParams = [];

  if (tags !== undefined) {
    updates.push('tags = ?');
    updateParams.push(JSON.stringify(tags));
  }

  if (metadata !== undefined) {
    updates.push('metadata = ?');
    updateParams.push(JSON.stringify(metadata));
  }

  if (status !== undefined && ['active', 'unsubscribed', 'bounced'].includes(status)) {
    updates.push('status = ?');
    updateParams.push(status);
    if (status === 'unsubscribed') {
      updates.push('unsubscribed_at = datetime("now")');
    }
  }

  if (updates.length === 0) {
    return new Response(JSON.stringify({ error: 'No valid fields to update' }), { status: 400 });
  }

  updates.push('updated_at = datetime("now")');
  updateParams.push(id, subdomain);

  await env.DB.prepare(
    `UPDATE subscribers SET ${updates.join(', ')} WHERE id = ? AND app_subdomain = ?`
  ).bind(...updateParams).run();

  return { success: true, id };
});

// DELETE /subscribers/:id - Remove subscriber (owner/deploy_token only)
router.delete('/subscribers/:id', async (request, env) => {
  const subdomain = getSubdomain(request);
  if (!subdomain) {
    return new Response(JSON.stringify({ error: 'Invalid origin' }), { status: 400 });
  }

  const { id } = request.params;
  const url = new URL(request.url);
  const deploy_token = url.searchParams.get('deploy_token');

  const user = await getSession(request, env);
  const isOwner = user && await isAppOwner(env, subdomain, user.email);
  const validToken = deploy_token && await validateDeployToken(env, subdomain, deploy_token);

  if (!isOwner && !validToken) {
    return new Response(JSON.stringify({ error: 'Not authorized' }), { status: 403 });
  }

  await env.DB.prepare(
    'DELETE FROM subscribers WHERE id = ? AND app_subdomain = ?'
  ).bind(id, subdomain).run();

  return { success: true };
});

// GET /unsubscribe - One-click unsubscribe (public)
router.get('/unsubscribe', async (request, env) => {
  const url = new URL(request.url);
  const token = url.searchParams.get('token');

  if (!token) {
    return new Response('<html><body><h1>Invalid unsubscribe link</h1></body></html>', {
      status: 400,
      headers: { 'Content-Type': 'text/html' }
    });
  }

  const subscriber = await env.DB.prepare(
    'SELECT id, app_subdomain, email FROM subscribers WHERE unsubscribe_token = ?'
  ).bind(token).first();

  if (!subscriber) {
    return new Response('<html><body><h1>Invalid or expired unsubscribe link</h1></body></html>', {
      status: 404,
      headers: { 'Content-Type': 'text/html' }
    });
  }

  await env.DB.prepare(
    'UPDATE subscribers SET status = ?, unsubscribed_at = datetime("now"), updated_at = datetime("now") WHERE id = ?'
  ).bind('unsubscribed', subscriber.id).run();

  return new Response(`
    <html>
    <head>
      <title>Unsubscribed</title>
      <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 500px; margin: 100px auto; text-align: center; padding: 20px; }
        h1 { color: #333; }
        p { color: #666; }
      </style>
    </head>
    <body>
      <h1>You've been unsubscribed</h1>
      <p>You will no longer receive emails from this app.</p>
      <p style="margin-top: 30px; font-size: 12px; color: #999;">${subscriber.email}</p>
    </body>
    </html>
  `, {
    headers: { 'Content-Type': 'text/html' }
  });
});

// ============ EMAIL DOMAINS ENDPOINTS (Paid Plans Only) ============

// Helper to check if app has active subscription
async function hasActiveSubscription(env, subdomain) {
  const subscription = await env.DB.prepare(
    'SELECT id FROM subscriptions WHERE app_subdomain = ? AND status = ?'
  ).bind(subdomain, 'active').first();
  return !!subscription;
}

// POST /email/domains - Add a custom email domain (paid only)
router.post('/email/domains', async (request, env) => {
  const subdomain = getSubdomain(request);
  if (!subdomain) {
    return new Response(JSON.stringify({ error: 'Invalid origin' }), { status: 400 });
  }

  const user = await getSession(request, env);
  const isOwner = user && await isAppOwner(env, subdomain, user.email);

  if (!isOwner) {
    return new Response(JSON.stringify({ error: 'Only app owner can add email domains' }), { status: 403 });
  }

  // Check for paid subscription
  if (!await hasActiveSubscription(env, subdomain)) {
    return new Response(JSON.stringify({ error: 'Custom email domains require an active Pro subscription' }), { status: 402 });
  }

  const { domain } = await request.json();

  if (!domain) {
    return new Response(JSON.stringify({ error: 'domain is required' }), { status: 400 });
  }

  // Validate domain format
  if (!/^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,}$/i.test(domain)) {
    return new Response(JSON.stringify({ error: 'Invalid domain format' }), { status: 400 });
  }

  // Check if domain already exists
  const existing = await env.DB.prepare(
    'SELECT id FROM email_domains WHERE app_subdomain = ? AND domain = ?'
  ).bind(subdomain, domain).first();

  if (existing) {
    return new Response(JSON.stringify({ error: 'Domain already added' }), { status: 409 });
  }

  // Add domain to Resend
  const resendRes = await fetch('https://api.resend.com/domains', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${env.RESEND_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ name: domain }),
  });

  if (!resendRes.ok) {
    const error = await resendRes.text();
    console.error('Resend domain creation failed:', error);
    return new Response(JSON.stringify({ error: 'Failed to add domain to email provider' }), { status: 500 });
  }

  const resendData = await resendRes.json();

  const id = generateId();
  await env.DB.prepare(`
    INSERT INTO email_domains (id, app_subdomain, domain, resend_domain_id, status, dns_records)
    VALUES (?, ?, ?, ?, 'pending', ?)
  `).bind(id, subdomain, domain, resendData.id, JSON.stringify(resendData.records || [])).run();

  return {
    id,
    domain,
    status: 'pending',
    dns_records: resendData.records || [],
    message: 'Add the following DNS records to your domain, then verify',
  };
});

// GET /email/domains - List email domains
router.get('/email/domains', async (request, env) => {
  const subdomain = getSubdomain(request);
  if (!subdomain) {
    return new Response(JSON.stringify({ error: 'Invalid origin' }), { status: 400 });
  }

  const user = await getSession(request, env);
  const isOwner = user && await isAppOwner(env, subdomain, user.email);

  if (!isOwner) {
    return new Response(JSON.stringify({ error: 'Not authorized' }), { status: 403 });
  }

  const domains = await env.DB.prepare(
    'SELECT id, domain, status, dns_records, verified_at, created_at FROM email_domains WHERE app_subdomain = ?'
  ).bind(subdomain).all();

  const items = domains.results.map(d => ({
    ...d,
    dns_records: d.dns_records ? JSON.parse(d.dns_records) : [],
  }));

  return { domains: items };
});

// POST /email/domains/:id/verify - Verify DNS for custom domain
router.post('/email/domains/:id/verify', async (request, env) => {
  const subdomain = getSubdomain(request);
  if (!subdomain) {
    return new Response(JSON.stringify({ error: 'Invalid origin' }), { status: 400 });
  }

  const { id } = request.params;

  const user = await getSession(request, env);
  const isOwner = user && await isAppOwner(env, subdomain, user.email);

  if (!isOwner) {
    return new Response(JSON.stringify({ error: 'Not authorized' }), { status: 403 });
  }

  const emailDomain = await env.DB.prepare(
    'SELECT * FROM email_domains WHERE id = ? AND app_subdomain = ?'
  ).bind(id, subdomain).first();

  if (!emailDomain) {
    return new Response(JSON.stringify({ error: 'Domain not found' }), { status: 404 });
  }

  if (emailDomain.status === 'verified') {
    return { status: 'verified', message: 'Domain already verified' };
  }

  // Trigger verification with Resend
  const resendRes = await fetch(`https://api.resend.com/domains/${emailDomain.resend_domain_id}/verify`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${env.RESEND_API_KEY}`,
    },
  });

  if (!resendRes.ok) {
    const error = await resendRes.text();
    console.error('Resend domain verification failed:', error);
    return new Response(JSON.stringify({ error: 'Verification failed. Please check your DNS records.' }), { status: 400 });
  }

  // Check domain status
  const statusRes = await fetch(`https://api.resend.com/domains/${emailDomain.resend_domain_id}`, {
    headers: {
      'Authorization': `Bearer ${env.RESEND_API_KEY}`,
    },
  });

  if (statusRes.ok) {
    const statusData = await statusRes.json();

    if (statusData.status === 'verified') {
      await env.DB.prepare(
        'UPDATE email_domains SET status = ?, verified_at = datetime("now") WHERE id = ?'
      ).bind('verified', id).run();

      return { status: 'verified', message: 'Domain verified successfully' };
    }

    return {
      status: statusData.status,
      message: 'Verification in progress. DNS records may take time to propagate.',
      dns_records: statusData.records || [],
    };
  }

  return { status: 'pending', message: 'Verification in progress' };
});

// DELETE /email/domains/:id - Remove custom domain
router.delete('/email/domains/:id', async (request, env) => {
  const subdomain = getSubdomain(request);
  if (!subdomain) {
    return new Response(JSON.stringify({ error: 'Invalid origin' }), { status: 400 });
  }

  const { id } = request.params;

  const user = await getSession(request, env);
  const isOwner = user && await isAppOwner(env, subdomain, user.email);

  if (!isOwner) {
    return new Response(JSON.stringify({ error: 'Not authorized' }), { status: 403 });
  }

  const emailDomain = await env.DB.prepare(
    'SELECT resend_domain_id FROM email_domains WHERE id = ? AND app_subdomain = ?'
  ).bind(id, subdomain).first();

  if (!emailDomain) {
    return new Response(JSON.stringify({ error: 'Domain not found' }), { status: 404 });
  }

  // Delete from Resend
  if (emailDomain.resend_domain_id) {
    await fetch(`https://api.resend.com/domains/${emailDomain.resend_domain_id}`, {
      method: 'DELETE',
      headers: {
        'Authorization': `Bearer ${env.RESEND_API_KEY}`,
      },
    });
  }

  await env.DB.prepare(
    'DELETE FROM email_domains WHERE id = ?'
  ).bind(id).run();

  return { success: true };
});

// ============ EMAIL SETTINGS ENDPOINTS ============

// PUT /email/settings - Update email settings (reply-to, from name)
router.put('/email/settings', async (request, env) => {
  const subdomain = getSubdomain(request);
  if (!subdomain) {
    return new Response(JSON.stringify({ error: 'Invalid origin' }), { status: 400 });
  }

  const { email_reply_to, email_from_name, deploy_token } = await request.json();

  const user = await getSession(request, env);
  const isOwner = user && await isAppOwner(env, subdomain, user.email);
  const validToken = deploy_token && await validateDeployToken(env, subdomain, deploy_token);

  if (!isOwner && !validToken) {
    return new Response(JSON.stringify({ error: 'Not authorized' }), { status: 403 });
  }

  // Validate reply-to email if provided
  if (email_reply_to && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email_reply_to)) {
    return new Response(JSON.stringify({ error: 'Invalid reply-to email address' }), { status: 400 });
  }

  // Upsert app settings
  await env.DB.prepare(`
    INSERT INTO app_settings (app_subdomain, email_reply_to, email_from_name, updated_at)
    VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(app_subdomain) DO UPDATE SET
      email_reply_to = COALESCE(excluded.email_reply_to, email_reply_to),
      email_from_name = COALESCE(excluded.email_from_name, email_from_name),
      updated_at = datetime('now')
  `).bind(subdomain, email_reply_to || null, email_from_name || null).run();

  return { success: true, email_reply_to, email_from_name };
});

// GET /email/settings - Get email settings
router.get('/email/settings', async (request, env) => {
  const subdomain = getSubdomain(request);
  if (!subdomain) {
    return new Response(JSON.stringify({ error: 'Invalid origin' }), { status: 400 });
  }

  const url = new URL(request.url);
  const deploy_token = url.searchParams.get('deploy_token');

  const user = await getSession(request, env);
  const isOwner = user && await isAppOwner(env, subdomain, user.email);
  const validToken = deploy_token && await validateDeployToken(env, subdomain, deploy_token);

  if (!isOwner && !validToken) {
    return new Response(JSON.stringify({ error: 'Not authorized' }), { status: 403 });
  }

  const settings = await env.DB.prepare(
    'SELECT email_reply_to, email_from_name FROM app_settings WHERE app_subdomain = ?'
  ).bind(subdomain).first();

  return {
    email_reply_to: settings?.email_reply_to || null,
    email_from_name: settings?.email_from_name || null,
  };
});

// ============ AGGREGATION ENDPOINTS ============

// ============ WEBHOOKS ENDPOINTS ============

// GET /webhooks - List webhooks for this app
router.get('/webhooks', async (request, env) => {
  const subdomain = getSubdomain(request);
  if (!subdomain) {
    return new Response(JSON.stringify({ error: 'Invalid origin' }), { status: 400 });
  }

  const url = new URL(request.url);
  const deploy_token = url.searchParams.get('deploy_token');

  const user = await getSession(request, env);
  const isOwner = user && await isAppOwner(env, subdomain, user.email);
  const validToken = deploy_token && await validateDeployToken(env, subdomain, deploy_token);

  if (!isOwner && !validToken) {
    return new Response(JSON.stringify({ error: 'Only app owner can manage webhooks' }), { status: 403 });
  }

  const webhooks = await env.DB.prepare(
    'SELECT id, collection, event, url, enabled, created_at FROM webhooks WHERE app_subdomain = ?'
  ).bind(subdomain).all();

  return { webhooks: webhooks.results };
});

// POST /webhooks - Create a webhook
router.post('/webhooks', async (request, env) => {
  const subdomain = getSubdomain(request);
  if (!subdomain) {
    return new Response(JSON.stringify({ error: 'Invalid origin' }), { status: 400 });
  }

  const { collection, event, url, secret, deploy_token } = await request.json();

  const user = await getSession(request, env);
  const isOwner = user && await isAppOwner(env, subdomain, user.email);
  const validToken = deploy_token && await validateDeployToken(env, subdomain, deploy_token);

  if (!isOwner && !validToken) {
    return new Response(JSON.stringify({ error: 'Only app owner can create webhooks' }), { status: 403 });
  }

  if (!collection || !event || !url) {
    return new Response(JSON.stringify({ error: 'collection, event, and url required' }), { status: 400 });
  }

  // Validate event type
  const validEvents = ['create', 'update', 'delete', 'all'];
  if (!validEvents.includes(event)) {
    return new Response(JSON.stringify({ error: `Invalid event. Valid: ${validEvents.join(', ')}` }), { status: 400 });
  }

  // Validate URL
  try {
    new URL(url);
  } catch {
    return new Response(JSON.stringify({ error: 'Invalid URL' }), { status: 400 });
  }

  const id = generateId();
  await env.DB.prepare(`
    INSERT INTO webhooks (id, app_subdomain, collection, event, url, secret)
    VALUES (?, ?, ?, ?, ?, ?)
  `).bind(id, subdomain, collection, event, url, secret || null).run();

  return { id, collection, event, url };
});

// DELETE /webhooks/:id - Delete a webhook
router.delete('/webhooks/:id', async (request, env) => {
  const subdomain = getSubdomain(request);
  if (!subdomain) {
    return new Response(JSON.stringify({ error: 'Invalid origin' }), { status: 400 });
  }

  const url = new URL(request.url);
  const deploy_token = url.searchParams.get('deploy_token');

  const user = await getSession(request, env);
  const isOwner = user && await isAppOwner(env, subdomain, user.email);
  const validToken = deploy_token && await validateDeployToken(env, subdomain, deploy_token);

  if (!isOwner && !validToken) {
    return new Response(JSON.stringify({ error: 'Only app owner can delete webhooks' }), { status: 403 });
  }

  const { id } = request.params;
  await env.DB.prepare('DELETE FROM webhooks WHERE id = ? AND app_subdomain = ?').bind(id, subdomain).run();

  return { success: true };
});

// ============ AI ENDPOINTS ============

// Model mappings for each provider
const AI_MODELS = {
  claude: {
    good: 'claude-sonnet-4-20250514',
    best: 'claude-opus-4-5-20251101',
  },
  gpt: {
    good: 'gpt-5-mini',
    best: 'gpt-5.2',
  },
  gemini: {
    good: 'gemini-2.5-flash',
    best: 'gemini-2.5-pro',
  },
};

// Approximate cost per 1M tokens (for tracking)
const TOKEN_COSTS = {
  'claude-sonnet-4-20250514': { input: 3.0, output: 15.0 },
  'claude-opus-4-5-20251101': { input: 15.0, output: 75.0 },
  'gpt-5-mini': { input: 0.15, output: 0.60 },
  'gpt-5.2': { input: 1.75, output: 14.0 },
  'gemini-2.5-flash': { input: 0.15, output: 0.60 },
  'gemini-2.5-pro': { input: 1.25, output: 10.00 },
};

// Tokens per credit by tier and provider (1 credit = $0.001)
// Targeting ~30% margin on each
const TOKENS_PER_CREDIT = {
  claude: {
    good: 75,   // Sonnet: ~$9/1M blended → 75 tokens/credit
    best: 15,   // Opus: ~$45/1M blended → 15 tokens/credit
  },
  gpt: {
    good: 1800, // gpt-4o-mini: ~$0.375/1M blended → 1800 tokens/credit
    best: 135,  // gpt-4o: ~$5.20/1M blended → 135 tokens/credit
  },
  gemini: {
    good: 1500, // gemini-2.5-flash: ~$0.45/1M blended → 1500 tokens/credit
    best: 100,  // gemini-2.5-pro: ~$7.08/1M blended → 100 tokens/credit
  },
};

// Helper to convert tokens to credits
function tokensToCredits(tokens, provider, tier) {
  const providerRates = TOKENS_PER_CREDIT[provider] || TOKENS_PER_CREDIT.claude;
  const rate = providerRates[tier] || providerRates.good;
  return Math.ceil(tokens / rate);
}

// Helper to get AI settings for an app
async function getAiSettings(env, subdomain) {
  const settings = await env.DB.prepare(
    'SELECT * FROM ai_settings WHERE app_subdomain = ?'
  ).bind(subdomain).first();

  return settings || {
    max_input_tokens: 4096,
    max_output_tokens: 4096,
    allowed_tiers: 'good,best',
    enabled: 1,
  };
}

// Helper to get owner_id from subdomain
async function getOwnerIdFromSubdomain(env, subdomain) {
  const app = await env.DB.prepare(
    'SELECT owner_id FROM apps WHERE subdomain = ?'
  ).bind(subdomain).first();
  return app?.owner_id;
}

// Helper to check and deduct credits (owner-based)
async function checkAndDeductCredits(env, subdomain, creditsNeeded) {
  const ownerId = await getOwnerIdFromSubdomain(env, subdomain);
  if (!ownerId) {
    return { success: false, balance: 0, required: creditsNeeded, error: 'App not found' };
  }

  const credits = await env.DB.prepare(
    'SELECT balance FROM owner_credits WHERE owner_id = ?'
  ).bind(ownerId).first();

  const balance = credits?.balance || 0;

  if (balance < creditsNeeded) {
    return { success: false, balance, required: creditsNeeded };
  }

  // Deduct credits
  await env.DB.prepare(`
    UPDATE owner_credits
    SET balance = balance - ?, lifetime_used = lifetime_used + ?, updated_at = datetime('now')
    WHERE owner_id = ?
  `).bind(creditsNeeded, creditsNeeded, ownerId).run();

  const newBalance = balance - creditsNeeded;

  // Trigger auto-refill check in background (non-blocking)
  // This runs asynchronously so we don't delay the response
  checkAutoRefill(env, ownerId).catch(e => console.error('Auto-refill check failed:', e));

  return { success: true, balance: newBalance, owner_id: ownerId };
}

// Helper to refund credits if request fails (owner-based)
async function refundCredits(env, subdomain, credits) {
  const ownerId = await getOwnerIdFromSubdomain(env, subdomain);
  if (!ownerId) return;

  await env.DB.prepare(`
    UPDATE owner_credits
    SET balance = balance + ?, lifetime_used = lifetime_used - ?, updated_at = datetime('now')
    WHERE owner_id = ?
  `).bind(credits, credits, ownerId).run();
}

// POST /ai/chat - Send a chat request to an AI provider
router.post('/ai/chat', async (request, env) => {
  const subdomain = getSubdomain(request);
  if (!subdomain) {
    return new Response(JSON.stringify({ error: 'Invalid origin' }), { status: 400 });
  }

  const body = await request.json();
  const { provider = 'claude', tier = 'good', messages, system, max_tokens, response_format, deploy_token } = body;

  // Auth: deploy_token or logged-in user
  const user = await getSession(request, env);
  const validToken = deploy_token && await validateDeployToken(env, subdomain, deploy_token);

  if (!user && !validToken) {
    return new Response(JSON.stringify({ error: 'Authentication required' }), { status: 401 });
  }

  // Validate provider
  if (!AI_MODELS[provider]) {
    return new Response(JSON.stringify({ error: `Invalid provider. Available: ${Object.keys(AI_MODELS).join(', ')}` }), { status: 400 });
  }

  // Validate tier
  if (!['good', 'best'].includes(tier)) {
    return new Response(JSON.stringify({ error: 'Invalid tier. Use "good" or "best"' }), { status: 400 });
  }

  // Validate response_format
  if (response_format && !['text', 'json'].includes(response_format)) {
    return new Response(JSON.stringify({ error: 'Invalid response_format. Use "text" or "json"' }), { status: 400 });
  }

  // Validate messages
  if (!messages || !Array.isArray(messages) || messages.length === 0) {
    return new Response(JSON.stringify({ error: 'messages array is required' }), { status: 400 });
  }

  // Get AI settings for this app
  const settings = await getAiSettings(env, subdomain);

  if (!settings.enabled) {
    return new Response(JSON.stringify({ error: 'AI is disabled for this app' }), { status: 403 });
  }

  // Check if tier is allowed
  const allowedTiers = settings.allowed_tiers.split(',');
  if (!allowedTiers.includes(tier)) {
    return new Response(JSON.stringify({ error: `Tier "${tier}" is not enabled for this app` }), { status: 403 });
  }

  // Get the model
  const model = AI_MODELS[provider][tier];

  // Calculate max tokens (use provided or default)
  const outputTokens = Math.min(max_tokens || settings.max_output_tokens, settings.max_output_tokens);

  // Estimate input tokens (rough: 4 chars per token)
  let inputText = system || '';
  let hasVision = false;
  for (const msg of messages) {
    if (typeof msg.content === 'string') {
      inputText += msg.content;
    } else if (Array.isArray(msg.content)) {
      // Multimodal message
      for (const part of msg.content) {
        if (part.type === 'text') {
          inputText += part.text || '';
        } else if (part.type === 'image') {
          hasVision = true;
          // Images cost roughly 1000 tokens for a typical image
          inputText += 'X'.repeat(4000);
        }
      }
    }
  }
  const estimatedInputTokens = Math.ceil(inputText.length / 4);

  // Check input token limit
  if (estimatedInputTokens > settings.max_input_tokens) {
    return new Response(JSON.stringify({
      error: `Input too large. Estimated ${estimatedInputTokens} tokens, max ${settings.max_input_tokens}`
    }), { status: 400 });
  }

  // Estimate total tokens and convert to credits
  const estimatedTotalTokens = estimatedInputTokens + outputTokens;
  const estimatedCredits = tokensToCredits(estimatedTotalTokens, provider, tier);

  // Check and deduct credits
  const creditCheck = await checkAndDeductCredits(env, subdomain, estimatedCredits);
  if (!creditCheck.success) {
    return new Response(JSON.stringify({
      error: 'Insufficient credits',
      balance: creditCheck.balance,
      required: creditCheck.required,
      tokens_per_credit: TOKENS_PER_CREDIT[provider]?.[tier] || TOKENS_PER_CREDIT.claude[tier],
    }), { status: 402 });
  }

  // Make the API call based on provider
  let result;
  let actualInputTokens = 0;
  let actualOutputTokens = 0;

  try {
    if (provider === 'claude') {
      result = await callClaude(env, model, messages, system, outputTokens);
      actualInputTokens = result.usage?.input_tokens || estimatedInputTokens;
      actualOutputTokens = result.usage?.output_tokens || 0;
    } else if (provider === 'gpt') {
      result = await callGPT(env, model, messages, system, outputTokens);
      actualInputTokens = result.usage?.prompt_tokens || estimatedInputTokens;
      actualOutputTokens = result.usage?.completion_tokens || 0;
    } else if (provider === 'gemini') {
      result = await callGemini(env, model, messages, system, outputTokens);
      actualInputTokens = result.usage?.promptTokenCount || estimatedInputTokens;
      actualOutputTokens = result.usage?.candidatesTokenCount || 0;
    } else {
      throw new Error(`Provider ${provider} not implemented yet`);
    }
  } catch (error) {
    // Refund the estimated credits on failure
    await refundCredits(env, subdomain, estimatedCredits);

    return new Response(JSON.stringify({
      error: 'AI request failed',
      details: error.message,
    }), { status: 500 });
  }

  // Calculate actual token usage and convert to credits
  const actualTotalTokens = actualInputTokens + actualOutputTokens;
  const actualCredits = tokensToCredits(actualTotalTokens, provider, tier);
  const creditDifference = estimatedCredits - actualCredits;

  if (creditDifference > 0) {
    // Refund the difference if we overestimated
    await refundCredits(env, subdomain, creditDifference);
  } else if (creditDifference < 0) {
    // Deduct more if we underestimated
    await checkAndDeductCredits(env, subdomain, -creditDifference);
  }

  // Calculate estimated cost for logging
  const costs = TOKEN_COSTS[model] || { input: 0, output: 0 };
  const estimatedCost = (actualInputTokens * costs.input + actualOutputTokens * costs.output) / 1000000;

  // Log usage
  const usageId = generateId();
  await env.DB.prepare(`
    INSERT INTO ai_usage (id, app_subdomain, user_id, provider, tier, model, input_tokens, output_tokens, total_tokens, credits_used, has_vision, estimated_cost_usd)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(
    usageId,
    subdomain,
    user?.id || null,
    provider,
    tier,
    model,
    actualInputTokens,
    actualOutputTokens,
    actualTotalTokens,
    actualCredits,
    hasVision ? 1 : 0,
    estimatedCost
  ).run();

  // Process response for JSON format if requested
  let content = result.content;
  if (response_format === 'json' && content) {
    // Remove markdown code blocks
    content = content
      .replace(/^```(?:json)?\s*\n?/i, '')
      .replace(/\n?```\s*$/i, '')
      .trim();

    // If still not valid JSON, try to extract JSON object/array
    try {
      JSON.parse(content);
    } catch (e) {
      const jsonMatch = content.match(/(\{[\s\S]*\}|\[[\s\S]*\])/);
      if (jsonMatch) {
        content = jsonMatch[1];
      }
    }
  }

  // Return the response
  return {
    content,
    model,
    usage: {
      input_tokens: actualInputTokens,
      output_tokens: actualOutputTokens,
      total_tokens: actualTotalTokens,
      credits_used: actualCredits,
      tokens_per_credit: TOKENS_PER_CREDIT[provider]?.[tier] || TOKENS_PER_CREDIT.claude[tier],
    },
  };
});

// Helper to call Claude API
async function callClaude(env, model, messages, system, maxTokens) {
  // Transform messages to Claude format
  const claudeMessages = messages.map(msg => {
    // Handle multimodal content
    if (Array.isArray(msg.content)) {
      const content = msg.content.map(part => {
        if (part.type === 'text') {
          return { type: 'text', text: part.text };
        } else if (part.type === 'image') {
          // Support base64 or URL
          if (part.source) {
            return {
              type: 'image',
              source: part.source,
            };
          } else if (part.url) {
            return {
              type: 'image',
              source: {
                type: 'url',
                url: part.url,
              },
            };
          } else if (part.base64) {
            return {
              type: 'image',
              source: {
                type: 'base64',
                media_type: part.media_type || 'image/jpeg',
                data: part.base64,
              },
            };
          }
        }
        return part;
      });
      return { role: msg.role, content };
    }

    return { role: msg.role, content: msg.content };
  });

  const requestBody = {
    model,
    max_tokens: maxTokens,
    messages: claudeMessages,
  };

  if (system) {
    requestBody.system = system;
  }

  const response = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': env.ANTHROPIC_API_KEY,
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify(requestBody),
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Claude API error: ${response.status} - ${error}`);
  }

  const data = await response.json();

  // Extract text content
  let content = '';
  if (data.content && Array.isArray(data.content)) {
    content = data.content
      .filter(block => block.type === 'text')
      .map(block => block.text)
      .join('\n');
  }

  return {
    content,
    usage: data.usage,
  };
}

// Helper to call OpenAI GPT API
async function callGPT(env, model, messages, system, maxTokens) {
  // Transform messages to OpenAI format
  const gptMessages = [];

  // Add system message if provided
  if (system) {
    gptMessages.push({ role: 'system', content: system });
  }

  // Transform user/assistant messages
  for (const msg of messages) {
    if (Array.isArray(msg.content)) {
      // Multimodal content
      const content = msg.content.map(part => {
        if (part.type === 'text') {
          return { type: 'text', text: part.text };
        } else if (part.type === 'image') {
          // Support URL or base64
          if (part.url) {
            return {
              type: 'image_url',
              image_url: { url: part.url },
            };
          } else if (part.base64) {
            return {
              type: 'image_url',
              image_url: {
                url: `data:${part.media_type || 'image/jpeg'};base64,${part.base64}`,
              },
            };
          } else if (part.source?.type === 'base64') {
            return {
              type: 'image_url',
              image_url: {
                url: `data:${part.source.media_type || 'image/jpeg'};base64,${part.source.data}`,
              },
            };
          }
        }
        return part;
      });
      gptMessages.push({ role: msg.role, content });
    } else {
      gptMessages.push({ role: msg.role, content: msg.content });
    }
  }

  const requestBody = {
    model,
    max_completion_tokens: maxTokens,
    messages: gptMessages,
  };

  const response = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${env.OPENAI_API_KEY}`,
    },
    body: JSON.stringify(requestBody),
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`OpenAI API error: ${response.status} - ${error}`);
  }

  const data = await response.json();

  // Extract content from the response
  const content = data.choices?.[0]?.message?.content || '';

  return {
    content,
    usage: data.usage,
  };
}

// Helper to call Google Gemini API
async function callGemini(env, model, messages, system, maxTokens) {
  // Transform messages to Gemini format
  const contents = [];

  // Add system instruction if provided (Gemini handles this differently)
  let systemInstruction = system;

  // Transform user/assistant messages
  for (const msg of messages) {
    const role = msg.role === 'assistant' ? 'model' : 'user';

    if (Array.isArray(msg.content)) {
      // Multimodal content
      const parts = msg.content.map(part => {
        if (part.type === 'text') {
          return { text: part.text };
        } else if (part.type === 'image') {
          // Support URL or base64
          if (part.base64) {
            return {
              inlineData: {
                mimeType: part.media_type || 'image/jpeg',
                data: part.base64,
              },
            };
          } else if (part.source?.type === 'base64') {
            return {
              inlineData: {
                mimeType: part.source.media_type || 'image/jpeg',
                data: part.source.data,
              },
            };
          }
          // URL-based images need to be fetched and converted to base64
          // For now, skip URL images (could add fetch support later)
          return { text: '[Image URL not supported - use base64]' };
        }
        return { text: '' };
      });
      contents.push({ role, parts });
    } else {
      contents.push({ role, parts: [{ text: msg.content }] });
    }
  }

  const requestBody = {
    contents,
    generationConfig: {
      maxOutputTokens: maxTokens,
    },
  };

  // Add system instruction if provided
  if (systemInstruction) {
    requestBody.systemInstruction = { parts: [{ text: systemInstruction }] };
  }

  const apiUrl = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${env.GEMINI_API_KEY}`;

  const response = await fetch(apiUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(requestBody),
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Gemini API error: ${response.status} - ${error}`);
  }

  const data = await response.json();

  // Extract content from the response
  let content = '';
  if (data.candidates?.[0]?.content?.parts) {
    content = data.candidates[0].content.parts
      .filter(part => part.text)
      .map(part => part.text)
      .join('');
  }

  return {
    content,
    usage: data.usageMetadata,
  };
}

// Image generation costs (credits per image)
const IMAGE_GENERATION_COSTS = {
  'dall-e-2': {
    '256x256': 20,    // ~$0.016 → 20 credits
    '512x512': 22,    // ~$0.018 → 22 credits
    '1024x1024': 25,  // ~$0.020 → 25 credits
  },
  'dall-e-3': {
    '1024x1024': 50,      // ~$0.040 → 50 credits (standard)
    '1024x1792': 100,     // ~$0.080 → 100 credits (standard)
    '1792x1024': 100,     // ~$0.080 → 100 credits (standard)
    '1024x1024-hd': 100,  // ~$0.080 → 100 credits (hd)
    '1024x1792-hd': 150,  // ~$0.120 → 150 credits (hd)
    '1792x1024-hd': 150,  // ~$0.120 → 150 credits (hd)
  },
};

// POST /ai/image - Generate images with DALL-E
router.post('/ai/image', async (request, env) => {
  const subdomain = getSubdomain(request);
  if (!subdomain) {
    return new Response(JSON.stringify({ error: 'Invalid origin' }), { status: 400 });
  }

  const { deploy_token, prompt, model = 'dall-e-3', size = '1024x1024', quality = 'standard', n = 1 } = await request.json();

  // Auth check
  const user = await getSession(request, env);
  const validToken = deploy_token && await validateDeployToken(env, subdomain, deploy_token);

  if (!user && !validToken) {
    return new Response(JSON.stringify({ error: 'Authentication required. Provide deploy_token or be logged in.' }), { status: 401 });
  }

  // Validate prompt
  if (!prompt || typeof prompt !== 'string' || prompt.trim().length === 0) {
    return new Response(JSON.stringify({ error: 'prompt is required' }), { status: 400 });
  }

  // Validate model
  if (!['dall-e-2', 'dall-e-3'].includes(model)) {
    return new Response(JSON.stringify({ error: 'Invalid model. Use "dall-e-2" or "dall-e-3"' }), { status: 400 });
  }

  // Validate size based on model
  const validSizes = model === 'dall-e-2'
    ? ['256x256', '512x512', '1024x1024']
    : ['1024x1024', '1024x1792', '1792x1024'];

  if (!validSizes.includes(size)) {
    return new Response(JSON.stringify({ error: `Invalid size for ${model}. Valid sizes: ${validSizes.join(', ')}` }), { status: 400 });
  }

  // Validate quality (only for dall-e-3)
  if (model === 'dall-e-3' && !['standard', 'hd'].includes(quality)) {
    return new Response(JSON.stringify({ error: 'Invalid quality. Use "standard" or "hd"' }), { status: 400 });
  }

  // Validate n (number of images)
  const maxImages = model === 'dall-e-3' ? 1 : 10;
  if (n < 1 || n > maxImages) {
    return new Response(JSON.stringify({ error: `n must be between 1 and ${maxImages} for ${model}` }), { status: 400 });
  }

  // Calculate credits needed
  let sizeKey = size;
  if (model === 'dall-e-3' && quality === 'hd') {
    sizeKey = `${size}-hd`;
  }
  const creditsPerImage = IMAGE_GENERATION_COSTS[model]?.[sizeKey] || 50;
  const totalCredits = creditsPerImage * n;

  // Check and deduct credits
  const creditCheck = await checkAndDeductCredits(env, subdomain, totalCredits);
  if (!creditCheck.success) {
    return new Response(JSON.stringify({
      error: 'Insufficient credits',
      balance: creditCheck.balance,
      required: totalCredits,
    }), { status: 402 });
  }

  try {
    const requestBody = {
      model,
      prompt: prompt.substring(0, model === 'dall-e-3' ? 4000 : 1000),
      n,
      size,
      response_format: 'url',
    };

    if (model === 'dall-e-3') {
      requestBody.quality = quality;
    }

    const response = await fetch('https://api.openai.com/v1/images/generations', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${env.OPENAI_API_KEY}`,
      },
      body: JSON.stringify(requestBody),
    });

    if (!response.ok) {
      const error = await response.text();
      // Refund credits on failure
      await refundCredits(env, subdomain, totalCredits);
      throw new Error(`DALL-E API error: ${response.status} - ${error}`);
    }

    const data = await response.json();

    // Log usage
    const usageId = generateId();
    await env.DB.prepare(`
      INSERT INTO ai_usage (id, app_subdomain, user_id, provider, tier, model, input_tokens, output_tokens, total_tokens, credits_used, has_vision, estimated_cost_usd)
      VALUES (?, ?, ?, 'openai', 'image', ?, 0, 0, 0, ?, 0, ?)
    `).bind(
      usageId,
      subdomain,
      user?.id || null,
      model,
      totalCredits,
      totalCredits * 0.001
    ).run();

    // Cache images in R2 (OpenAI URLs are temporary)
    const app = await env.DB.prepare('SELECT custom_domain FROM apps WHERE subdomain = ?').bind(subdomain).first();
    const baseUrl = app?.custom_domain ? `https://${app.custom_domain}` : `https://${subdomain}.itsalive.co`;

    const cachedImages = await Promise.all(data.data.map(async (img) => {
      try {
        // Fetch image from OpenAI's temporary URL
        const imageResponse = await fetch(img.url);
        if (!imageResponse.ok) {
          // If fetch fails, return original URL as fallback
          return { url: img.url, revised_prompt: img.revised_prompt, cached: false };
        }

        const imageData = await imageResponse.arrayBuffer();
        const contentType = imageResponse.headers.get('content-type') || 'image/png';
        const ext = contentType.includes('png') ? 'png' : 'webp';

        // Generate unique filename and store in R2
        const imageId = generateId();
        const filename = `${imageId}.${ext}`;
        const path = `${subdomain}/uploads/ai/${filename}`;

        await env.SITES.put(path, imageData, {
          httpMetadata: { contentType }
        });

        // Store metadata in uploads table
        await env.DB.prepare(`
          INSERT INTO uploads (id, app_subdomain, filename, original_filename, content_type, size, created_by, public)
          VALUES (?, ?, ?, ?, ?, ?, ?, 1)
        `).bind(imageId, subdomain, filename, `dalle-${imageId}.${ext}`, contentType, imageData.byteLength, user?.id || 'ai').run();

        const permanentUrl = `${baseUrl}/uploads/ai/${filename}`;
        return { url: permanentUrl, revised_prompt: img.revised_prompt, cached: true };
      } catch (e) {
        // On any error, fall back to original URL
        return { url: img.url, revised_prompt: img.revised_prompt, cached: false };
      }
    }));

    return {
      images: cachedImages,
      model,
      size,
      quality: model === 'dall-e-3' ? quality : undefined,
      credits_used: totalCredits,
    };
  } catch (error) {
    return new Response(JSON.stringify({
      error: 'Image generation failed',
      details: error.message,
    }), { status: 500 });
  }
});

// POST /ai/transcribe - Transcribe audio with Whisper
router.post('/ai/transcribe', async (request, env) => {
  const subdomain = getSubdomain(request);
  if (!subdomain) {
    return new Response(JSON.stringify({ error: 'Invalid origin' }), { status: 400 });
  }

  const formData = await request.formData();
  const file = formData.get('file');
  const deploy_token = formData.get('deploy_token');
  const language = formData.get('language'); // Optional: ISO 639-1 code
  const responseFormat = formData.get('response_format') || 'json'; // json, text, srt, verbose_json, vtt

  // Auth check
  const user = await getSession(request, env);
  const validToken = deploy_token && await validateDeployToken(env, subdomain, deploy_token);

  if (!user && !validToken) {
    return new Response(JSON.stringify({ error: 'Authentication required. Provide deploy_token or be logged in.' }), { status: 401 });
  }

  // Validate file
  if (!file) {
    return new Response(JSON.stringify({ error: 'No audio file provided' }), { status: 400 });
  }

  // Validate file type
  const allowedTypes = [
    'audio/flac', 'audio/m4a', 'audio/mp3', 'audio/mp4', 'audio/mpeg',
    'audio/mpga', 'audio/oga', 'audio/ogg', 'audio/wav', 'audio/webm',
    'video/mp4', 'video/mpeg', 'video/webm'
  ];
  const fileType = file.type.toLowerCase();
  if (!allowedTypes.some(t => fileType.includes(t.split('/')[1]))) {
    return new Response(JSON.stringify({
      error: 'Invalid file type. Supported: flac, m4a, mp3, mp4, mpeg, mpga, oga, ogg, wav, webm'
    }), { status: 400 });
  }

  // Size limit: 25MB (OpenAI limit)
  const maxSize = 25 * 1024 * 1024;
  if (file.size > maxSize) {
    return new Response(JSON.stringify({ error: 'File too large. Maximum 25MB.' }), { status: 400 });
  }

  // Estimate credits: ~10 credits per MB (rough estimate based on typical audio compression)
  // Whisper is $0.006/minute, assuming ~1MB ≈ 1 minute for typical audio
  const estimatedCredits = Math.max(10, Math.ceil(file.size / (1024 * 1024)) * 10);

  // Check and deduct credits
  const creditCheck = await checkAndDeductCredits(env, subdomain, estimatedCredits);
  if (!creditCheck.success) {
    return new Response(JSON.stringify({
      error: 'Insufficient credits',
      balance: creditCheck.balance,
      required: estimatedCredits,
    }), { status: 402 });
  }

  try {
    // Build form data for OpenAI
    const openaiFormData = new FormData();
    openaiFormData.append('file', file, file.name || 'audio.mp3');
    openaiFormData.append('model', 'whisper-1');
    openaiFormData.append('response_format', responseFormat);

    if (language) {
      openaiFormData.append('language', language);
    }

    const response = await fetch('https://api.openai.com/v1/audio/transcriptions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.OPENAI_API_KEY}`,
      },
      body: openaiFormData,
    });

    if (!response.ok) {
      const error = await response.text();
      await refundCredits(env, subdomain, estimatedCredits);
      throw new Error(`Whisper API error: ${response.status} - ${error}`);
    }

    let result;
    if (responseFormat === 'text' || responseFormat === 'srt' || responseFormat === 'vtt') {
      result = { text: await response.text() };
    } else {
      result = await response.json();
    }

    // Calculate actual duration if available (verbose_json provides it)
    let actualCredits = estimatedCredits;
    if (result.duration) {
      // $0.006 per minute → 10 credits per minute
      actualCredits = Math.max(1, Math.ceil(result.duration / 60) * 10);
      const creditDiff = estimatedCredits - actualCredits;
      if (creditDiff > 0) {
        await refundCredits(env, subdomain, creditDiff);
      }
    }

    // Log usage
    const usageId = generateId();
    await env.DB.prepare(`
      INSERT INTO ai_usage (id, app_subdomain, user_id, provider, tier, model, input_tokens, output_tokens, total_tokens, credits_used, has_vision, estimated_cost_usd)
      VALUES (?, ?, ?, 'openai', 'transcription', 'whisper-1', 0, 0, 0, ?, 0, ?)
    `).bind(
      usageId,
      subdomain,
      user?.id || null,
      actualCredits,
      actualCredits * 0.001
    ).run();

    return {
      text: result.text,
      duration: result.duration,
      language: result.language,
      credits_used: actualCredits,
    };
  } catch (error) {
    return new Response(JSON.stringify({
      error: 'Transcription failed',
      details: error.message,
    }), { status: 500 });
  }
});

// TTS costs (credits per 1K characters)
const TTS_COSTS = {
  'tts-1': 20,     // $0.015/1K chars → 20 credits
  'tts-1-hd': 40,  // $0.030/1K chars → 40 credits
};

// POST /ai/tts - Text to speech with OpenAI TTS
router.post('/ai/tts', async (request, env) => {
  const subdomain = getSubdomain(request);
  if (!subdomain) {
    return new Response(JSON.stringify({ error: 'Invalid origin' }), { status: 400 });
  }

  const { deploy_token, input, model = 'tts-1', voice = 'alloy', response_format = 'mp3', speed = 1.0 } = await request.json();

  // Auth check
  const user = await getSession(request, env);
  const validToken = deploy_token && await validateDeployToken(env, subdomain, deploy_token);

  if (!user && !validToken) {
    return new Response(JSON.stringify({ error: 'Authentication required. Provide deploy_token or be logged in.' }), { status: 401 });
  }

  // Validate input
  if (!input || typeof input !== 'string' || input.trim().length === 0) {
    return new Response(JSON.stringify({ error: 'input text is required' }), { status: 400 });
  }

  // OpenAI TTS has a 4096 character limit
  if (input.length > 4096) {
    return new Response(JSON.stringify({ error: 'Input too long. Maximum 4096 characters.' }), { status: 400 });
  }

  // Validate model
  if (!['tts-1', 'tts-1-hd'].includes(model)) {
    return new Response(JSON.stringify({ error: 'Invalid model. Use "tts-1" or "tts-1-hd"' }), { status: 400 });
  }

  // Validate voice
  const validVoices = ['alloy', 'echo', 'fable', 'onyx', 'nova', 'shimmer'];
  if (!validVoices.includes(voice)) {
    return new Response(JSON.stringify({ error: `Invalid voice. Valid voices: ${validVoices.join(', ')}` }), { status: 400 });
  }

  // Validate response format
  const validFormats = ['mp3', 'opus', 'aac', 'flac', 'wav', 'pcm'];
  if (!validFormats.includes(response_format)) {
    return new Response(JSON.stringify({ error: `Invalid format. Valid formats: ${validFormats.join(', ')}` }), { status: 400 });
  }

  // Validate speed
  if (speed < 0.25 || speed > 4.0) {
    return new Response(JSON.stringify({ error: 'Speed must be between 0.25 and 4.0' }), { status: 400 });
  }

  // Calculate credits (per 1K characters)
  const creditsPerK = TTS_COSTS[model] || 20;
  const totalCredits = Math.max(1, Math.ceil(input.length / 1000) * creditsPerK);

  // Check and deduct credits
  const creditCheck = await checkAndDeductCredits(env, subdomain, totalCredits);
  if (!creditCheck.success) {
    return new Response(JSON.stringify({
      error: 'Insufficient credits',
      balance: creditCheck.balance,
      required: totalCredits,
    }), { status: 402 });
  }

  try {
    const response = await fetch('https://api.openai.com/v1/audio/speech', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${env.OPENAI_API_KEY}`,
      },
      body: JSON.stringify({
        model,
        input,
        voice,
        response_format,
        speed,
      }),
    });

    if (!response.ok) {
      const error = await response.text();
      await refundCredits(env, subdomain, totalCredits);
      throw new Error(`TTS API error: ${response.status} - ${error}`);
    }

    // Log usage
    const usageId = generateId();
    await env.DB.prepare(`
      INSERT INTO ai_usage (id, app_subdomain, user_id, provider, tier, model, input_tokens, output_tokens, total_tokens, credits_used, has_vision, estimated_cost_usd)
      VALUES (?, ?, ?, 'openai', 'tts', ?, ?, 0, ?, ?, 0, ?)
    `).bind(
      usageId,
      subdomain,
      user?.id || null,
      model,
      input.length,  // Store character count in input_tokens
      input.length,
      totalCredits,
      totalCredits * 0.001
    ).run();

    // Return the audio as a binary response
    const contentTypes = {
      mp3: 'audio/mpeg',
      opus: 'audio/opus',
      aac: 'audio/aac',
      flac: 'audio/flac',
      wav: 'audio/wav',
      pcm: 'audio/pcm',
    };

    return new Response(response.body, {
      headers: {
        'Content-Type': contentTypes[response_format] || 'audio/mpeg',
        'X-Credits-Used': String(totalCredits),
        'X-Character-Count': String(input.length),
      },
    });
  } catch (error) {
    return new Response(JSON.stringify({
      error: 'TTS generation failed',
      details: error.message,
    }), { status: 500 });
  }
});

// GET /ai/credits - Get current credit balance (owner-based)
router.get('/ai/credits', async (request, env) => {
  const subdomain = getSubdomain(request);
  if (!subdomain) {
    return new Response(JSON.stringify({ error: 'Invalid origin' }), { status: 400 });
  }

  const url = new URL(request.url);
  const deploy_token = url.searchParams.get('deploy_token');

  const user = await getSession(request, env);
  const isOwner = user && await isAppOwner(env, subdomain, user.email);
  const validToken = deploy_token && await validateDeployToken(env, subdomain, deploy_token);

  if (!isOwner && !validToken) {
    return new Response(JSON.stringify({ error: 'Not authorized' }), { status: 403 });
  }

  const ownerId = await getOwnerIdFromSubdomain(env, subdomain);
  if (!ownerId) {
    return new Response(JSON.stringify({ error: 'App not found' }), { status: 404 });
  }

  const credits = await env.DB.prepare(
    'SELECT * FROM owner_credits WHERE owner_id = ?'
  ).bind(ownerId).first();

  return {
    balance: credits?.balance || 0,
    lifetime_purchased: credits?.lifetime_purchased || 0,
    lifetime_used: credits?.lifetime_used || 0,
  };
});

// POST /ai/credits - Add credits (owner only, for testing/admin)
router.post('/ai/credits', async (request, env) => {
  const subdomain = getSubdomain(request);
  if (!subdomain) {
    return new Response(JSON.stringify({ error: 'Invalid origin' }), { status: 400 });
  }

  const { amount, deploy_token } = await request.json();

  const user = await getSession(request, env);
  const isOwner = user && await isAppOwner(env, subdomain, user.email);
  const validToken = deploy_token && await validateDeployToken(env, subdomain, deploy_token);

  if (!isOwner && !validToken) {
    return new Response(JSON.stringify({ error: 'Not authorized' }), { status: 403 });
  }

  if (!amount || typeof amount !== 'number' || amount <= 0) {
    return new Response(JSON.stringify({ error: 'Valid positive amount required' }), { status: 400 });
  }

  const ownerId = await getOwnerIdFromSubdomain(env, subdomain);
  if (!ownerId) {
    return new Response(JSON.stringify({ error: 'App not found' }), { status: 404 });
  }

  // Upsert credits (owner-based)
  await env.DB.prepare(`
    INSERT INTO owner_credits (owner_id, balance, lifetime_purchased)
    VALUES (?, ?, ?)
    ON CONFLICT(owner_id) DO UPDATE SET
      balance = balance + excluded.balance,
      lifetime_purchased = lifetime_purchased + excluded.lifetime_purchased,
      updated_at = datetime('now')
  `).bind(ownerId, amount, amount).run();

  const credits = await env.DB.prepare(
    'SELECT * FROM owner_credits WHERE owner_id = ?'
  ).bind(ownerId).first();

  return {
    balance: credits.balance,
    added: amount,
    lifetime_purchased: credits.lifetime_purchased,
  };
});

// GET /ai/usage - Get usage history
router.get('/ai/usage', async (request, env) => {
  const subdomain = getSubdomain(request);
  if (!subdomain) {
    return new Response(JSON.stringify({ error: 'Invalid origin' }), { status: 400 });
  }

  const url = new URL(request.url);
  const deploy_token = url.searchParams.get('deploy_token');
  const limit = Math.min(parseInt(url.searchParams.get('limit') || '50'), 100);
  const offset = parseInt(url.searchParams.get('offset') || '0');

  const user = await getSession(request, env);
  const isOwner = user && await isAppOwner(env, subdomain, user.email);
  const validToken = deploy_token && await validateDeployToken(env, subdomain, deploy_token);

  if (!isOwner && !validToken) {
    return new Response(JSON.stringify({ error: 'Not authorized' }), { status: 403 });
  }

  const usage = await env.DB.prepare(`
    SELECT id, user_id, provider, tier, model, input_tokens, output_tokens, total_tokens, has_vision, estimated_cost_usd, created_at
    FROM ai_usage
    WHERE app_subdomain = ?
    ORDER BY created_at DESC
    LIMIT ? OFFSET ?
  `).bind(subdomain, limit, offset).all();

  // Get totals
  const totals = await env.DB.prepare(`
    SELECT
      COUNT(*) as request_count,
      SUM(input_tokens) as total_input_tokens,
      SUM(output_tokens) as total_output_tokens,
      SUM(total_tokens) as total_tokens,
      SUM(estimated_cost_usd) as total_cost
    FROM ai_usage
    WHERE app_subdomain = ?
  `).bind(subdomain).first();

  return {
    items: usage.results,
    totals: {
      requests: totals?.request_count || 0,
      input_tokens: totals?.total_input_tokens || 0,
      output_tokens: totals?.total_output_tokens || 0,
      total_tokens: totals?.total_tokens || 0,
      estimated_cost: totals?.total_cost || 0,
    },
    limit,
    offset,
  };
});

// GET /ai/settings - Get AI settings for this app
router.get('/ai/settings', async (request, env) => {
  const subdomain = getSubdomain(request);
  if (!subdomain) {
    return new Response(JSON.stringify({ error: 'Invalid origin' }), { status: 400 });
  }

  const url = new URL(request.url);
  const deploy_token = url.searchParams.get('deploy_token');

  const user = await getSession(request, env);
  const isOwner = user && await isAppOwner(env, subdomain, user.email);
  const validToken = deploy_token && await validateDeployToken(env, subdomain, deploy_token);

  if (!isOwner && !validToken) {
    return new Response(JSON.stringify({ error: 'Not authorized' }), { status: 403 });
  }

  const settings = await getAiSettings(env, subdomain);
  return settings;
});

// PUT /ai/settings - Update AI settings for this app
router.put('/ai/settings', async (request, env) => {
  const subdomain = getSubdomain(request);
  if (!subdomain) {
    return new Response(JSON.stringify({ error: 'Invalid origin' }), { status: 400 });
  }

  const { max_input_tokens, max_output_tokens, allowed_tiers, enabled, deploy_token } = await request.json();

  const user = await getSession(request, env);
  const isOwner = user && await isAppOwner(env, subdomain, user.email);
  const validToken = deploy_token && await validateDeployToken(env, subdomain, deploy_token);

  if (!isOwner && !validToken) {
    return new Response(JSON.stringify({ error: 'Not authorized' }), { status: 403 });
  }

  // Validate allowed_tiers if provided
  if (allowed_tiers) {
    const tiers = allowed_tiers.split(',');
    for (const t of tiers) {
      if (!['good', 'best'].includes(t.trim())) {
        return new Response(JSON.stringify({ error: 'Invalid tier in allowed_tiers' }), { status: 400 });
      }
    }
  }

  await env.DB.prepare(`
    INSERT INTO ai_settings (app_subdomain, max_input_tokens, max_output_tokens, allowed_tiers, enabled)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(app_subdomain) DO UPDATE SET
      max_input_tokens = COALESCE(excluded.max_input_tokens, max_input_tokens),
      max_output_tokens = COALESCE(excluded.max_output_tokens, max_output_tokens),
      allowed_tiers = COALESCE(excluded.allowed_tiers, allowed_tiers),
      enabled = COALESCE(excluded.enabled, enabled),
      updated_at = datetime('now')
  `).bind(
    subdomain,
    max_input_tokens || 4096,
    max_output_tokens || 4096,
    allowed_tiers || 'good,best',
    enabled !== undefined ? (enabled ? 1 : 0) : 1
  ).run();

  const settings = await getAiSettings(env, subdomain);
  return settings;
});

// ============ STATISTICS ENDPOINTS ============

// GET /stats/summary - Overview of app metrics
router.get('/stats/summary', async (request, env) => {
  const url = new URL(request.url);
  const deploy_token = url.searchParams.get('deploy_token');
  const querySubdomain = url.searchParams.get('subdomain');

  // Prefer query param subdomain (for owner dashboard), fall back to origin
  const originSubdomain = getSubdomain(request);
  const subdomain = querySubdomain || (originSubdomain !== 'dashboard' ? originSubdomain : null);
  if (!subdomain) {
    return new Response(JSON.stringify({ error: 'Subdomain required' }), { status: 400 });
  }

  // Check authorization: app user who is owner, or owner session, or deploy token
  const user = await getSession(request, env);
  const ownerSession = await getOwnerSession(request, env);
  const isOwner = (user && await isAppOwner(env, subdomain, user.email)) ||
                  (ownerSession && await isAppOwner(env, subdomain, ownerSession.email));
  const validToken = deploy_token && await validateDeployToken(env, subdomain, deploy_token);

  if (!isOwner && !validToken) {
    return new Response(JSON.stringify({ error: 'Not authorized. Owner or deploy_token required.' }), { status: 403 });
  }

  const today = new Date().toISOString().slice(0, 10);
  const weekAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
  const monthAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);

  // Active users (DAU, WAU, MAU)
  const [dauResult, wauResult, mauResult] = await Promise.all([
    env.DB.prepare('SELECT COUNT(*) as count FROM user_activity WHERE app_subdomain = ? AND date = ?')
      .bind(subdomain, today).first(),
    env.DB.prepare('SELECT COUNT(DISTINCT user_id) as count FROM user_activity WHERE app_subdomain = ? AND date >= ?')
      .bind(subdomain, weekAgo).first(),
    env.DB.prepare('SELECT COUNT(DISTINCT user_id) as count FROM user_activity WHERE app_subdomain = ? AND date >= ?')
      .bind(subdomain, monthAgo).first(),
  ]);

  // Total registered users
  const totalUsersResult = await env.DB.prepare(
    'SELECT COUNT(*) as count FROM app_users WHERE app_subdomain = ?'
  ).bind(subdomain).first();

  // New signups this week
  const signupsResult = await env.DB.prepare(
    'SELECT COUNT(*) as count FROM app_users WHERE app_subdomain = ? AND created_at >= ?'
  ).bind(subdomain, weekAgo).first();

  // AI usage this month
  const aiUsageResult = await env.DB.prepare(`
    SELECT COUNT(*) as requests, COALESCE(SUM(credits_used), 0) as credits
    FROM ai_usage WHERE app_subdomain = ? AND created_at >= ?
  `).bind(subdomain, monthAgo).first();

  // Upload usage this month
  const uploadUsageResult = await env.DB.prepare(`
    SELECT COUNT(*) as uploads, COALESCE(SUM(credits_used), 0) as credits, COALESCE(SUM(size), 0) as bytes
    FROM upload_usage WHERE app_subdomain = ? AND created_at >= ?
  `).bind(subdomain, monthAgo).first();

  // Storage stats
  const storageResult = await env.DB.prepare(`
    SELECT COUNT(*) as files, COALESCE(SUM(size), 0) as bytes
    FROM uploads WHERE app_subdomain = ?
  `).bind(subdomain).first();

  // Documents count
  const docsResult = await env.DB.prepare(
    'SELECT COUNT(*) as count FROM app_data WHERE app_subdomain = ?'
  ).bind(subdomain).first();

  // Page views and unique visitors from Analytics Engine
  let pageViews = { today: 0, week: 0, month: 0 };
  let uniqueVisitors = { today: 0, week: 0, month: 0 };

  try {
    // Query Analytics Engine for page views and unique visitors
    const todayQuery = `
      SELECT COUNT() as page_views, COUNT(DISTINCT blob2) as unique_visitors
      FROM "itsalive-analytics"
      WHERE index1 = '${subdomain}' AND timestamp >= NOW() - INTERVAL '24' HOUR
    `;
    const todayStats = await queryAnalytics(env, todayQuery);
    if (todayStats?.data?.[0]) {
      pageViews.today = todayStats.data[0].page_views || 0;
      uniqueVisitors.today = todayStats.data[0].unique_visitors || 0;
    }

    const weekQuery = `
      SELECT COUNT() as page_views, COUNT(DISTINCT blob2) as unique_visitors
      FROM "itsalive-analytics" WHERE index1 = '${subdomain}' AND timestamp >= NOW() - INTERVAL '7' DAY
    `;
    const weekStats = await queryAnalytics(env, weekQuery);
    if (weekStats?.data?.[0]) {
      pageViews.week = weekStats.data[0].page_views || 0;
      uniqueVisitors.week = weekStats.data[0].unique_visitors || 0;
    }

    const monthQuery = `
      SELECT COUNT() as page_views, COUNT(DISTINCT blob2) as unique_visitors
      FROM "itsalive-analytics" WHERE index1 = '${subdomain}' AND timestamp >= NOW() - INTERVAL '30' DAY
    `;
    const monthStats = await queryAnalytics(env, monthQuery);
    if (monthStats?.data?.[0]) {
      pageViews.month = monthStats.data[0].page_views || 0;
      uniqueVisitors.month = monthStats.data[0].unique_visitors || 0;
    }
  } catch (e) {
    // Analytics Engine may not be set up yet
    console.error('Analytics query error:', e);
  }

  return {
    users: {
      total: totalUsersResult?.count || 0,
      dau: dauResult?.count || 0,
      wau: wauResult?.count || 0,
      mau: mauResult?.count || 0,
      signups_this_week: signupsResult?.count || 0,
    },
    traffic: {
      page_views: pageViews,
      unique_visitors: uniqueVisitors,
    },
    ai: {
      requests_this_month: aiUsageResult?.requests || 0,
      credits_used_this_month: aiUsageResult?.credits || 0,
    },
    uploads: {
      count_this_month: uploadUsageResult?.uploads || 0,
      credits_used_this_month: uploadUsageResult?.credits || 0,
      bytes_this_month: uploadUsageResult?.bytes || 0,
    },
    storage: {
      files: storageResult?.files || 0,
      bytes: storageResult?.bytes || 0,
      mb: Math.round((storageResult?.bytes || 0) / 1024 / 1024 * 100) / 100,
    },
    content: {
      documents: docsResult?.count || 0,
    },
  };
});

// GET /stats/users - User activity over time
router.get('/stats/users', async (request, env) => {
  const url = new URL(request.url);
  const deploy_token = url.searchParams.get('deploy_token');
  const querySubdomain = url.searchParams.get('subdomain');
  const days = Math.min(parseInt(url.searchParams.get('days') || '30'), 90);

  const originSubdomain = getSubdomain(request);
  const subdomain = querySubdomain || (originSubdomain !== 'dashboard' ? originSubdomain : null);
  if (!subdomain) {
    return new Response(JSON.stringify({ error: 'Subdomain required' }), { status: 400 });
  }

  const user = await getSession(request, env);
  const ownerSession = await getOwnerSession(request, env);
  const isOwner = (user && await isAppOwner(env, subdomain, user.email)) ||
                  (ownerSession && await isAppOwner(env, subdomain, ownerSession.email));
  const validToken = deploy_token && await validateDeployToken(env, subdomain, deploy_token);

  if (!isOwner && !validToken) {
    return new Response(JSON.stringify({ error: 'Not authorized' }), { status: 403 });
  }

  const startDate = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);

  // Daily active users over time
  const dauOverTime = await env.DB.prepare(`
    SELECT date, COUNT(*) as active_users
    FROM user_activity
    WHERE app_subdomain = ? AND date >= ?
    GROUP BY date
    ORDER BY date
  `).bind(subdomain, startDate).all();

  // New signups over time
  const signupsOverTime = await env.DB.prepare(`
    SELECT date(created_at) as date, COUNT(*) as signups
    FROM app_users
    WHERE app_subdomain = ? AND created_at >= ?
    GROUP BY date(created_at)
    ORDER BY date
  `).bind(subdomain, startDate).all();

  return {
    period_days: days,
    daily_active_users: dauOverTime.results,
    signups: signupsOverTime.results,
  };
});

// GET /stats/traffic - Page views and visitors over time
router.get('/stats/traffic', async (request, env) => {
  const url = new URL(request.url);
  const deploy_token = url.searchParams.get('deploy_token');
  const querySubdomain = url.searchParams.get('subdomain');
  const period = url.searchParams.get('period') || 'day';

  const originSubdomain = getSubdomain(request);
  const subdomain = querySubdomain || (originSubdomain !== 'dashboard' ? originSubdomain : null);
  if (!subdomain) {
    return new Response(JSON.stringify({ error: 'Subdomain required' }), { status: 400 });
  }

  const user = await getSession(request, env);
  const ownerSession = await getOwnerSession(request, env);
  const isOwner = (user && await isAppOwner(env, subdomain, user.email)) ||
                  (ownerSession && await isAppOwner(env, subdomain, ownerSession.email));
  const validToken = deploy_token && await validateDeployToken(env, subdomain, deploy_token);

  if (!isOwner && !validToken) {
    return new Response(JSON.stringify({ error: 'Not authorized' }), { status: 403 });
  }

  if (!env.ANALYTICS) {
    return { error: 'Analytics not configured', data: [] };
  }

  try {
    let interval, groupBy, periodAlias;
    if (period === 'hour' || period === '24h') {
      interval = "INTERVAL '24' HOUR";
      groupBy = 'toStartOfHour(timestamp)';
      periodAlias = 'formatDateTime(time_bucket, \'%Y-%m-%d %H\')';
    } else if (period === 'day' || period === '7d') {
      interval = "INTERVAL '14' DAY";
      groupBy = 'toDate(timestamp)';
      periodAlias = 'formatDateTime(time_bucket, \'%Y-%m-%d\')';
    } else if (period === 'week') {
      interval = "INTERVAL '90' DAY";
      groupBy = 'toStartOfWeek(timestamp)';
      periodAlias = 'formatDateTime(time_bucket, \'%Y-W%V\')';
    } else {
      interval = "INTERVAL '365' DAY";
      groupBy = 'toStartOfMonth(timestamp)';
      periodAlias = 'formatDateTime(time_bucket, \'%Y-%m\')';
    }

    const query = `
      SELECT
        ${groupBy} as time_bucket,
        COUNT() as page_views,
        COUNT(DISTINCT blob2) as unique_visitors
      FROM "itsalive-analytics"
      WHERE index1 = '${subdomain}'
      AND timestamp >= NOW() - ${interval}
      GROUP BY time_bucket
      ORDER BY time_bucket
    `;

    const result = await queryAnalytics(env, query);

    if (result.error) {
      return { period, data: [], error: result.error };
    }

    // Format the response with period labels
    const data = (result?.data || []).map(row => ({
      period: row.time_bucket,
      page_views: row.page_views,
      unique_visitors: row.unique_visitors,
    }));

    return {
      period,
      data,
    };
  } catch (e) {
    console.error('Analytics query error:', e);
    return { error: 'Analytics query failed', details: e.message, data: [] };
  }
});

// GET /stats/debug - Debug Analytics Engine (temporary)
router.get('/stats/debug', async (request, env) => {
  try {
    // Try a simpler query first
    const simpleQuery = `SELECT COUNT() as total FROM "itsalive-analytics"`;

    // Make a raw fetch to see full response
    const response = await fetch(
      `https://api.cloudflare.com/client/v4/accounts/${env.CLOUDFLARE_ACCOUNT_ID}/analytics_engine/sql`,
      {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${env.CLOUDFLARE_API_TOKEN}`,
          'Content-Type': 'text/plain',
        },
        body: simpleQuery,
      }
    );

    const responseText = await response.text();
    let responseJson;
    try {
      responseJson = JSON.parse(responseText);
    } catch (e) {
      responseJson = null;
    }

    return {
      status: response.status,
      ok: response.ok,
      response_text: responseText.substring(0, 500),
      response_json: responseJson,
      has_account_id: !!env.CLOUDFLARE_ACCOUNT_ID,
      has_api_token: !!env.CLOUDFLARE_API_TOKEN,
    };
  } catch (e) {
    return { error: e.message, stack: e.stack };
  }
});

// GET /stats/ai - AI usage over time
router.get('/stats/ai', async (request, env) => {
  const url = new URL(request.url);
  const deploy_token = url.searchParams.get('deploy_token');
  const querySubdomain = url.searchParams.get('subdomain');
  const days = Math.min(parseInt(url.searchParams.get('days') || '30'), 90);

  const originSubdomain = getSubdomain(request);
  const subdomain = querySubdomain || (originSubdomain !== 'dashboard' ? originSubdomain : null);
  if (!subdomain) {
    return new Response(JSON.stringify({ error: 'Subdomain required' }), { status: 400 });
  }

  const user = await getSession(request, env);
  const ownerSession = await getOwnerSession(request, env);
  const isOwner = (user && await isAppOwner(env, subdomain, user.email)) ||
                  (ownerSession && await isAppOwner(env, subdomain, ownerSession.email));
  const validToken = deploy_token && await validateDeployToken(env, subdomain, deploy_token);

  if (!isOwner && !validToken) {
    return new Response(JSON.stringify({ error: 'Not authorized' }), { status: 403 });
  }

  const startDate = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);

  // AI usage over time
  const usageOverTime = await env.DB.prepare(`
    SELECT date(created_at) as date,
           COUNT(*) as requests,
           SUM(credits_used) as credits,
           SUM(input_tokens + output_tokens) as tokens
    FROM ai_usage
    WHERE app_subdomain = ? AND created_at >= ?
    GROUP BY date(created_at)
    ORDER BY date
  `).bind(subdomain, startDate).all();

  // Usage by feature
  const byFeature = await env.DB.prepare(`
    SELECT
      CASE
        WHEN model LIKE '%dall-e%' THEN 'image'
        WHEN tier = 'image' THEN 'image'
        WHEN tier = 'transcribe' THEN 'transcribe'
        WHEN tier = 'tts' THEN 'tts'
        ELSE 'chat'
      END as feature,
      COUNT(*) as requests,
      SUM(credits_used) as credits
    FROM ai_usage
    WHERE app_subdomain = ? AND created_at >= ?
    GROUP BY feature
  `).bind(subdomain, startDate).all();

  // Usage by provider/tier for the stats page display
  const byProviderTier = await env.DB.prepare(`
    SELECT
      provider,
      tier,
      COUNT(*) as requests,
      SUM(input_tokens + output_tokens) as total_tokens,
      SUM(credits_used) as total_credits
    FROM ai_usage
    WHERE app_subdomain = ? AND created_at >= ?
    GROUP BY provider, tier
    ORDER BY total_credits DESC
  `).bind(subdomain, startDate).all();

  return {
    period_days: days,
    daily_usage: usageOverTime.results,
    by_feature: byFeature.results,
    data: byProviderTier.results,
  };
});

// GET /stats/uploads - Upload usage over time
router.get('/stats/uploads', async (request, env) => {
  const url = new URL(request.url);
  const deploy_token = url.searchParams.get('deploy_token');
  const querySubdomain = url.searchParams.get('subdomain');
  const days = Math.min(parseInt(url.searchParams.get('days') || '30'), 90);

  const originSubdomain = getSubdomain(request);
  const subdomain = querySubdomain || (originSubdomain !== 'dashboard' ? originSubdomain : null);
  if (!subdomain) {
    return new Response(JSON.stringify({ error: 'Subdomain required' }), { status: 400 });
  }

  const user = await getSession(request, env);
  const ownerSession = await getOwnerSession(request, env);
  const isOwner = (user && await isAppOwner(env, subdomain, user.email)) ||
                  (ownerSession && await isAppOwner(env, subdomain, ownerSession.email));
  const validToken = deploy_token && await validateDeployToken(env, subdomain, deploy_token);

  if (!isOwner && !validToken) {
    return new Response(JSON.stringify({ error: 'Not authorized' }), { status: 403 });
  }

  const startDate = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);

  // Upload usage over time
  const usageOverTime = await env.DB.prepare(`
    SELECT date(created_at) as date,
           COUNT(*) as uploads,
           SUM(credits_used) as credits,
           SUM(size) as bytes
    FROM upload_usage
    WHERE app_subdomain = ? AND created_at >= ?
    GROUP BY date(created_at)
    ORDER BY date
  `).bind(subdomain, startDate).all();

  // Usage by content type
  const byContentType = await env.DB.prepare(`
    SELECT content_type,
           COUNT(*) as uploads,
           SUM(credits_used) as credits,
           SUM(size) as bytes
    FROM upload_usage
    WHERE app_subdomain = ? AND created_at >= ?
    GROUP BY content_type
    ORDER BY uploads DESC
  `).bind(subdomain, startDate).all();

  // Total for period
  const totals = await env.DB.prepare(`
    SELECT COUNT(*) as uploads,
           COALESCE(SUM(credits_used), 0) as credits,
           COALESCE(SUM(size), 0) as bytes
    FROM upload_usage
    WHERE app_subdomain = ? AND created_at >= ?
  `).bind(subdomain, startDate).first();

  return {
    period_days: days,
    totals: {
      uploads: totals?.uploads || 0,
      credits: totals?.credits || 0,
      bytes: totals?.bytes || 0,
      mb: Math.round((totals?.bytes || 0) / 1024 / 1024 * 100) / 100,
    },
    daily_usage: usageOverTime.results,
    by_content_type: byContentType.results,
  };
});

// ============ OG Routes (for dynamic meta tags in SPAs) ============

// PUT /og/routes - Configure OG routes (replaces existing)
router.put('/og/routes', async (request, env) => {
  const subdomain = getSubdomain(request);
  if (!subdomain) {
    return new Response(JSON.stringify({ error: 'Invalid origin' }), { status: 400 });
  }

  const { routes, deploy_token } = await request.json();

  const user = await getSession(request, env);
  const isOwner = user && await isAppOwner(env, subdomain, user.email);
  const validToken = deploy_token && await validateDeployToken(env, subdomain, deploy_token);

  if (!isOwner && !validToken) {
    return new Response(JSON.stringify({ error: 'Not authorized' }), { status: 403 });
  }

  if (!Array.isArray(routes)) {
    return new Response(JSON.stringify({ error: 'routes must be an array' }), { status: 400 });
  }

  // Validate each route
  for (const route of routes) {
    if (!route.pattern || !route.collection) {
      return new Response(JSON.stringify({ error: 'Each route must have pattern and collection' }), { status: 400 });
    }
    if (!route.pattern.startsWith('/')) {
      return new Response(JSON.stringify({ error: 'Pattern must start with /' }), { status: 400 });
    }
  }

  // Delete existing routes and insert new ones
  await env.DB.prepare('DELETE FROM og_routes WHERE app_subdomain = ?').bind(subdomain).run();

  for (const route of routes) {
    const id = generateId();
    await env.DB.prepare(`
      INSERT INTO og_routes (id, app_subdomain, pattern, collection, id_param, title_field, description_field, image_field)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      id,
      subdomain,
      route.pattern,
      route.collection,
      route.id_param || 'id',
      route.title_field || null,
      route.description_field || null,
      route.image_field || null
    ).run();
  }

  return { ok: true, routes_count: routes.length };
});

// GET /og/routes - List configured OG routes
router.get('/og/routes', async (request, env) => {
  const subdomain = getSubdomain(request);
  if (!subdomain) {
    return new Response(JSON.stringify({ error: 'Invalid origin' }), { status: 400 });
  }

  const result = await env.DB.prepare(
    'SELECT pattern, collection, id_param, title_field, description_field, image_field, created_at FROM og_routes WHERE app_subdomain = ?'
  ).bind(subdomain).all();

  return { routes: result.results };
});

// DELETE /og/routes - Clear all OG routes
router.delete('/og/routes', async (request, env) => {
  const subdomain = getSubdomain(request);
  if (!subdomain) {
    return new Response(JSON.stringify({ error: 'Invalid origin' }), { status: 400 });
  }

  const body = await request.json().catch(() => ({}));
  const { deploy_token } = body;

  const user = await getSession(request, env);
  const isOwner = user && await isAppOwner(env, subdomain, user.email);
  const validToken = deploy_token && await validateDeployToken(env, subdomain, deploy_token);

  if (!isOwner && !validToken) {
    return new Response(JSON.stringify({ error: 'Not authorized' }), { status: 403 });
  }

  await env.DB.prepare('DELETE FROM og_routes WHERE app_subdomain = ?').bind(subdomain).run();

  return { ok: true };
});

// 404 handler
router.all('*', () => new Response(errorPage({
  title: 'Not Found',
  message: 'The page you\'re looking for doesn\'t exist.',
  icon: '&#128269;',
}), { status: 404, headers: { 'content-type': 'text/html' } }));

export default {
  async fetch(request, env, ctx) {
    try {
      // Handle CORS first (async custom domain lookup)
      await handleCors(request, env);
      return router.fetch(request, env, ctx);
    } catch (e) {
      console.error('Unhandled error:', e.message, e.stack);
      console.error('Request URL:', request.url);
      console.error('Request method:', request.method);
      return new Response(JSON.stringify({
        error: e.message,
        type: e.name,
        url: request.url
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  },

  // Scheduled handler for cron jobs and job queue processing
  async scheduled(event, env, ctx) {
    const now = new Date();

    // Process due cron jobs
    const dueJobs = await env.DB.prepare(
      'SELECT * FROM cron_jobs WHERE enabled = 1 AND next_run <= ? LIMIT 50'
    ).bind(now.toISOString()).all();

    for (const job of dueJobs.results) {
      ctx.waitUntil((async () => {
        try {
          // Build the full URL for the app
          const baseUrl = `https://${job.app_subdomain}.itsalive.co`;
          const fullUrl = job.url.startsWith('/') ? baseUrl + job.url : job.url;

          // Execute the cron job
          const headers = job.headers ? JSON.parse(job.headers) : {};
          await fetch(fullUrl, {
            method: job.method || 'POST',
            headers: { 'Content-Type': 'application/json', ...headers },
            body: job.body || undefined,
          });

          // Update last_run and calculate next_run
          const nextRun = getNextCronRun(job.schedule, now);
          await env.DB.prepare(
            'UPDATE cron_jobs SET last_run = ?, next_run = ? WHERE id = ?'
          ).bind(now.toISOString(), nextRun ? nextRun.toISOString() : null, job.id).run();
        } catch (e) {
          console.error(`Cron job ${job.id} failed:`, e.message);
        }
      })());
    }

    // Process pending jobs
    const pendingJobs = await env.DB.prepare(
      'SELECT * FROM jobs WHERE status = ? AND run_at <= ? LIMIT 50'
    ).bind('pending', now.toISOString()).all();

    for (const job of pendingJobs.results) {
      ctx.waitUntil((async () => {
        try {
          // Mark as running
          await env.DB.prepare(
            'UPDATE jobs SET status = ?, attempts = attempts + 1 WHERE id = ?'
          ).bind('running', job.id).run();

          // Execute job by calling the app's job handler endpoint
          const baseUrl = `https://${job.app_subdomain}.itsalive.co`;
          const jobData = job.data ? JSON.parse(job.data) : null;

          const res = await fetch(`${baseUrl}/_jobs/${job.type}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id: job.id, type: job.type, data: jobData }),
          });

          if (res.ok) {
            // Mark as completed
            await env.DB.prepare(
              'UPDATE jobs SET status = ?, completed_at = ? WHERE id = ?'
            ).bind('completed', now.toISOString(), job.id).run();
          } else {
            throw new Error(`HTTP ${res.status}: ${await res.text()}`);
          }
        } catch (e) {
          // Check if we should retry
          const attempts = job.attempts + 1;
          if (attempts >= job.max_attempts) {
            await env.DB.prepare(
              'UPDATE jobs SET status = ?, last_error = ? WHERE id = ?'
            ).bind('failed', e.message, job.id).run();
          } else {
            // Reset to pending for retry (with exponential backoff)
            const retryAt = new Date(now.getTime() + Math.pow(2, attempts) * 60000);
            await env.DB.prepare(
              'UPDATE jobs SET status = ?, run_at = ?, last_error = ? WHERE id = ?'
            ).bind('pending', retryAt.toISOString(), e.message, job.id).run();
          }
        }
      })());
    }
  },
};
