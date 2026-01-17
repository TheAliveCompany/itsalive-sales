import { AutoRouter } from 'itty-router';

// Custom CORS middleware that supports async custom domain lookup
async function handleCors(request, env) {
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
    } else {
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
async function sendEmail(env, to, subject, html, fromName = "It's Alive!") {
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
        html,
      }),
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

  return user;
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

  return JSON.parse(data);
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
  const owner = await getOwnerSession(request, env);
  if (!owner) {
    return new Response(JSON.stringify({ error: 'Not logged in' }), { status: 401 });
  }
  return new Response(JSON.stringify({ email: owner.email, owner_id: owner.owner_id }));
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
  if (!owner) {
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
  }), { headers: { 'content-type': 'text/html' } });
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
  }), { headers: { 'content-type': 'text/html' } });
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

  // Notify about new site launch
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
  await Promise.all([
    sendEmail(env, 'sam@itsalive.co', `New site launched: ${pending.subdomain}.itsalive.co`, launchEmailHtml),
    sendEmail(env, 'melih@itsalive.co', `New site launched: ${pending.subdomain}.itsalive.co`, launchEmailHtml),
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
router.put('/db/:collection/:id', async (request, env) => {
  const subdomain = getSubdomain(request);
  const { collection, id } = request.params;
  const data = await request.json();

  // Get collection settings (for public_write and schema)
  const settings = await getCollectionSettings(env, subdomain, collection);

  // Check auth - require login unless public_write is enabled
  const user = await getSession(request, env);
  if (!user && !settings.public_write) {
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

  // Ownership check: logged-in users can only edit their own docs
  // Anonymous writes can only create new docs or update anonymous docs
  if (existing && existing.created_by) {
    if (!user || existing.created_by !== user.id) {
      return new Response(JSON.stringify({ error: 'Not authorized to edit this document' }), { status: 403 });
    }
  }

  const createdBy = user ? user.id : null;

  // Extract lat/lng for geo queries if present in data
  const lat = typeof data.lat === 'number' ? data.lat : (typeof data.latitude === 'number' ? data.latitude : null);
  const lng = typeof data.lng === 'number' ? data.lng : (typeof data.longitude === 'number' ? data.longitude : null);

  await env.DB.prepare(`
    INSERT INTO app_data (app_subdomain, collection, doc_id, data, created_by, lat, lng, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, datetime("now"))
    ON CONFLICT(app_subdomain, collection, doc_id) DO UPDATE SET
      data = excluded.data,
      lat = excluded.lat,
      lng = excluded.lng,
      updated_at = datetime("now")
  `).bind(subdomain, collection, id, JSON.stringify(data), createdBy, lat, lng).run();

  return { success: true };
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
router.post('/db/:collection/_bulk', async (request, env) => {
  const subdomain = getSubdomain(request);
  const { collection } = request.params;
  const { docs } = await request.json();

  // Get collection settings (for public_write and schema)
  const settings = await getCollectionSettings(env, subdomain, collection);

  // Check auth - require login unless public_write is enabled
  const user = await getSession(request, env);
  if (!user && !settings.public_write) {
    return new Response(JSON.stringify({ error: 'Not logged in' }), { status: 401 });
  }

  if (!Array.isArray(docs) || docs.length === 0) {
    return new Response(JSON.stringify({ error: 'docs must be a non-empty array' }), { status: 400 });
  }

  if (docs.length > 100) {
    return new Response(JSON.stringify({ error: 'Maximum 100 documents per bulk operation' }), { status: 400 });
  }

  const results = [];
  const createdBy = user ? user.id : null;

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

    // Ownership check: logged-in users can only edit their own docs
    // Anonymous writes can only create new docs or update anonymous docs
    if (existing && existing.created_by) {
      if (!user || existing.created_by !== user.id) {
        results.push({ id, success: false, error: 'Not authorized to edit this document' });
        continue;
      }
    }

    // Save document
    await env.DB.prepare(`
      INSERT INTO app_data (app_subdomain, collection, doc_id, data, created_by, updated_at)
      VALUES (?, ?, ?, ?, ?, datetime("now"))
      ON CONFLICT(app_subdomain, collection, doc_id) DO UPDATE SET
        data = excluded.data,
        updated_at = datetime("now")
    `).bind(subdomain, collection, id, JSON.stringify(data), createdBy).run();

    results.push({ id, success: true });
  }

  const succeeded = results.filter(r => r.success).length;
  const failed = results.filter(r => !r.success).length;

  return { results, succeeded, failed };
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

// POST /uploads - Upload a file (requires login)
router.post('/uploads', async (request, env) => {
  const subdomain = getSubdomain(request);
  if (!subdomain) {
    return new Response(JSON.stringify({ error: 'Invalid origin' }), { status: 400 });
  }

  const user = await getSession(request, env);
  if (!user) {
    return new Response(JSON.stringify({ error: 'Login required' }), { status: 401 });
  }

  const formData = await request.formData();
  const file = formData.get('file');
  const isPublic = formData.get('public') !== 'false';

  if (!file) {
    return new Response(JSON.stringify({ error: 'No file provided' }), { status: 400 });
  }

  // Validate file type
  const allowedTypes = [
    'image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/svg+xml',
    'application/pdf', 'text/plain', 'text/csv'
  ];
  if (!allowedTypes.includes(file.type)) {
    return new Response(JSON.stringify({ error: `File type not allowed. Allowed: ${allowedTypes.join(', ')}` }), { status: 400 });
  }

  // Size limit: 10MB for images, 25MB for PDFs
  const maxSize = file.type === 'application/pdf' ? 25 * 1024 * 1024 : 10 * 1024 * 1024;
  if (file.size > maxSize) {
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

  // Build public URL
  const app = await env.DB.prepare('SELECT custom_domain FROM apps WHERE subdomain = ?').bind(subdomain).first();
  const baseUrl = app?.custom_domain ? `https://${app.custom_domain}` : `https://${subdomain}.itsalive.co`;

  return {
    id,
    url: `${baseUrl}/uploads/${user.id}/${filename}`,
    filename: file.name,
    content_type: file.type,
    size: file.size
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

  const { to, subject, html, text, template, template_data, deploy_token } = await request.json();

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

  // Get branding
  const branding = await getAppBranding(env, subdomain);

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

  // Wrap in branded template
  const finalHtml = emailTemplate({
    buttonText: null,
    buttonUrl: null,
    footer: emailHtml,
    branding,
  });

  // Send via Resend
  const id = generateId();
  try {
    const sent = await sendEmail(env, to, emailSubject, finalHtml, branding.appName || subdomain);

    await env.DB.prepare(`
      INSERT INTO email_log (id, app_subdomain, to_email, subject, template, status, sent_at)
      VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
    `).bind(id, subdomain, to, emailSubject, template || 'custom', sent ? 'sent' : 'failed').run();

    if (!sent) {
      return new Response(JSON.stringify({ error: 'Failed to send email' }), { status: 500 });
    }

    return { id, status: 'sent' };
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

// 404 handler
router.all('*', () => new Response(errorPage({
  title: 'Not Found',
  message: 'The page you\'re looking for doesn\'t exist.',
  icon: '&#128269;',
}), { status: 404, headers: { 'content-type': 'text/html' } }));

export default {
  async fetch(request, env, ctx) {
    // Handle CORS first (async custom domain lookup)
    await handleCors(request, env);
    return router.fetch(request, env, ctx);
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
