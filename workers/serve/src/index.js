export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const host = request.headers.get('host');
    const startTime = Date.now();

    // Dashboard subdomain
    if (host === 'dashboard.itsalive.co') {
      // Apple Pay domain verification
      if (url.pathname === '/.well-known/apple-developer-merchantid-domain-association') {
        return fetch('https://stripe.com/files/apple-pay/apple-developer-merchantid-domain-association');
      }

      // Stats page: /stats/appname
      const statsMatch = url.pathname.match(/^\/stats\/([a-z0-9-]+)$/i);
      if (statsMatch) {
        return new Response(statsPage(statsMatch[1]), {
          headers: { 'content-type': 'text/html' },
        });
      }

      // Checkout page: /checkout?plan=pro_monthly&site=mysite
      if (url.pathname === '/checkout') {
        const plan = url.searchParams.get('plan');
        const site = url.searchParams.get('site');
        return new Response(checkoutPage(plan, site), {
          headers: { 'content-type': 'text/html' },
        });
      }

      // Main dashboard
      return new Response(dashboardPage(), {
        headers: { 'content-type': 'text/html' },
      });
    }

    // Landing page for root domain - no tracking
    if (host === 'itsalive.co' || host === 'www.itsalive.co') {
      // Serve OG image from R2
      if (url.pathname === '/og-image.png') {
        const object = await env.SITES.get('_root/og-image.png');
        if (object) {
          return new Response(object.body, {
            headers: {
              'content-type': 'image/png',
              'cache-control': 'public, max-age=86400'
            },
          });
        }
      }

      // Dashboard for managing apps
      if (url.pathname === '/dashboard') {
        return new Response(dashboardPage(), {
          headers: { 'content-type': 'text/html' },
        });
      }

      // Custom domain setup docs
      if (url.pathname === '/docs/custom-domains') {
        return new Response(customDomainsPage(), {
          headers: { 'content-type': 'text/html' },
        });
      }

      return new Response(landingPage(), {
        headers: { 'content-type': 'text/html' },
      });
    }

    // Determine subdomain - either from *.itsalive.co or custom domain lookup
    let subdomain;

    if (host.endsWith('.itsalive.co')) {
      // Standard subdomain
      subdomain = host.split('.')[0];
    } else {
      // Custom domain - look up in database
      const app = await env.DB.prepare(
        'SELECT subdomain FROM apps WHERE custom_domain = ?'
      ).bind(host).first();

      if (!app) {
        return new Response(notFoundPage(host), {
          status: 404,
          headers: { 'content-type': 'text/html' },
        });
      }
      subdomain = app.subdomain;
    }

    // Settings page for app management
    if (url.pathname === '/_settings') {
      return new Response(settingsPage(subdomain), {
        headers: { 'content-type': 'text/html' },
      });
    }

    // Health check for domain verification
    if (url.pathname === '/_health') {
      return new Response('ok', { status: 200 });
    }

    // Dynamic OG image generation
    if (url.pathname === '/_og') {
      const title = url.searchParams.get('title') || subdomain;
      const description = url.searchParams.get('description') || '';
      const theme = url.searchParams.get('theme') || 'dark';

      const bgColor = theme === 'light' ? '#ffffff' : '#0a0a0b';
      const textColor = theme === 'light' ? '#000000' : '#ffffff';
      const accentColor = '#00d4ff';

      const svg = `
        <svg width="1200" height="630" xmlns="http://www.w3.org/2000/svg">
          <rect width="100%" height="100%" fill="${bgColor}"/>
          <text x="80" y="280" font-family="system-ui, sans-serif" font-size="72" font-weight="bold" fill="${textColor}">${escapeXml(title.substring(0, 40))}</text>
          ${description ? `<text x="80" y="360" font-family="system-ui, sans-serif" font-size="32" fill="${theme === 'light' ? '#666' : '#888'}">${escapeXml(description.substring(0, 80))}</text>` : ''}
          <text x="80" y="550" font-family="system-ui, sans-serif" font-size="24" fill="${accentColor}">${subdomain}.itsalive.co</text>
        </svg>
      `;

      return new Response(svg, {
        headers: {
          'Content-Type': 'image/svg+xml',
          'Cache-Control': 'public, max-age=86400',
        },
      });
    }

    // Serve uploaded files
    if (url.pathname.startsWith('/uploads/')) {
      const key = `${subdomain}${url.pathname}`;
      const object = await env.SITES.get(key);

      if (!object) {
        return new Response('Not found', { status: 404 });
      }

      return new Response(object.body, {
        headers: {
          'Content-Type': object.httpMetadata?.contentType || 'application/octet-stream',
          'Cache-Control': 'public, max-age=31536000, immutable',
        },
      });
    }

    // Image optimization endpoint: /_images/path/to/image.jpg?w=400&q=80&f=webp
    if (url.pathname.startsWith('/_images/')) {
      const imagePath = url.pathname.replace('/_images/', '');
      const key = `${subdomain}/uploads/${imagePath}`;

      // Parse transformation params
      const width = parseInt(url.searchParams.get('w') || url.searchParams.get('width') || '0') || undefined;
      const height = parseInt(url.searchParams.get('h') || url.searchParams.get('height') || '0') || undefined;
      const quality = parseInt(url.searchParams.get('q') || url.searchParams.get('quality') || '80');
      const format = url.searchParams.get('f') || url.searchParams.get('format') || 'webp';
      const fit = url.searchParams.get('fit') || 'scale-down'; // cover, contain, scale-down, crop

      // Validate params
      if (width && (width < 1 || width > 4000)) {
        return new Response(JSON.stringify({ error: 'Width must be between 1 and 4000' }), { status: 400 });
      }
      if (height && (height < 1 || height > 4000)) {
        return new Response(JSON.stringify({ error: 'Height must be between 1 and 4000' }), { status: 400 });
      }
      if (quality < 1 || quality > 100) {
        return new Response(JSON.stringify({ error: 'Quality must be between 1 and 100' }), { status: 400 });
      }
      if (!['webp', 'avif', 'jpeg', 'jpg', 'png', 'auto'].includes(format)) {
        return new Response(JSON.stringify({ error: 'Format must be webp, avif, jpeg, png, or auto' }), { status: 400 });
      }

      // Get original image from R2
      const object = await env.SITES.get(key);
      if (!object) {
        return new Response('Image not found', { status: 404 });
      }

      const originalContentType = object.httpMetadata?.contentType || 'image/jpeg';

      // If no transformations requested, return original
      if (!width && !height && format === 'auto') {
        return new Response(object.body, {
          headers: {
            'Content-Type': originalContentType,
            'Cache-Control': 'public, max-age=31536000, immutable',
          },
        });
      }

      // Build cache key for transformed image
      const cacheKey = `${key}?w=${width || ''}&h=${height || ''}&q=${quality}&f=${format}&fit=${fit}`;
      const cache = caches.default;
      const cacheRequest = new Request(`https://cache.itsalive.co/${cacheKey}`);

      // Check cache first
      let cachedResponse = await cache.match(cacheRequest);
      if (cachedResponse) {
        return cachedResponse;
      }

      // Determine output content type
      let outputFormat = format;
      if (format === 'auto') {
        // Use Accept header to determine best format
        const accept = request.headers.get('Accept') || '';
        if (accept.includes('image/avif')) {
          outputFormat = 'avif';
        } else if (accept.includes('image/webp')) {
          outputFormat = 'webp';
        } else {
          outputFormat = 'jpeg';
        }
      }
      if (outputFormat === 'jpg') outputFormat = 'jpeg';

      const contentTypeMap = {
        webp: 'image/webp',
        avif: 'image/avif',
        jpeg: 'image/jpeg',
        png: 'image/png',
      };

      // Use Cloudflare Image Resizing
      // Create a URL to the original image that Cloudflare can fetch
      const imageUrl = `https://${subdomain}.itsalive.co/uploads/${imagePath}`;

      try {
        const resizedResponse = await fetch(imageUrl, {
          cf: {
            image: {
              width: width,
              height: height,
              quality: quality,
              format: outputFormat,
              fit: fit,
            },
          },
        });

        if (!resizedResponse.ok) {
          // Fallback: return original if resizing fails
          return new Response(object.body, {
            headers: {
              'Content-Type': originalContentType,
              'Cache-Control': 'public, max-age=31536000, immutable',
              'X-Image-Optimized': 'false',
              'X-Fallback-Reason': 'resize-failed',
            },
          });
        }

        // Check if transformation actually happened by comparing content types
        const responseContentType = resizedResponse.headers.get('content-type') || '';
        const expectedContentType = contentTypeMap[outputFormat];
        const wasTransformed = responseContentType.includes(outputFormat) ||
          (outputFormat === 'jpeg' && responseContentType.includes('jpeg'));

        if (!wasTransformed && outputFormat !== 'png' && !originalContentType.includes(outputFormat)) {
          // Image Resizing didn't transform the image (likely not enabled)
          // Return original with headers indicating the situation
          return new Response(object.body, {
            headers: {
              'Content-Type': originalContentType,
              'Cache-Control': 'public, max-age=31536000, immutable',
              'X-Image-Optimized': 'false',
              'X-Fallback-Reason': 'image-resizing-not-enabled',
              'X-Requested-Format': outputFormat,
            },
          });
        }

        // Create response with caching headers
        const response = new Response(resizedResponse.body, {
          headers: {
            'Content-Type': responseContentType || contentTypeMap[outputFormat] || 'image/jpeg',
            'Cache-Control': 'public, max-age=31536000, immutable',
            'Vary': 'Accept',
            'X-Image-Optimized': 'true',
            'X-Original-Size': object.size?.toString() || 'unknown',
          },
        });

        // Cache the transformed image
        ctx.waitUntil(cache.put(cacheRequest, response.clone()));

        return response;
      } catch (err) {
        // Fallback: return original if anything fails
        return new Response(object.body, {
          headers: {
            'Content-Type': originalContentType,
            'Cache-Control': 'public, max-age=31536000, immutable',
            'X-Image-Optimized': 'false',
            'X-Fallback-Reason': 'error',
            'X-Error': err.message,
          },
        });
      }
    }

    // Proxy uploads API to API worker
    if (url.pathname.startsWith('/_uploads')) {
      const cookie = request.headers.get('cookie') || '';
      const match = cookie.match(/itsalive_session=([^;]+)/);

      const apiPath = url.pathname.replace('/_uploads', '/uploads');
      const apiUrl = new URL(apiPath + url.search, 'https://api.itsalive.co');

      const headers = new Headers(request.headers);
      headers.delete('cookie');
      headers.delete('host');
      headers.set('X-Forwarded-Host', host);
      if (match) {
        headers.set('X-Session-Token', match[1]);
      }

      const apiRequest = new Request(apiUrl.toString(), {
        method: request.method,
        headers,
        body: request.method !== 'GET' && request.method !== 'HEAD' ? request.body : undefined,
      });

      const apiResponse = await env.API.fetch(apiRequest);

      const responseHeaders = new Headers(apiResponse.headers);
      responseHeaders.set('Access-Control-Allow-Origin', `https://${host}`);
      responseHeaders.set('Access-Control-Allow-Credentials', 'true');

      return new Response(apiResponse.body, {
        status: apiResponse.status,
        headers: responseHeaders,
      });
    }

    // Proxy email API to API worker
    if (url.pathname.startsWith('/_email')) {
      const cookie = request.headers.get('cookie') || '';
      const match = cookie.match(/itsalive_session=([^;]+)/);

      const apiPath = url.pathname.replace('/_email', '/email');
      const apiUrl = new URL(apiPath + url.search, 'https://api.itsalive.co');

      const headers = new Headers(request.headers);
      headers.delete('cookie');
      headers.delete('host');
      headers.set('X-Forwarded-Host', host);
      if (match) {
        headers.set('X-Session-Token', match[1]);
      }

      const apiRequest = new Request(apiUrl.toString(), {
        method: request.method,
        headers,
        body: request.method !== 'GET' && request.method !== 'HEAD' ? request.body : undefined,
      });

      const apiResponse = await env.API.fetch(apiRequest);

      const responseHeaders = new Headers(apiResponse.headers);
      responseHeaders.set('Access-Control-Allow-Origin', `https://${host}`);
      responseHeaders.set('Access-Control-Allow-Credentials', 'true');

      return new Response(apiResponse.body, {
        status: apiResponse.status,
        headers: responseHeaders,
      });
    }

    // Proxy platform feedback API to API worker
    if (url.pathname.startsWith('/_itsalive')) {
      const headers = new Headers(request.headers);
      headers.delete('host');
      headers.set('X-Forwarded-Host', host);

      const apiRequest = new Request(`https://api.itsalive.co${url.pathname}${url.search}`, {
        method: request.method,
        headers,
        body: request.method !== 'GET' && request.method !== 'HEAD' ? request.body : undefined,
      });

      const apiResponse = await env.API.fetch(apiRequest);

      const responseHeaders = new Headers(apiResponse.headers);
      responseHeaders.set('Access-Control-Allow-Origin', `https://${host}`);
      responseHeaders.set('Access-Control-Allow-Credentials', 'true');

      return new Response(apiResponse.body, {
        status: apiResponse.status,
        headers: responseHeaders,
      });
    }

    // Proxy /_ai requests to API worker
    if (url.pathname.startsWith('/_ai')) {
      const headers = new Headers(request.headers);
      headers.delete('host');
      headers.set('X-Forwarded-Host', host);

      const apiRequest = new Request(`https://api.itsalive.co${url.pathname.replace('/_ai', '/ai')}${url.search}`, {
        method: request.method,
        headers,
        body: request.method !== 'GET' && request.method !== 'HEAD' ? request.body : undefined,
      });

      const apiResponse = await env.API.fetch(apiRequest);

      const responseHeaders = new Headers(apiResponse.headers);
      responseHeaders.set('Access-Control-Allow-Origin', `https://${host}`);
      responseHeaders.set('Access-Control-Allow-Credentials', 'true');

      return new Response(apiResponse.body, {
        status: apiResponse.status,
        headers: responseHeaders,
      });
    }

    // Auth callback for custom domains - exchanges callback token for session cookie
    if (url.pathname === '/_auth/callback') {
      const callbackToken = url.searchParams.get('token');
      if (!callbackToken) {
        return new Response('Missing token', { status: 400 });
      }

      // Exchange callback token for session token
      const sessionToken = await env.EMAIL_TOKENS.get(`callback:${callbackToken}`);
      if (!sessionToken) {
        return new Response('Invalid or expired token', { status: 400 });
      }

      // Delete the callback token (one-time use)
      await env.EMAIL_TOKENS.delete(`callback:${callbackToken}`);

      // Set cookie and redirect to app root
      return new Response(null, {
        status: 302,
        headers: {
          'Location': '/',
          'Set-Cookie': `itsalive_session=${sessionToken}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${30 * 24 * 60 * 60}`,
        },
      });
    }

    // Auth me endpoint for custom domains - returns current user from cookie
    if (url.pathname === '/_auth/me') {
      const cookie = request.headers.get('cookie') || '';
      const match = cookie.match(/itsalive_session=([^;]+)/);

      if (!match) {
        return new Response(JSON.stringify({ error: 'Not logged in' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      const token = match[1];
      const session = await env.DB.prepare(
        `SELECT s.user_id, u.email FROM sessions s
         JOIN app_users u ON s.user_id = u.id
         WHERE s.token = ? AND s.app_subdomain = ? AND s.expires_at > datetime('now')`
      ).bind(token, subdomain).first();

      if (!session) {
        return new Response(JSON.stringify({ error: 'Not logged in' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      return new Response(JSON.stringify({ user: { id: session.user_id, email: session.email } }), {
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // Auth logout endpoint
    if (url.pathname === '/_auth/logout' && request.method === 'POST') {
      const cookie = request.headers.get('cookie') || '';
      const match = cookie.match(/itsalive_session=([^;]+)/);

      if (match) {
        await env.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(match[1]).run();
      }

      return new Response(JSON.stringify({ success: true }), {
        headers: {
          'Content-Type': 'application/json',
          'Set-Cookie': 'itsalive_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0',
        },
      });
    }

    // Auth login proxy - forwards to API via Service Binding
    if (url.pathname === '/_auth/login' && request.method === 'POST') {
      const headers = new Headers(request.headers);
      headers.delete('host');
      headers.set('X-Forwarded-Host', host);

      const apiRequest = new Request('https://api.itsalive.co/auth/login', {
        method: 'POST',
        headers,
        body: request.body,
      });

      const apiResponse = await env.API.fetch(apiRequest);

      const responseHeaders = new Headers(apiResponse.headers);
      responseHeaders.set('Access-Control-Allow-Origin', `https://${host}`);
      responseHeaders.set('Access-Control-Allow-Credentials', 'true');

      return new Response(apiResponse.body, {
        status: apiResponse.status,
        headers: responseHeaders,
      });
    }

    // Database proxy for custom domains - forwards to API via Service Binding
    if (url.pathname.startsWith('/_db/')) {
      const cookie = request.headers.get('cookie') || '';
      const match = cookie.match(/itsalive_session=([^;]+)/);

      // Build the API URL (remove /_db prefix, add to api.itsalive.co/db)
      const apiPath = url.pathname.replace('/_db/', '/db/');
      const apiUrl = new URL(apiPath + url.search, 'https://api.itsalive.co');

      // Forward request to API with session token header
      const headers = new Headers(request.headers);
      headers.delete('cookie'); // Don't forward cookies
      headers.delete('host');
      headers.set('X-Forwarded-Host', host);
      if (match) {
        headers.set('X-Session-Token', match[1]);
      }

      const apiRequest = new Request(apiUrl.toString(), {
        method: request.method,
        headers,
        body: request.method !== 'GET' && request.method !== 'HEAD' ? request.body : undefined,
      });

      const apiResponse = await env.API.fetch(apiRequest);

      // Return API response with CORS headers for the custom domain
      const responseHeaders = new Headers(apiResponse.headers);
      responseHeaders.set('Access-Control-Allow-Origin', `https://${host}`);
      responseHeaders.set('Access-Control-Allow-Credentials', 'true');

      return new Response(apiResponse.body, {
        status: apiResponse.status,
        headers: responseHeaders,
      });
    }

    // Handle preflight for all API proxy routes
    if ((url.pathname.startsWith('/_auth') || url.pathname.startsWith('/_db') || url.pathname.startsWith('/_me') || url.pathname.startsWith('/_uploads') || url.pathname.startsWith('/_email') || url.pathname.startsWith('/_itsalive') || url.pathname.startsWith('/_ai')) && request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': `https://${host}`,
          'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type',
          'Access-Control-Allow-Credentials': 'true',
          'Access-Control-Max-Age': '86400',
        },
      });
    }

    // User private data proxy for custom domains - forwards to API via Service Binding
    if (url.pathname.startsWith('/_me/')) {
      const cookie = request.headers.get('cookie') || '';
      const match = cookie.match(/itsalive_session=([^;]+)/);

      // Build the API URL (remove /_me prefix, add to api.itsalive.co/me)
      const apiPath = url.pathname.replace('/_me/', '/me/');
      const apiUrl = new URL(apiPath + url.search, 'https://api.itsalive.co');

      // Forward request to API with session token header
      const headers = new Headers(request.headers);
      headers.delete('cookie');
      headers.delete('host');
      headers.set('X-Forwarded-Host', host);
      if (match) {
        headers.set('X-Session-Token', match[1]);
      }

      const apiRequest = new Request(apiUrl.toString(), {
        method: request.method,
        headers,
        body: request.method !== 'GET' && request.method !== 'HEAD' ? request.body : undefined,
      });

      const apiResponse = await env.API.fetch(apiRequest);

      const responseHeaders = new Headers(apiResponse.headers);
      responseHeaders.set('Access-Control-Allow-Origin', `https://${host}`);
      responseHeaders.set('Access-Control-Allow-Credentials', 'true');

      return new Response(apiResponse.body, {
        status: apiResponse.status,
        headers: responseHeaders,
      });
    }

    // Build path
    let path = url.pathname;
    if (path === '/') path = '/index.html';

    const key = `${subdomain}${path}`;

    // Try exact match
    let object = await env.SITES.get(key);

    // Fallback to index.html for SPA routing
    const isSpaFallback = !object;
    if (!object) {
      object = await env.SITES.get(`${subdomain}/index.html`);
    }

    if (!object) {
      return new Response(comingSoonPage(subdomain), {
        status: 200,
        headers: { 'content-type': 'text/html' },
      });
    }

    const headers = new Headers();
    headers.set('content-type', getContentType(path));
    headers.set('cache-control', 'public, max-age=3600');

    // Check if this SPA fallback matches an OG route for dynamic meta tags
    if (isSpaFallback && url.pathname !== '/') {
      const ogData = await getOGDataForPath(env, subdomain, url.pathname);
      if (ogData) {
        const html = await object.text();
        const modifiedHtml = injectOGTags(html, ogData, subdomain);
        // Track page view
        ctx.waitUntil(trackPageView(env, request, subdomain));
        return new Response(modifiedHtml, {
          headers: {
            'content-type': 'text/html',
            'cache-control': 'public, max-age=60',
          },
        });
      }
    }

    // Track page view for HTML pages
    const contentType = getContentType(path);
    if (contentType === 'text/html' && subdomain) {
      ctx.waitUntil(trackPageView(env, request, subdomain));
    }

    return new Response(object.body, { headers });
  }
};

// Track page view to Analytics Engine
async function trackPageView(env, request, subdomain) {
  try {
    if (!env.ANALYTICS) return;

    // Create visitor hash from IP + User-Agent (privacy-friendly, changes daily)
    const ip = request.headers.get('cf-connecting-ip') || 'unknown';
    const ua = request.headers.get('user-agent') || 'unknown';
    const today = new Date().toISOString().slice(0, 10);
    const visitorData = `${ip}:${ua}:${today}`;

    // Simple hash function for visitor ID
    const encoder = new TextEncoder();
    const data = encoder.encode(visitorData);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = new Uint8Array(hashBuffer);
    const visitorHash = Array.from(hashArray.slice(0, 8))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');

    const country = request.cf?.country || 'XX';

    env.ANALYTICS.writeDataPoint({
      blobs: [subdomain, visitorHash, country],
      doubles: [1], // page view count
      indexes: [subdomain],
    });
  } catch (e) {
    // Don't fail the request if analytics fails
    console.error('Analytics error:', e);
  }
}

function getContentType(path) {
  const ext = path.split('.').pop();
  const types = {
    html: 'text/html',
    css: 'text/css',
    js: 'application/javascript',
    json: 'application/json',
    png: 'image/png',
    jpg: 'image/jpeg',
    jpeg: 'image/jpeg',
    gif: 'image/gif',
    svg: 'image/svg+xml',
    ico: 'image/x-icon',
    woff: 'font/woff',
    woff2: 'font/woff2',
  };
  return types[ext] || 'application/octet-stream';
}

function escapeXml(str) {
  return str.replace(/[<>&'"]/g, c => ({
    '<': '&lt;',
    '>': '&gt;',
    '&': '&amp;',
    "'": '&apos;',
    '"': '&quot;'
  })[c]);
}

function notFoundPage(domain) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Domain Not Found</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: system-ui, -apple-system, sans-serif;
      background: #0a0a0b;
      color: #fff;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .container { text-align: center; padding: 2rem; }
    h1 { font-size: 2rem; margin-bottom: 1rem; }
    p { color: #888; margin-bottom: 1.5rem; }
    code { background: #1a1a1a; padding: 0.3rem 0.6rem; border-radius: 4px; }
    a { color: #00d4ff; text-decoration: none; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Domain Not Configured</h1>
    <p><code>${domain}</code> is not connected to any app.</p>
    <p><a href="https://itsalive.co">Learn more about itsalive.co</a></p>
  </div>
</body>
</html>`;
}

function comingSoonPage(subdomain) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${subdomain}.itsalive.co - Coming Soon</title>
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
    <div class="icon">&#128640;</div>
    <h1>Coming Soon</h1>
    <p>This site is being built and will be live shortly.</p>
    <div class="subdomain">${subdomain}.itsalive.co</div>
  </div>
  <p class="footer"><a href="https://itsalive.co">Powered by itsalive.co</a></p>
</body>
</html>`;
}

function checkoutPage(plan, site) {
  const validPlan = ['pro_monthly', 'pro_annual'].includes(plan) ? plan : 'pro_annual';
  const isAnnual = validPlan === 'pro_annual';
  const planName = isAnnual ? 'Pro Annual' : 'Pro Monthly';
  const price = isAnnual ? '$50/year' : '$5/month';
  const credits = isAnnual ? '20,000' : '1,500';
  const siteDisplay = site || 'your site';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Checkout - itsalive.co</title>
  <script src="https://js.stripe.com/v3/"></script>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: system-ui, -apple-system, sans-serif;
      background: #0a0a0b;
      color: #fff;
      min-height: 100vh;
    }
    .header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 1.5rem 2rem;
      border-bottom: 1px solid #1a1a1a;
      background: #0d0d0d;
    }
    .logo {
      font-size: 1.5rem;
      font-weight: 800;
      background: linear-gradient(135deg, #00d4ff 0%, #7b2dff 50%, #ff2d7b 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      text-decoration: none;
    }
    .back-link {
      color: #888;
      text-decoration: none;
      font-size: 0.9rem;
    }
    .back-link:hover { color: #fff; }
    .container {
      max-width: 500px;
      margin: 0 auto;
      padding: 3rem 1.5rem;
    }
    h1 {
      font-size: 1.75rem;
      margin-bottom: 0.5rem;
    }
    .subtitle {
      color: #888;
      margin-bottom: 2rem;
    }
    .plan-summary {
      background: rgba(255,255,255,0.02);
      border: 1px solid #222;
      border-radius: 12px;
      padding: 1.5rem;
      margin-bottom: 2rem;
    }
    .plan-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 1rem;
    }
    .plan-name {
      font-weight: 700;
      font-size: 1.1rem;
    }
    .plan-price {
      font-size: 1.5rem;
      font-weight: 800;
      background: linear-gradient(135deg, #00d4ff, #7b2dff);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }
    .plan-details {
      color: #888;
      font-size: 0.9rem;
    }
    .change-plan {
      color: #00d4ff;
      text-decoration: none;
      font-size: 0.85rem;
    }
    .change-plan:hover { text-decoration: underline; }
    .payment-section {
      margin-bottom: 1.5rem;
    }
    .payment-section h2 {
      font-size: 1rem;
      color: #888;
      text-transform: uppercase;
      letter-spacing: 1px;
      margin-bottom: 1rem;
    }
    #payment-element {
      background: #111;
      border: 1px solid #333;
      border-radius: 8px;
      padding: 1rem;
    }
    .btn {
      width: 100%;
      padding: 1rem;
      background: linear-gradient(135deg, #00d4ff, #7b2dff);
      border: none;
      border-radius: 8px;
      color: #fff;
      font-size: 1rem;
      font-weight: 600;
      cursor: pointer;
      margin-top: 1.5rem;
      transition: opacity 0.2s;
    }
    .btn:hover { opacity: 0.9; }
    .btn:disabled {
      opacity: 0.5;
      cursor: not-allowed;
    }
    .error-message {
      background: rgba(255,68,68,0.1);
      border: 1px solid rgba(255,68,68,0.3);
      color: #ff6b6b;
      padding: 1rem;
      border-radius: 8px;
      margin-top: 1rem;
      display: none;
    }
    .loading {
      text-align: center;
      padding: 2rem;
      color: #888;
    }
    .secure-note {
      text-align: center;
      color: #666;
      font-size: 0.8rem;
      margin-top: 1.5rem;
    }
  </style>
</head>
<body>
  <header class="header">
    <a href="/" class="logo">itsalive.co</a>
    <a href="/" class="back-link">← Back to Dashboard</a>
  </header>

  <div class="container">
    <h1>Upgrade ${site ? site + '.itsalive.co' : 'your site'}</h1>
    <p class="subtitle">Credits are shared across all your sites</p>

    <div class="plan-summary">
      <div class="plan-header">
        <span class="plan-name">${planName}</span>
        <span class="plan-price">${price}</span>
      </div>
      <div class="plan-details">${credits} credits ${isAnnual ? 'per year' : 'per month'}</div>
      <a href="/checkout?plan=${isAnnual ? 'pro_monthly' : 'pro_annual'}&site=${site || ''}" class="change-plan">${isAnnual ? '← Switch to Monthly ($5/mo)' : '← Switch to Annual ($50/yr - save 17%)'}</a>
    </div>

    <div class="payment-section">
      <h2>Payment Details</h2>
      <div id="payment-element">
        <div class="loading">Loading payment form...</div>
      </div>
    </div>

    <button id="submit-btn" class="btn" disabled>Subscribe</button>
    <div id="error-message" class="error-message"></div>

    <p class="secure-note">🔒 Secured by Stripe. Your card details are never stored on our servers.</p>
  </div>

  <script>
    const API = 'https://api.itsalive.co';
    const plan = '${validPlan}';
    const site = '${site || ''}';
    let stripe, elements, setupIntentId;

    async function init() {
      try {
        // Check if logged in (owner session for dashboard)
        const meRes = await fetch(API + '/owner/me', { credentials: 'include' });
        if (!meRes.ok) {
          showError('Please log in to continue. Redirecting...');
          setTimeout(() => { window.location.href = '/'; }, 2000);
          return;
        }

        // Check if returning from redirect (3D Secure, etc.)
        const urlParams = new URLSearchParams(window.location.search);
        if (urlParams.get('status') === 'processing' && urlParams.get('setup_intent')) {
          const redirectSetupIntentId = urlParams.get('setup_intent');
          // Clear URL params
          window.history.replaceState({}, '', '/checkout?plan=' + plan + '&site=' + site);
          // Create subscription with the confirmed SetupIntent
          document.getElementById('submit-btn').textContent = 'Creating subscription...';
          document.getElementById('submit-btn').disabled = true;
          const subRes = await fetch(API + '/billing/create-subscription', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ plan, site, setup_intent_id: redirectSetupIntentId })
          });
          const subData = await subRes.json();
          if (subData.error) {
            showError(subData.error);
            document.getElementById('submit-btn').disabled = false;
            document.getElementById('submit-btn').textContent = 'Subscribe';
            return;
          }
          window.location.href = '/?billing=success';
          return;
        }

        // Get Stripe config
        const configRes = await fetch(API + '/billing/config', { credentials: 'include' });
        if (!configRes.ok) {
          showError('Failed to load payment configuration');
          return;
        }
        const config = await configRes.json();
        stripe = Stripe(config.publishable_key);

        // Create SetupIntent
        if (!site) {
          showError('No site specified. Please go back to the dashboard and select a site to upgrade.');
          return;
        }

        const siRes = await fetch(API + '/billing/setup-intent', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({ plan, site })
        });
        const siData = await siRes.json();

        if (siData.error) {
          showError(siData.error);
          return;
        }

        if (!siData.client_secret) {
          showError('Failed to initialize payment. Missing client_secret.');
          return;
        }

        setupIntentId = siData.setup_intent_id;

        // Create Payment Element
        elements = stripe.elements({
          clientSecret: siData.client_secret,
          appearance: {
            theme: 'night',
            variables: {
              colorPrimary: '#00d4ff',
              colorBackground: '#111',
              colorText: '#fff',
              colorDanger: '#ff4444',
              fontFamily: 'system-ui, -apple-system, sans-serif',
              borderRadius: '6px',
            },
            rules: {
              '.Input': {
                border: '1px solid #333',
                backgroundColor: '#0a0a0b',
              },
              '.Input:focus': {
                border: '1px solid #00d4ff',
              },
              '.Label': {
                color: '#888',
              },
            },
          },
        });

        const paymentElement = elements.create('payment', {
          layout: 'tabs',
          paymentMethodOrder: ['apple_pay', 'google_pay', 'card', 'link'],
        });
        paymentElement.mount('#payment-element');

        paymentElement.on('ready', () => {
          document.getElementById('submit-btn').disabled = false;
        });

      } catch (err) {
        showError('Failed to initialize checkout: ' + err.message);
      }
    }

    async function handleSubmit() {
      const btn = document.getElementById('submit-btn');
      btn.disabled = true;
      btn.textContent = 'Processing...';
      hideError();

      try {
        // Confirm the SetupIntent
        const { error, setupIntent } = await stripe.confirmSetup({
          elements,
          confirmParams: {
            return_url: window.location.origin + '/checkout?plan=' + plan + '&site=' + site + '&status=processing',
          },
          redirect: 'if_required',
        });

        if (error) {
          showError(error.message);
          btn.disabled = false;
          btn.textContent = 'Subscribe';
          return;
        }

        // SetupIntent confirmed, now create the subscription
        btn.textContent = 'Creating subscription...';

        const subRes = await fetch(API + '/billing/create-subscription', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({ plan, site, setup_intent_id: setupIntentId })
        });
        const subData = await subRes.json();

        if (subData.error) {
          showError(subData.error);
          btn.disabled = false;
          btn.textContent = 'Subscribe';
          return;
        }

        // Success! Redirect to dashboard
        window.location.href = '/?billing=success';

      } catch (err) {
        showError('Payment failed: ' + err.message);
        btn.disabled = false;
        btn.textContent = 'Subscribe';
      }
    }

    function showError(msg) {
      const el = document.getElementById('error-message');
      el.textContent = msg;
      el.style.display = 'block';
    }

    function hideError() {
      document.getElementById('error-message').style.display = 'none';
    }

    document.getElementById('submit-btn').addEventListener('click', handleSubmit);
    init();
  </script>
</body>
</html>`;
}

function dashboardPage() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Dashboard - itsalive.co</title>
  <script src="https://js.stripe.com/v3/"></script>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: system-ui, -apple-system, sans-serif;
      background: #0a0a0b;
      color: #fff;
      min-height: 100vh;
    }
    .header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 1.5rem 2rem;
      border-bottom: 1px solid #1a1a1a;
      background: #0d0d0d;
    }
    .logo {
      font-size: 1.5rem;
      font-weight: 800;
      background: linear-gradient(135deg, #00d4ff 0%, #7b2dff 50%, #ff2d7b 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      text-decoration: none;
    }
    .header-right {
      display: flex;
      align-items: center;
      gap: 1rem;
    }
    .user-email {
      color: #888;
      font-size: 0.9rem;
    }
    .btn {
      display: inline-block;
      padding: 0.6rem 1.2rem;
      background: #fff;
      color: #000;
      border: none;
      border-radius: 6px;
      font-size: 0.9rem;
      font-weight: 600;
      cursor: pointer;
      text-decoration: none;
      transition: transform 0.2s;
    }
    .btn:hover { transform: translateY(-1px); }
    .btn-secondary {
      background: transparent;
      border: 1px solid #333;
      color: #fff;
    }
    .btn-small {
      padding: 0.4rem 0.8rem;
      font-size: 0.8rem;
    }
    .container {
      max-width: 900px;
      margin: 0 auto;
      padding: 2rem;
    }
    h1 {
      font-size: 1.75rem;
      margin-bottom: 0.5rem;
    }
    .subtitle {
      color: #666;
      margin-bottom: 2rem;
    }
    .apps-grid {
      display: grid;
      gap: 1rem;
    }
    .app-card {
      background: rgba(255,255,255,0.02);
      border: 1px solid rgba(255,255,255,0.08);
      border-radius: 12px;
      padding: 1.5rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
      transition: border-color 0.2s;
    }
    .app-card:hover {
      border-color: rgba(255,255,255,0.15);
    }
    .app-info h3 {
      font-size: 1.1rem;
      margin-bottom: 0.25rem;
    }
    .app-info h3 a {
      color: #fff;
      text-decoration: none;
    }
    .app-info h3 a:hover {
      color: #00d4ff;
    }
    .app-url {
      color: #666;
      font-size: 0.85rem;
      font-family: 'SF Mono', Monaco, monospace;
    }
    .app-url a {
      color: #00d4ff;
      text-decoration: none;
    }
    .app-meta {
      color: #555;
      font-size: 0.8rem;
      margin-top: 0.5rem;
    }
    .app-actions {
      display: flex;
      gap: 0.5rem;
    }
    .empty-state {
      text-align: center;
      padding: 4rem 2rem;
      color: #666;
    }
    .empty-state h2 {
      color: #888;
      margin-bottom: 1rem;
    }
    .empty-state code {
      display: inline-block;
      background: #1a1a1a;
      padding: 0.75rem 1.5rem;
      border-radius: 8px;
      font-family: 'SF Mono', Monaco, monospace;
      margin: 1rem 0;
    }
    .login-card {
      max-width: 400px;
      margin: 4rem auto;
      background: rgba(255,255,255,0.02);
      border: 1px solid rgba(255,255,255,0.08);
      border-radius: 16px;
      padding: 2.5rem;
      text-align: center;
    }
    .login-card h2 {
      margin-bottom: 0.5rem;
    }
    .login-card p {
      color: #888;
      margin-bottom: 1.5rem;
    }
    .form-group {
      margin-bottom: 1rem;
    }
    input[type="text"], input[type="email"] {
      width: 100%;
      padding: 0.75rem 1rem;
      background: #111;
      border: 1px solid #333;
      border-radius: 8px;
      color: #fff;
      font-size: 1rem;
    }
    input:focus {
      outline: none;
      border-color: #00d4ff;
    }
    .message {
      margin-top: 1rem;
      padding: 0.75rem;
      border-radius: 8px;
    }
    .message.success {
      background: rgba(39, 202, 64, 0.1);
      color: #27ca40;
    }
    .message.error {
      background: rgba(255, 68, 68, 0.1);
      color: #ff4444;
    }
    #loading {
      text-align: center;
      padding: 4rem;
      color: #666;
    }
    .hidden { display: none; }

    /* Modal */
    .modal-overlay {
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: rgba(0,0,0,0.8);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 1000;
    }
    .modal {
      background: #111;
      border: 1px solid #222;
      border-radius: 16px;
      padding: 2rem;
      width: 90%;
      max-width: 500px;
      max-height: 90vh;
      overflow-y: auto;
    }
    .modal h2 {
      margin-bottom: 1.5rem;
    }
    .modal-actions {
      display: flex;
      gap: 0.5rem;
      justify-content: flex-end;
      margin-top: 1.5rem;
      padding-top: 1.5rem;
      border-top: 1px solid #222;
    }
    label {
      display: block;
      margin-bottom: 0.5rem;
      color: #888;
      font-size: 0.9rem;
    }
    .dns-box {
      background: #0a0a0b;
      border-radius: 8px;
      padding: 1rem;
      margin-top: 1rem;
      font-family: 'SF Mono', Monaco, monospace;
      font-size: 0.85rem;
    }
    .dns-row {
      display: flex;
      justify-content: space-between;
      padding: 0.25rem 0;
    }
    .dns-label { color: #666; }
    .dns-value { color: #00d4ff; }
    .status-badge {
      display: inline-block;
      padding: 0.25rem 0.5rem;
      border-radius: 4px;
      font-size: 0.75rem;
      font-weight: 600;
    }
    .status-badge.active {
      background: rgba(39, 202, 64, 0.1);
      color: #27ca40;
    }
    .status-badge.pending {
      background: rgba(255, 189, 46, 0.1);
      color: #ffbd2e;
    }

    /* Stats styles */
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
      gap: 1rem;
      margin-bottom: 2rem;
    }
    .stat-card {
      background: rgba(255,255,255,0.03);
      border: 1px solid rgba(255,255,255,0.08);
      border-radius: 12px;
      padding: 1.25rem;
      text-align: center;
    }
    .stat-value {
      font-size: 2rem;
      font-weight: 700;
      background: linear-gradient(135deg, #00d4ff, #7b2dff);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }
    .stat-label {
      font-size: 0.8rem;
      color: #666;
      margin-top: 0.25rem;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .stats-section {
      margin-bottom: 2rem;
    }
    .stats-section h3 {
      font-size: 1rem;
      color: #888;
      margin-bottom: 1rem;
      padding-bottom: 0.5rem;
      border-bottom: 1px solid #222;
    }
    .chart-container {
      background: rgba(0,0,0,0.3);
      border-radius: 8px;
      padding: 1rem;
      min-height: 200px;
    }
    .chart-bars {
      display: flex;
      align-items: flex-end;
      justify-content: space-between;
      height: 150px;
      gap: 4px;
      padding: 0 0.5rem;
    }
    .chart-bar-wrapper {
      flex: 1;
      display: flex;
      flex-direction: column;
      align-items: center;
      height: 100%;
    }
    .chart-bar {
      width: 100%;
      max-width: 40px;
      background: linear-gradient(180deg, #00d4ff, #7b2dff);
      border-radius: 4px 4px 0 0;
      min-height: 4px;
      transition: height 0.3s;
    }
    .chart-bar.secondary {
      background: linear-gradient(180deg, #ff2d7b, #ff6b35);
      opacity: 0.7;
    }
    .chart-label {
      font-size: 0.7rem;
      color: #666;
      margin-top: 0.5rem;
      text-align: center;
    }
    .chart-legend {
      display: flex;
      justify-content: center;
      gap: 1.5rem;
      margin-top: 1rem;
      font-size: 0.8rem;
    }
    .legend-item {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      color: #888;
    }
    .legend-dot {
      width: 10px;
      height: 10px;
      border-radius: 50%;
    }
    .legend-dot.primary { background: #00d4ff; }
    .legend-dot.secondary { background: #ff2d7b; }
    .period-selector {
      display: flex;
      gap: 0.5rem;
      margin-bottom: 1rem;
    }
    .period-btn {
      padding: 0.4rem 0.8rem;
      background: transparent;
      border: 1px solid #333;
      color: #888;
      border-radius: 6px;
      cursor: pointer;
      font-size: 0.8rem;
      transition: all 0.2s;
    }
    .period-btn:hover {
      border-color: #555;
      color: #fff;
    }
    .period-btn.active {
      background: #fff;
      color: #000;
      border-color: #fff;
    }
    .ai-usage-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.85rem;
    }
    .ai-usage-table th {
      text-align: left;
      padding: 0.75rem;
      border-bottom: 1px solid #333;
      color: #666;
      font-weight: 500;
    }
    .ai-usage-table td {
      padding: 0.75rem;
      border-bottom: 1px solid #222;
    }
    .no-data {
      text-align: center;
      padding: 2rem;
      color: #666;
    }
  </style>
</head>
<body>
  <header class="header">
    <a href="/" class="logo">It's Alive!</a>
    <div class="header-right" id="header-right"></div>
  </header>

  <div id="loading">Loading...</div>

  <div id="login-view" class="hidden">
    <div class="login-card">
      <h2>Welcome Back</h2>
      <p>Enter your email to access your dashboard</p>
      <form id="login-form">
        <div class="form-group">
          <input type="email" id="login-email" placeholder="you@example.com" required>
        </div>
        <button type="submit" class="btn" style="width: 100%;">Send Login Link</button>
      </form>
      <div id="login-message"></div>
    </div>
  </div>

  <div id="dashboard-view" class="hidden">
    <div class="container">
      <h1>Your Apps</h1>
      <p class="subtitle">Manage your deployed applications</p>
      <div id="apps-list" class="apps-grid"></div>
    </div>
  </div>

  <div id="modal-container"></div>

  <script>
    const API = 'https://api.itsalive.co';
    let currentUser = null;

    async function init() {
      try {
        const res = await fetch(API + '/owner/me', { credentials: 'include' });

        document.getElementById('loading').classList.add('hidden');

        if (res.status === 401) {
          document.getElementById('login-view').classList.remove('hidden');
          return;
        }

        currentUser = await res.json();

        // Load billing info
        const billingRes = await fetch(API + '/billing/info', { credentials: 'include' });
        const billing = billingRes.ok ? await billingRes.json() : null;

        let headerHtml = '';
        if (billing) {
          const balance = billing.credits?.balance || 0;
          const planLabel = billing.subscription ? (billing.subscription.plan === 'pro_annual' ? 'Pro Annual' : 'Pro Monthly') : 'Free';
          headerHtml += '<div class="credits-badge" onclick="openBilling()" style="cursor:pointer;display:flex;align-items:center;gap:0.5rem;padding:0.4rem 0.8rem;background:rgba(0,212,255,0.1);border:1px solid rgba(0,212,255,0.2);border-radius:20px;">';
          headerHtml += '<span style="color:#00d4ff;font-weight:600;">' + balance.toLocaleString() + '</span>';
          headerHtml += '<span style="color:#666;font-size:0.8rem;">credits</span>';
          if (!billing.subscription) {
            headerHtml += '<span style="margin-left:0.25rem;padding:0.15rem 0.4rem;background:#7b2dff;color:#fff;font-size:0.7rem;border-radius:10px;font-weight:600;">UPGRADE</span>';
          }
          headerHtml += '</div>';
        }
        headerHtml += '<span class="user-email">' + currentUser.email + '</span>';
        headerHtml += '<button class="btn btn-secondary btn-small" onclick="logout()">Log Out</button>';
        document.getElementById('header-right').innerHTML = headerHtml;

        // Store billing for later use
        window.currentBilling = billing;

        // Check for billing success/cancel params
        const urlParams = new URLSearchParams(window.location.search);
        if (urlParams.get('billing') === 'success') {
          showBillingSuccess();
          window.history.replaceState({}, '', '/');
        } else if (urlParams.get('billing') === 'canceled') {
          window.history.replaceState({}, '', '/');
        }

        document.getElementById('dashboard-view').classList.remove('hidden');
        loadApps();
      } catch (e) {
        document.getElementById('loading').textContent = 'Error: ' + e.message;
      }
    }

    async function loadApps() {
      const res = await fetch(API + '/owner/apps', { credentials: 'include' });
      const data = await res.json();

      const container = document.getElementById('apps-list');

      if (!data.apps || data.apps.length === 0) {
        container.innerHTML = \`
          <div class="empty-state">
            <h2>No apps yet</h2>
            <p>Deploy your first app with a single command:</p>
            <code>npx itsalive-co</code>
          </div>
        \`;
        return;
      }

      const billing = window.currentBilling;
      const subscriptions = billing?.subscriptions || {};

      container.innerHTML = data.apps.map(app => {
        const hasSiteSub = !!subscriptions[app.subdomain];
        const siteSub = subscriptions[app.subdomain];
        const planBadge = siteSub ? (siteSub.plan === 'pro_annual' ? 'Pro Annual' : 'Pro Monthly') : '';
        return \`
        <div class="app-card">
          <div class="app-info">
            <h3>
              <a href="https://\${app.subdomain}.itsalive.co" target="_blank">\${app.email_app_name || app.subdomain}</a>
              \${hasSiteSub ? '<span style="font-size:0.7rem;background:linear-gradient(135deg,#00d4ff,#7b2dff);color:#fff;padding:0.2rem 0.5rem;border-radius:4px;margin-left:0.5rem;font-weight:500;">' + planBadge + '</span>' : ''}
            </h3>
            <div class="app-url">
              <a href="https://\${app.subdomain}.itsalive.co" target="_blank">\${app.subdomain}.itsalive.co</a>
              \${app.custom_domain ? ' → <a href="https://' + app.custom_domain + '" target="_blank">' + app.custom_domain + '</a>' : ''}
            </div>
            <div class="app-meta">Created \${new Date(app.created_at).toLocaleDateString()}</div>
          </div>
          <div class="app-actions">
            \${!hasSiteSub ? '<a href="/checkout?plan=pro_annual&site=' + app.subdomain + '" class="btn btn-small" style="background:linear-gradient(135deg,#7b2dff,#00d4ff);border:none;">Upgrade</a>' : ''}
            <a href="/stats/\${app.subdomain}" class="btn btn-secondary btn-small">Stats</a>
            <button class="btn btn-secondary btn-small" onclick="openSettings('\${app.subdomain}')">Settings</button>
            <a href="https://\${app.subdomain}.itsalive.co" target="_blank" class="btn btn-small">Visit</a>
          </div>
        </div>
      \`;}).join('');
    }

    async function openSettings(subdomain) {
      const res = await fetch(API + '/owner/app/' + subdomain, { credentials: 'include' });
      const app = await res.json();

      const domainStatus = app.domain_status || 'none';

      let domainSection = '';
      if (domainStatus === 'none') {
        domainSection = \`
          <div class="form-group">
            <label>Custom Domain</label>
            <input type="text" id="edit-domain" placeholder="example.com">
            <p style="color:#666;font-size:0.85rem;margin-top:0.5rem;">Enter your domain (e.g., myapp.com). You'll need to update your nameservers.</p>
          </div>
          <button type="button" class="btn" onclick="setupDomain('\${subdomain}')" style="margin-bottom:1rem;">Set Up Domain</button>
          <div id="domain-message"></div>
        \`;
      } else if (domainStatus === 'pending_ns') {
        const ns = app.nameservers || [];
        domainSection = \`
          <div class="form-group">
            <label>Custom Domain</label>
            <div style="display:flex;align-items:center;gap:0.5rem;">
              <code style="flex:1;">\${app.custom_domain}</code>
              <span class="status-badge pending">Pending</span>
            </div>
            <div class="dns-box" style="margin-top:1rem;">
              <p style="color:#ffbd2e;margin-bottom:0.75rem;font-weight:600;">Update your nameservers</p>
              <p style="color:#888;margin-bottom:0.75rem;font-size:0.85rem;">Go to your domain registrar and change the nameservers to:</p>
              \${ns.map(n => '<div class="dns-row"><span class="dns-value">' + n + '</span></div>').join('')}
            </div>
          </div>
          <button type="button" class="btn" onclick="checkDomainStatus('\${subdomain}')" style="margin-bottom:1rem;">Check Status</button>
          <button type="button" class="btn btn-secondary" onclick="removeDomain('\${subdomain}')" style="margin-bottom:1rem;margin-left:0.5rem;">Remove</button>
          <div id="domain-message"></div>
        \`;
      } else if (domainStatus === 'active') {
        domainSection = \`
          <div class="form-group">
            <label>Custom Domain</label>
            <div style="display:flex;align-items:center;gap:0.5rem;">
              <a href="https://\${app.custom_domain}" target="_blank" style="color:#00d4ff;">\${app.custom_domain}</a>
              <span class="status-badge active">Active</span>
            </div>
          </div>
          <div style="display:flex;gap:0.5rem;margin-bottom:1rem;">
            <button type="button" class="btn" onclick="openDnsManager('\${subdomain}')">Manage DNS</button>
            <button type="button" class="btn btn-secondary" onclick="removeDomain('\${subdomain}')">Remove Domain</button>
          </div>
          <div id="domain-message"></div>
        \`;
      }

      const modal = document.createElement('div');
      modal.className = 'modal-overlay';
      modal.onclick = (e) => { if (e.target === modal) modal.remove(); };
      modal.innerHTML = \`
        <div class="modal">
          <h2>Settings: \${app.branding?.appName || subdomain}</h2>

          <div style="border-bottom:1px solid #222;padding-bottom:1rem;margin-bottom:1rem;">
            \${domainSection}
          </div>

          <form id="settings-form">
            <div class="form-group">
              <label>App Name (for emails)</label>
              <input type="text" id="edit-appname" placeholder="My App" value="\${app.branding?.appName || ''}">
            </div>

            <div class="form-group">
              <label>Tagline</label>
              <input type="text" id="edit-tagline" placeholder="Your productivity companion" value="\${app.branding?.tagline || ''}">
            </div>

            <div style="display:grid;grid-template-columns:1fr 1fr;gap:1rem;">
              <div class="form-group">
                <label>Primary Color</label>
                <input type="text" id="edit-primary" placeholder="#00d4ff" value="\${app.branding?.primaryColor || ''}">
              </div>
              <div class="form-group">
                <label>Button Color</label>
                <input type="text" id="edit-button" placeholder="#ffffff" value="\${app.branding?.buttonColor || ''}">
              </div>
            </div>

            <div id="settings-message"></div>

            <div class="modal-actions">
              <button type="button" class="btn btn-secondary" onclick="this.closest('.modal-overlay').remove()">Cancel</button>
              <button type="submit" class="btn">Save Branding</button>
            </div>
          </form>
        </div>
      \`;

      document.getElementById('modal-container').appendChild(modal);

      document.getElementById('settings-form').onsubmit = async (e) => {
        e.preventDefault();
        const msgEl = document.getElementById('settings-message');

        try {
          const res = await fetch(API + '/owner/app/' + subdomain, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({
              app_name: document.getElementById('edit-appname').value || null,
              tagline: document.getElementById('edit-tagline').value || null,
              primary_color: document.getElementById('edit-primary').value || null,
              button_color: document.getElementById('edit-button').value || null,
            })
          });
          const data = await res.json();

          if (data.success) {
            msgEl.innerHTML = '<div class="message success">Saved!</div>';
            setTimeout(() => {
              modal.remove();
              loadApps();
            }, 1000);
          } else {
            msgEl.innerHTML = '<div class="message error">' + (data.error || 'Failed to save') + '</div>';
          }
        } catch (err) {
          msgEl.innerHTML = '<div class="message error">Error: ' + err.message + '</div>';
        }
      };
    }

    async function setupDomain(subdomain) {
      const domain = document.getElementById('edit-domain').value.trim();
      const msgEl = document.getElementById('domain-message');

      if (!domain) {
        msgEl.innerHTML = '<div class="message error">Please enter a domain</div>';
        return;
      }

      msgEl.innerHTML = '<div class="message">Setting up domain...</div>';

      try {
        const res = await fetch(API + '/owner/app/' + subdomain + '/setup-domain', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({ domain })
        });
        const data = await res.json();

        if (data.success) {
          // Refresh the modal to show nameservers
          document.querySelector('.modal-overlay').remove();
          openSettings(subdomain);
        } else {
          msgEl.innerHTML = '<div class="message error">' + (data.error || 'Failed to set up domain') + '</div>';
        }
      } catch (err) {
        msgEl.innerHTML = '<div class="message error">Error: ' + err.message + '</div>';
      }
    }

    async function checkDomainStatus(subdomain) {
      const msgEl = document.getElementById('domain-message');
      msgEl.innerHTML = '<div class="message">Checking status...</div>';

      try {
        const res = await fetch(API + '/owner/app/' + subdomain + '/domain-status', {
          credentials: 'include'
        });
        const data = await res.json();

        if (data.status === 'active') {
          msgEl.innerHTML = '<div class="message success">Domain is active!</div>';
          setTimeout(() => {
            document.querySelector('.modal-overlay').remove();
            openSettings(subdomain);
            loadApps();
          }, 1000);
        } else {
          msgEl.innerHTML = '<div class="message">' + (data.message || 'Still waiting for nameserver update...') + '</div>';
        }
      } catch (err) {
        msgEl.innerHTML = '<div class="message error">Error: ' + err.message + '</div>';
      }
    }

    async function removeDomain(subdomain) {
      if (!confirm('Remove custom domain? This will delete the DNS configuration.')) return;

      const msgEl = document.getElementById('domain-message');
      msgEl.innerHTML = '<div class="message">Removing domain...</div>';

      try {
        const res = await fetch(API + '/owner/app/' + subdomain + '/domain', {
          method: 'DELETE',
          credentials: 'include'
        });
        const data = await res.json();

        if (data.success) {
          document.querySelector('.modal-overlay').remove();
          openSettings(subdomain);
          loadApps();
        } else {
          msgEl.innerHTML = '<div class="message error">' + (data.error || 'Failed to remove domain') + '</div>';
        }
      } catch (err) {
        msgEl.innerHTML = '<div class="message error">Error: ' + err.message + '</div>';
      }
    }

    async function openDnsManager(subdomain) {
      const modal = document.createElement('div');
      modal.className = 'modal-overlay';
      modal.onclick = (e) => { if (e.target === modal) modal.remove(); };
      modal.innerHTML = \`
        <div class="modal" style="max-width:800px;width:95%;">
          <h2>DNS Records</h2>
          <div id="dns-content"><p style="color:#888;">Loading...</p></div>
        </div>
      \`;
      document.getElementById('modal-container').appendChild(modal);
      await loadDnsRecords(subdomain);
    }

    async function loadDnsRecords(subdomain) {
      const container = document.getElementById('dns-content');
      try {
        const res = await fetch(API + '/owner/app/' + subdomain + '/dns', { credentials: 'include' });
        const data = await res.json();

        if (data.error) {
          container.innerHTML = '<div class="message error">' + data.error + '</div>';
          return;
        }

        const records = data.records || [];
        container.innerHTML = \`
          <p style="color:#888;margin-bottom:1rem;">Domain: <strong>\${data.domain}</strong></p>

          <div style="margin-bottom:1.5rem;">
            <button class="btn btn-small" onclick="showAddDnsForm('\${subdomain}')">+ Add Record</button>
          </div>

          <div id="dns-add-form" style="display:none;margin-bottom:1.5rem;padding:1rem;background:rgba(0,0,0,0.3);border-radius:8px;">
            <h4 style="margin-bottom:1rem;">Add DNS Record</h4>
            <div style="display:grid;grid-template-columns:100px 1fr 1fr auto;gap:0.5rem;align-items:end;">
              <div class="form-group" style="margin:0;">
                <label style="font-size:0.75rem;">Type</label>
                <select id="dns-type" style="padding:0.5rem;">
                  <option value="A">A</option>
                  <option value="AAAA">AAAA</option>
                  <option value="CNAME">CNAME</option>
                  <option value="TXT">TXT</option>
                  <option value="MX">MX</option>
                  <option value="NS">NS</option>
                </select>
              </div>
              <div class="form-group" style="margin:0;">
                <label style="font-size:0.75rem;">Name</label>
                <input type="text" id="dns-name" placeholder="@ or subdomain">
              </div>
              <div class="form-group" style="margin:0;">
                <label style="font-size:0.75rem;">Content</label>
                <input type="text" id="dns-content-input" placeholder="Value">
              </div>
              <button class="btn btn-small" onclick="addDnsRecord('\${subdomain}')" style="height:38px;">Add</button>
            </div>
            <div id="dns-add-priority" style="display:none;margin-top:0.5rem;">
              <label style="font-size:0.75rem;">Priority (for MX)</label>
              <input type="number" id="dns-priority" value="10" style="width:80px;">
            </div>
            <div id="dns-add-message" style="margin-top:0.5rem;"></div>
          </div>

          <table style="width:100%;border-collapse:collapse;font-size:0.9rem;">
            <thead>
              <tr style="border-bottom:1px solid #333;text-align:left;">
                <th style="padding:0.5rem;width:60px;">Type</th>
                <th style="padding:0.5rem;">Name</th>
                <th style="padding:0.5rem;">Content</th>
                <th style="padding:0.5rem;width:80px;">Proxied</th>
                <th style="padding:0.5rem;width:80px;"></th>
              </tr>
            </thead>
            <tbody>
              \${records.length === 0 ? '<tr><td colspan="5" style="padding:1rem;color:#666;text-align:center;">No DNS records</td></tr>' : records.map(r => \`
                <tr style="border-bottom:1px solid #222;">
                  <td style="padding:0.5rem;"><code style="background:#222;padding:0.2rem 0.4rem;border-radius:3px;">\${r.type}</code></td>
                  <td style="padding:0.5rem;word-break:break-all;">\${r.name}</td>
                  <td style="padding:0.5rem;word-break:break-all;font-family:monospace;font-size:0.85rem;">\${r.priority ? '[' + r.priority + '] ' : ''}\${r.content}</td>
                  <td style="padding:0.5rem;">\${r.proxied ? '<span style="color:#f90;">ON</span>' : '<span style="color:#666;">off</span>'}</td>
                  <td style="padding:0.5rem;">
                    <button class="btn btn-small btn-secondary" onclick="deleteDnsRecord('\${subdomain}', '\${r.id}')" style="padding:0.25rem 0.5rem;font-size:0.75rem;">Delete</button>
                  </td>
                </tr>
              \`).join('')}
            </tbody>
          </table>

          <div style="margin-top:1.5rem;text-align:right;">
            <button class="btn btn-secondary" onclick="this.closest('.modal-overlay').remove()">Close</button>
          </div>
        \`;

        // Show priority field when MX is selected
        document.getElementById('dns-type').onchange = function() {
          document.getElementById('dns-add-priority').style.display = this.value === 'MX' ? 'block' : 'none';
        };
      } catch (err) {
        container.innerHTML = '<div class="message error">Error: ' + err.message + '</div>';
      }
    }

    function showAddDnsForm(subdomain) {
      document.getElementById('dns-add-form').style.display = 'block';
    }

    async function addDnsRecord(subdomain) {
      const msgEl = document.getElementById('dns-add-message');
      const type = document.getElementById('dns-type').value;
      const name = document.getElementById('dns-name').value.trim();
      const content = document.getElementById('dns-content-input').value.trim();
      const priority = document.getElementById('dns-priority').value;

      if (!name || !content) {
        msgEl.innerHTML = '<div class="message error">Name and content are required</div>';
        return;
      }

      msgEl.innerHTML = '<div class="message">Adding record...</div>';

      try {
        const body = { type, name, content };
        if (type === 'MX') body.priority = parseInt(priority);

        const res = await fetch(API + '/owner/app/' + subdomain + '/dns', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify(body)
        });
        const data = await res.json();

        if (data.success) {
          await loadDnsRecords(subdomain);
        } else {
          msgEl.innerHTML = '<div class="message error">' + (data.error || 'Failed to add record') + '</div>';
        }
      } catch (err) {
        msgEl.innerHTML = '<div class="message error">Error: ' + err.message + '</div>';
      }
    }

    async function deleteDnsRecord(subdomain, recordId) {
      if (!confirm('Delete this DNS record?')) return;

      try {
        const res = await fetch(API + '/owner/app/' + subdomain + '/dns/' + recordId, {
          method: 'DELETE',
          credentials: 'include'
        });
        const data = await res.json();

        if (data.success) {
          await loadDnsRecords(subdomain);
        } else {
          alert(data.error || 'Failed to delete record');
        }
      } catch (err) {
        alert('Error: ' + err.message);
      }
    }

    document.getElementById('login-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const email = document.getElementById('login-email').value;
      const msgEl = document.getElementById('login-message');

      try {
        const res = await fetch(API + '/owner/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({ email })
        });
        const data = await res.json();

        if (data.success) {
          msgEl.innerHTML = '<div class="message success">Check your email for a login link!</div>';
        } else {
          msgEl.innerHTML = '<div class="message error">' + (data.error || 'Failed') + '</div>';
        }
      } catch (err) {
        msgEl.innerHTML = '<div class="message error">Error: ' + err.message + '</div>';
      }
    });

    // Stats modal
    let currentStatsPeriod = 'day';
    let currentStatsSubdomain = null;

    async function openStats(subdomain) {
      currentStatsSubdomain = subdomain;
      const modal = document.createElement('div');
      modal.className = 'modal-overlay';
      modal.id = 'stats-modal';
      modal.onclick = (e) => { if (e.target === modal) modal.remove(); };
      modal.innerHTML = \`
        <div class="modal" style="max-width:900px;width:95%;">
          <h2>Stats: \${subdomain}</h2>
          <div id="stats-content"><p style="color:#888;">Loading...</p></div>
          <div style="margin-top:1.5rem;text-align:right;">
            <button class="btn btn-secondary" onclick="this.closest('.modal-overlay').remove()">Close</button>
          </div>
        </div>
      \`;
      document.getElementById('modal-container').appendChild(modal);
      await loadStats(subdomain);
    }

    async function loadStats(subdomain) {
      const container = document.getElementById('stats-content');

      try {
        const [summaryRes, trafficRes, aiRes] = await Promise.all([
          fetch(API + '/stats/summary?subdomain=' + subdomain, { credentials: 'include' }),
          fetch(API + '/stats/traffic?subdomain=' + subdomain + '&period=' + currentStatsPeriod, { credentials: 'include' }),
          fetch(API + '/stats/ai?subdomain=' + subdomain + '&period=month', { credentials: 'include' })
        ]);

        const summary = await summaryRes.json();
        const traffic = await trafficRes.json();
        const ai = await aiRes.json();

        if (summary.error) {
          container.innerHTML = '<div class="message error">' + summary.error + '</div>';
          return;
        }

        // Format numbers
        const fmt = (n) => {
          if (n >= 1000000) return (n/1000000).toFixed(1) + 'M';
          if (n >= 1000) return (n/1000).toFixed(1) + 'K';
          return (n || 0).toString();
        };

        // Build traffic chart
        const trafficData = traffic.data || [];
        const maxViews = Math.max(...trafficData.map(d => d.page_views || 0), 1);
        const maxVisitors = Math.max(...trafficData.map(d => d.unique_visitors || 0), 1);
        const chartMax = Math.max(maxViews, maxVisitors);

        let trafficChart = '';
        if (trafficData.length > 0) {
          trafficChart = \`
            <div class="chart-bars">
              \${trafficData.slice(-14).map(d => {
                const viewsHeight = chartMax > 0 ? ((d.page_views || 0) / chartMax) * 130 : 0;
                const visitorsHeight = chartMax > 0 ? ((d.unique_visitors || 0) / chartMax) * 130 : 0;
                const label = formatChartLabel(d.period, currentStatsPeriod);
                return \`
                  <div class="chart-bar-wrapper">
                    <div style="display:flex;gap:2px;align-items:flex-end;height:130px;">
                      <div class="chart-bar" style="height:\${viewsHeight}px;" title="Views: \${d.page_views || 0}"></div>
                      <div class="chart-bar secondary" style="height:\${visitorsHeight}px;" title="Visitors: \${d.unique_visitors || 0}"></div>
                    </div>
                    <div class="chart-label">\${label}</div>
                  </div>
                \`;
              }).join('')}
            </div>
            <div class="chart-legend">
              <div class="legend-item"><div class="legend-dot primary"></div> Page Views</div>
              <div class="legend-item"><div class="legend-dot secondary"></div> Unique Visitors</div>
            </div>
          \`;
        } else {
          trafficChart = '<div class="no-data">No traffic data yet</div>';
        }

        // Build AI usage table
        let aiTable = '';
        const aiData = ai.data || [];
        if (aiData.length > 0) {
          const totalCredits = aiData.reduce((sum, d) => sum + (d.total_credits || 0), 0);
          const totalRequests = aiData.reduce((sum, d) => sum + (d.requests || 0), 0);
          aiTable = \`
            <table class="ai-usage-table">
              <thead>
                <tr>
                  <th>Provider</th>
                  <th>Tier</th>
                  <th>Requests</th>
                  <th>Tokens</th>
                  <th>Credits</th>
                </tr>
              </thead>
              <tbody>
                \${aiData.map(d => \`
                  <tr>
                    <td>\${d.provider}</td>
                    <td>\${d.tier}</td>
                    <td>\${fmt(d.requests)}</td>
                    <td>\${fmt(d.total_tokens)}</td>
                    <td>\${fmt(d.total_credits)}</td>
                  </tr>
                \`).join('')}
              </tbody>
            </table>
            <p style="margin-top:1rem;color:#666;font-size:0.85rem;">
              Total: \${fmt(totalRequests)} requests, \${fmt(totalCredits)} credits used this month
            </p>
          \`;
        } else {
          aiTable = '<div class="no-data">No AI usage this month</div>';
        }

        container.innerHTML = \`
          <div class="stats-grid">
            <div class="stat-card">
              <div class="stat-value">\${fmt(summary.dau)}</div>
              <div class="stat-label">DAU</div>
            </div>
            <div class="stat-card">
              <div class="stat-value">\${fmt(summary.wau)}</div>
              <div class="stat-label">WAU</div>
            </div>
            <div class="stat-card">
              <div class="stat-value">\${fmt(summary.mau)}</div>
              <div class="stat-label">MAU</div>
            </div>
            <div class="stat-card">
              <div class="stat-value">\${fmt(summary.total_users)}</div>
              <div class="stat-label">Total Users</div>
            </div>
            <div class="stat-card">
              <div class="stat-value">\${fmt(summary.signups_today)}</div>
              <div class="stat-label">Signups Today</div>
            </div>
            <div class="stat-card">
              <div class="stat-value">\${fmt(summary.total_documents)}</div>
              <div class="stat-label">Documents</div>
            </div>
          </div>

          <div class="stats-section">
            <h3>Traffic</h3>
            <div class="period-selector">
              <button class="period-btn \${currentStatsPeriod === 'hour' ? 'active' : ''}" onclick="changeStatsPeriod('hour')">Hourly</button>
              <button class="period-btn \${currentStatsPeriod === 'day' ? 'active' : ''}" onclick="changeStatsPeriod('day')">Daily</button>
              <button class="period-btn \${currentStatsPeriod === 'week' ? 'active' : ''}" onclick="changeStatsPeriod('week')">Weekly</button>
              <button class="period-btn \${currentStatsPeriod === 'month' ? 'active' : ''}" onclick="changeStatsPeriod('month')">Monthly</button>
            </div>
            <div class="chart-container">
              \${trafficChart}
            </div>
          </div>

          <div class="stats-section">
            <h3>AI Usage (This Month)</h3>
            \${aiTable}
          </div>
        \`;
      } catch (err) {
        container.innerHTML = '<div class="message error">Error loading stats: ' + err.message + '</div>';
      }
    }

    function formatChartLabel(period, type) {
      if (!period) return '';
      if (type === 'hour') {
        const h = parseInt(period.split(' ')[1] || period);
        return h + ':00';
      }
      if (type === 'day') {
        const d = new Date(period);
        return (d.getMonth()+1) + '/' + d.getDate();
      }
      if (type === 'week') {
        return 'W' + period.split('-W')[1];
      }
      if (type === 'month') {
        const parts = period.split('-');
        return parts[1] + '/' + parts[0].slice(2);
      }
      return period;
    }

    async function changeStatsPeriod(period) {
      currentStatsPeriod = period;
      if (currentStatsSubdomain) {
        document.getElementById('stats-content').innerHTML = '<p style="color:#888;">Loading...</p>';
        await loadStats(currentStatsSubdomain);
      }
    }

    // ============ BILLING FUNCTIONS ============

    function showBillingSuccess() {
      const banner = document.createElement('div');
      banner.style.cssText = 'position:fixed;top:0;left:0;right:0;background:linear-gradient(90deg,#00d4ff,#7b2dff);color:#fff;text-align:center;padding:1rem;font-weight:600;z-index:9999;';
      banner.innerHTML = 'Payment successful! Your credits have been added. <button onclick="this.parentElement.remove()" style="margin-left:1rem;background:#fff;color:#000;border:none;padding:0.4rem 0.8rem;border-radius:4px;cursor:pointer;">Dismiss</button>';
      document.body.prepend(banner);
      setTimeout(() => banner.remove(), 10000);
    }

    async function openBilling() {
      const billing = window.currentBilling;
      if (!billing) return;

      const subscriptions = billing.subscriptions || {};
      const siteList = Object.keys(subscriptions);
      const hasAnySubscription = siteList.length > 0;
      const balance = billing.credits?.balance || 0;
      const lifetimePurchased = billing.credits?.lifetime_purchased || 0;
      const lifetimeUsed = billing.credits?.lifetime_used || 0;
      const autoRefill = billing.auto_refill || { enabled: false, threshold: 10000, refill_amount: 50000, price_cents: 5000 };
      const hasPaymentMethod = billing.has_payment_method;

      let subscriptionSection = '';
      if (hasAnySubscription) {
        // Show all site subscriptions
        const subItems = siteList.map(site => {
          const sub = subscriptions[site];
          const planName = sub.plan === 'pro_annual' ? 'Pro Annual' : 'Pro Monthly';
          const renewDate = new Date(sub.current_period_end).toLocaleDateString();
          return \`
            <div style="display:flex;justify-content:space-between;align-items:center;padding:0.75rem 0;border-bottom:1px solid rgba(255,255,255,0.05);">
              <div>
                <div style="font-weight:600;">\${site}.itsalive.co</div>
                <div style="font-size:0.85rem;color:#888;">\${planName} - \${sub.cancel_at_period_end ? 'Cancels' : 'Renews'} \${renewDate}</div>
              </div>
            </div>
          \`;
        }).join('');

        subscriptionSection = \`
          <div style="background:linear-gradient(135deg,rgba(0,212,255,0.1),rgba(123,45,255,0.1));border:1px solid rgba(0,212,255,0.2);border-radius:12px;padding:1.5rem;margin-bottom:1.5rem;">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem;">
              <div style="font-size:0.8rem;color:#888;text-transform:uppercase;letter-spacing:1px;">Active Subscriptions</div>
              <button class="btn btn-secondary btn-small" onclick="openPortal()">Manage</button>
            </div>
            \${subItems}
          </div>
        \`;
      } else {
        subscriptionSection = \`
          <div style="background:rgba(255,255,255,0.02);border:1px solid rgba(255,255,255,0.08);border-radius:12px;padding:1.5rem;margin-bottom:1.5rem;text-align:center;">
            <div style="font-size:0.9rem;color:#888;">No active subscriptions</div>
            <div style="font-size:0.85rem;color:#666;margin-top:0.5rem;">Upgrade individual sites from the dashboard</div>
          </div>
        \`;
      }

      const modal = document.createElement('div');
      modal.className = 'modal-overlay';
      modal.onclick = (e) => { if (e.target === modal) modal.remove(); };
      modal.innerHTML = \`
        <div class="modal" style="max-width:550px;">
          <h2>Billing & Credits</h2>

          <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:1rem;margin:1.5rem 0;">
            <div style="text-align:center;padding:1rem;background:rgba(255,255,255,0.02);border-radius:8px;">
              <div style="font-size:1.75rem;font-weight:700;color:#00d4ff;">\${balance.toLocaleString()}</div>
              <div style="font-size:0.75rem;color:#666;text-transform:uppercase;">Balance</div>
            </div>
            <div style="text-align:center;padding:1rem;background:rgba(255,255,255,0.02);border-radius:8px;">
              <div style="font-size:1.75rem;font-weight:700;color:#7b2dff;">\${lifetimePurchased.toLocaleString()}</div>
              <div style="font-size:0.75rem;color:#666;text-transform:uppercase;">Purchased</div>
            </div>
            <div style="text-align:center;padding:1rem;background:rgba(255,255,255,0.02);border-radius:8px;">
              <div style="font-size:1.75rem;font-weight:700;color:#ff2d7b;">\${lifetimeUsed.toLocaleString()}</div>
              <div style="font-size:0.75rem;color:#666;text-transform:uppercase;">Used</div>
            </div>
          </div>

          \${subscriptionSection}

          \${hasAnySubscription ? \`
          <div style="background:rgba(255,255,255,0.02);border:1px solid rgba(255,255,255,0.08);border-radius:12px;padding:1.5rem;">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem;">
              <div>
                <div style="font-weight:600;">Auto-Refill</div>
                <div style="font-size:0.85rem;color:#666;">Automatically add credits when balance is low</div>
              </div>
              <label style="display:flex;align-items:center;cursor:pointer;">
                <input type="checkbox" id="auto-refill-toggle" \${autoRefill.enabled ? 'checked' : ''} onchange="toggleAutoRefill(this.checked)" style="width:40px;height:22px;appearance:none;background:#333;border-radius:11px;position:relative;cursor:pointer;transition:0.2s;">
              </label>
            </div>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:1rem;font-size:0.9rem;">
              <div>
                <div style="color:#666;font-size:0.8rem;margin-bottom:0.25rem;">When balance drops below</div>
                <div style="font-weight:600;">\${autoRefill.threshold.toLocaleString()} credits</div>
              </div>
              <div>
                <div style="color:#666;font-size:0.8rem;margin-bottom:0.25rem;">Auto-purchase</div>
                <div style="font-weight:600;">\${autoRefill.refill_amount.toLocaleString()} credits for $\${(autoRefill.price_cents / 100).toFixed(0)}</div>
              </div>
            </div>
            <div id="auto-refill-message" style="margin-top:0.5rem;"></div>
          </div>
          \` : ''}

          <div class="modal-actions" style="margin-top:1.5rem;">
            <button class="btn btn-secondary" onclick="viewTransactions()">View Transactions</button>
            <button class="btn btn-secondary" onclick="this.closest('.modal-overlay').remove()">Close</button>
          </div>
        </div>
      \`;

      // Style the toggle and plan cards
      const style = document.createElement('style');
      style.textContent = \`
        #auto-refill-toggle:checked { background: #00d4ff; }
        #auto-refill-toggle::after {
          content: '';
          position: absolute;
          top: 2px;
          left: 2px;
          width: 18px;
          height: 18px;
          background: #fff;
          border-radius: 50%;
          transition: 0.2s;
        }
        #auto-refill-toggle:checked::after { left: 20px; }
        .plan-card:hover { border-color: #00d4ff !important; background: rgba(0,212,255,0.05); }
      \`;
      modal.appendChild(style);

      document.getElementById('modal-container').appendChild(modal);
    }

    async function openPortal() {
      try {
        const res = await fetch(API + '/billing/portal', {
          method: 'POST',
          credentials: 'include'
        });
        const data = await res.json();

        if (data.portal_url) {
          window.location.href = data.portal_url;
        } else {
          alert(data.error || 'Failed to open billing portal');
        }
      } catch (err) {
        alert('Error: ' + err.message);
      }
    }

    async function toggleAutoRefill(enabled) {
      const msgEl = document.getElementById('auto-refill-message');
      try {
        const res = await fetch(API + '/billing/auto-refill', {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({ enabled })
        });
        const data = await res.json();

        if (data.error) {
          msgEl.innerHTML = '<div class="message error">' + data.error + '</div>';
          document.getElementById('auto-refill-toggle').checked = !enabled;
        } else {
          msgEl.innerHTML = '<div class="message success">Auto-refill ' + (enabled ? 'enabled' : 'disabled') + '</div>';
          window.currentBilling.auto_refill = data;
          setTimeout(() => { msgEl.innerHTML = ''; }, 2000);
        }
      } catch (err) {
        msgEl.innerHTML = '<div class="message error">Error: ' + err.message + '</div>';
        document.getElementById('auto-refill-toggle').checked = !enabled;
      }
    }

    async function viewTransactions() {
      const modal = document.createElement('div');
      modal.className = 'modal-overlay';
      modal.onclick = (e) => { if (e.target === modal) modal.remove(); };
      modal.innerHTML = \`
        <div class="modal" style="max-width:600px;">
          <h2>Credit Transactions</h2>
          <div id="transactions-content"><p style="color:#888;">Loading...</p></div>
          <div class="modal-actions">
            <button class="btn btn-secondary" onclick="this.closest('.modal-overlay').remove()">Close</button>
          </div>
        </div>
      \`;
      document.getElementById('modal-container').appendChild(modal);

      try {
        const res = await fetch(API + '/billing/transactions', { credentials: 'include' });
        const data = await res.json();
        const container = document.getElementById('transactions-content');

        if (!data.transactions || data.transactions.length === 0) {
          container.innerHTML = '<p style="color:#666;text-align:center;padding:2rem;">No transactions yet</p>';
          return;
        }

        container.innerHTML = \`
          <table style="width:100%;border-collapse:collapse;font-size:0.9rem;">
            <thead>
              <tr style="border-bottom:1px solid #333;">
                <th style="text-align:left;padding:0.75rem;color:#666;">Date</th>
                <th style="text-align:left;padding:0.75rem;color:#666;">Description</th>
                <th style="text-align:right;padding:0.75rem;color:#666;">Credits</th>
              </tr>
            </thead>
            <tbody>
              \${data.transactions.map(tx => \`
                <tr style="border-bottom:1px solid #222;">
                  <td style="padding:0.75rem;color:#888;">\${new Date(tx.created_at).toLocaleDateString()}</td>
                  <td style="padding:0.75rem;">\${tx.description || tx.type}</td>
                  <td style="padding:0.75rem;text-align:right;color:#27ca40;font-weight:600;">+\${tx.amount.toLocaleString()}</td>
                </tr>
              \`).join('')}
            </tbody>
          </table>
        \`;
      } catch (err) {
        document.getElementById('transactions-content').innerHTML = '<div class="message error">Error: ' + err.message + '</div>';
      }
    }

    async function logout() {
      await fetch(API + '/owner/logout', { method: 'POST', credentials: 'include' });
      location.reload();
    }

    init();
  </script>
</body>
</html>`;
}

function statsPage(subdomain) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Stats - ${subdomain} - itsalive.co</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: system-ui, -apple-system, sans-serif;
      background: #0a0a0b;
      color: #fff;
      min-height: 100vh;
    }
    .header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 1.5rem 2rem;
      border-bottom: 1px solid #1a1a1a;
      background: #0d0d0d;
    }
    .header-left {
      display: flex;
      align-items: center;
      gap: 1rem;
    }
    .logo {
      font-size: 1.5rem;
      font-weight: 800;
      background: linear-gradient(135deg, #00d4ff 0%, #7b2dff 50%, #ff2d7b 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      text-decoration: none;
    }
    .back-link {
      color: #666;
      text-decoration: none;
      font-size: 0.9rem;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }
    .back-link:hover { color: #fff; }
    .app-badge {
      background: rgba(255,255,255,0.1);
      padding: 0.4rem 0.8rem;
      border-radius: 20px;
      font-size: 0.85rem;
      color: #00d4ff;
    }
    .container {
      max-width: 1200px;
      margin: 0 auto;
      padding: 2rem;
    }
    .page-header {
      margin-bottom: 2rem;
    }
    .page-title {
      font-size: 2rem;
      font-weight: 700;
      margin-bottom: 0.5rem;
      display: flex;
      align-items: center;
      gap: 1rem;
    }
    .page-subtitle {
      color: #666;
      font-size: 0.95rem;
    }
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 1.25rem;
      margin-bottom: 2.5rem;
    }
    .stat-card {
      background: linear-gradient(135deg, rgba(0,212,255,0.05) 0%, rgba(123,45,255,0.05) 100%);
      border: 1px solid rgba(255,255,255,0.08);
      border-radius: 16px;
      padding: 1.5rem;
      position: relative;
      overflow: hidden;
    }
    .stat-card::before {
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      height: 3px;
      background: linear-gradient(90deg, #00d4ff, #7b2dff);
      opacity: 0.5;
    }
    .stat-card.highlight::before {
      opacity: 1;
    }
    .stat-value {
      font-size: 2.5rem;
      font-weight: 800;
      background: linear-gradient(135deg, #00d4ff, #7b2dff);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      line-height: 1.1;
    }
    .stat-label {
      font-size: 0.8rem;
      color: #888;
      margin-top: 0.5rem;
      text-transform: uppercase;
      letter-spacing: 1px;
    }
    .stat-change {
      font-size: 0.75rem;
      margin-top: 0.5rem;
      padding: 0.2rem 0.5rem;
      border-radius: 10px;
      display: inline-block;
    }
    .stat-change.up { background: rgba(39,202,64,0.15); color: #27ca40; }
    .stat-change.down { background: rgba(255,68,68,0.15); color: #ff4444; }
    .section {
      margin-bottom: 3rem;
    }
    .section-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 1.5rem;
    }
    .section-title {
      font-size: 1.25rem;
      font-weight: 600;
      color: #fff;
    }
    .period-tabs {
      display: flex;
      gap: 0.5rem;
      background: rgba(255,255,255,0.03);
      padding: 0.25rem;
      border-radius: 8px;
    }
    .period-tab {
      padding: 0.5rem 1rem;
      background: transparent;
      border: none;
      color: #666;
      font-size: 0.85rem;
      cursor: pointer;
      border-radius: 6px;
      transition: all 0.2s;
    }
    .period-tab:hover { color: #fff; }
    .period-tab.active {
      background: #fff;
      color: #000;
    }
    .chart-card {
      background: rgba(255,255,255,0.02);
      border: 1px solid rgba(255,255,255,0.08);
      border-radius: 16px;
      padding: 1.5rem;
    }
    .chart-area {
      height: 280px;
      display: flex;
      align-items: flex-end;
      justify-content: space-between;
      gap: 8px;
      padding: 1rem 0;
      border-bottom: 1px solid rgba(255,255,255,0.1);
    }
    .chart-column {
      flex: 1;
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 8px;
      max-width: 60px;
    }
    .chart-bars-group {
      display: flex;
      gap: 4px;
      align-items: flex-end;
      height: 200px;
    }
    .chart-bar {
      width: 20px;
      border-radius: 4px 4px 0 0;
      min-height: 4px;
      transition: all 0.3s ease;
      cursor: pointer;
      position: relative;
    }
    .chart-bar.views {
      background: linear-gradient(180deg, #00d4ff, #0099cc);
    }
    .chart-bar.visitors {
      background: linear-gradient(180deg, #ff2d7b, #cc2266);
    }
    .chart-bar:hover {
      filter: brightness(1.2);
    }
    .chart-bar:hover::after {
      content: attr(data-value);
      position: absolute;
      bottom: calc(100% + 8px);
      left: 50%;
      transform: translateX(-50%);
      background: #fff;
      color: #000;
      padding: 4px 8px;
      border-radius: 4px;
      font-size: 0.75rem;
      white-space: nowrap;
      z-index: 10;
    }
    .chart-label {
      font-size: 0.7rem;
      color: #555;
      text-align: center;
    }
    .chart-legend {
      display: flex;
      justify-content: center;
      gap: 2rem;
      margin-top: 1.5rem;
    }
    .legend-item {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      font-size: 0.85rem;
      color: #888;
    }
    .legend-dot {
      width: 12px;
      height: 12px;
      border-radius: 3px;
    }
    .legend-dot.views { background: linear-gradient(180deg, #00d4ff, #0099cc); }
    .legend-dot.visitors { background: linear-gradient(180deg, #ff2d7b, #cc2266); }
    .ai-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 1rem;
    }
    .ai-card {
      background: rgba(255,255,255,0.02);
      border: 1px solid rgba(255,255,255,0.08);
      border-radius: 12px;
      padding: 1.25rem;
    }
    .ai-card-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 1rem;
    }
    .ai-provider {
      font-size: 0.9rem;
      font-weight: 600;
    }
    .ai-tier {
      font-size: 0.75rem;
      padding: 0.25rem 0.5rem;
      border-radius: 4px;
      background: rgba(123,45,255,0.2);
      color: #a855f7;
    }
    .ai-stats {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 1rem;
      text-align: center;
    }
    .ai-stat-value {
      font-size: 1.25rem;
      font-weight: 700;
      color: #fff;
    }
    .ai-stat-label {
      font-size: 0.7rem;
      color: #666;
      text-transform: uppercase;
    }
    .empty-state {
      text-align: center;
      padding: 3rem 2rem;
      color: #666;
    }
    .empty-state h3 {
      color: #888;
      margin-bottom: 0.5rem;
    }
    .loading {
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 200px;
      color: #666;
    }
    .spinner {
      width: 40px;
      height: 40px;
      border: 3px solid rgba(255,255,255,0.1);
      border-top-color: #00d4ff;
      border-radius: 50%;
      animation: spin 1s linear infinite;
    }
    @keyframes spin {
      to { transform: rotate(360deg); }
    }
    .error-message {
      background: rgba(255,68,68,0.1);
      border: 1px solid rgba(255,68,68,0.3);
      color: #ff4444;
      padding: 1rem;
      border-radius: 8px;
      text-align: center;
    }
    .visit-link {
      color: #00d4ff;
      text-decoration: none;
    }
    .visit-link:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <header class="header">
    <div class="header-left">
      <a href="/" class="logo">It's Alive!</a>
      <a href="/" class="back-link">← Back to Dashboard</a>
    </div>
  </header>

  <div class="container">
    <div class="page-header">
      <h1 class="page-title">
        ${subdomain}
        <span class="app-badge">${subdomain}.itsalive.co</span>
      </h1>
      <p class="page-subtitle">Analytics and usage statistics • <a href="https://${subdomain}.itsalive.co" target="_blank" class="visit-link">Visit app →</a></p>
    </div>

    <div id="loading" class="loading">
      <div class="spinner"></div>
    </div>

    <div id="content" style="display:none;">
      <div id="summary-stats" class="stats-grid"></div>

      <div class="section">
        <div class="section-header">
          <h2 class="section-title">Traffic <span style="font-size:0.75rem;font-weight:400;color:#666;margin-left:0.5rem;">delayed ~5 min</span></h2>
          <div class="period-tabs">
            <button class="period-tab" data-period="hour">Hourly</button>
            <button class="period-tab active" data-period="day">Daily</button>
            <button class="period-tab" data-period="week">Weekly</button>
            <button class="period-tab" data-period="month">Monthly</button>
          </div>
        </div>
        <div class="chart-card">
          <div id="traffic-chart" class="chart-area"></div>
          <div class="chart-legend">
            <div class="legend-item"><div class="legend-dot views"></div> Page Views</div>
            <div class="legend-item"><div class="legend-dot visitors"></div> Unique Visitors</div>
          </div>
        </div>
      </div>

      <div class="section">
        <div class="section-header">
          <h2 class="section-title">AI Usage This Month</h2>
        </div>
        <div id="ai-usage" class="ai-grid"></div>
      </div>
    </div>

    <div id="error" style="display:none;"></div>
  </div>

  <script>
    const API = 'https://api.itsalive.co';
    const subdomain = '${subdomain}';
    let currentPeriod = 'day';

    async function init() {
      try {
        const [summaryRes, trafficRes, aiRes] = await Promise.all([
          fetch(API + '/stats/summary?subdomain=' + subdomain, { credentials: 'include' }),
          fetch(API + '/stats/traffic?subdomain=' + subdomain + '&period=' + currentPeriod, { credentials: 'include' }),
          fetch(API + '/stats/ai?subdomain=' + subdomain + '&period=month', { credentials: 'include' })
        ]);

        const summary = await summaryRes.json();
        const traffic = await trafficRes.json();
        const ai = await aiRes.json();

        document.getElementById('loading').style.display = 'none';

        if (summary.error) {
          showError(summary.error);
          return;
        }

        document.getElementById('content').style.display = 'block';
        renderSummary(summary);
        renderTrafficChart(traffic);
        renderAIUsage(ai);
      } catch (e) {
        showError('Failed to load stats: ' + e.message);
      }
    }

    function showError(message) {
      document.getElementById('loading').style.display = 'none';
      document.getElementById('error').style.display = 'block';
      document.getElementById('error').innerHTML = '<div class="error-message">' + message + '</div>';
    }

    function fmt(n) {
      if (n >= 1000000) return (n/1000000).toFixed(1) + 'M';
      if (n >= 1000) return (n/1000).toFixed(1) + 'K';
      return (n || 0).toString();
    }

    function renderSummary(data) {
      const container = document.getElementById('summary-stats');
      container.innerHTML = \`
        <div class="stat-card highlight">
          <div class="stat-value">\${fmt(data.users?.dau)}</div>
          <div class="stat-label">Daily Active Users</div>
        </div>
        <div class="stat-card">
          <div class="stat-value">\${fmt(data.users?.wau)}</div>
          <div class="stat-label">Weekly Active Users</div>
        </div>
        <div class="stat-card">
          <div class="stat-value">\${fmt(data.users?.mau)}</div>
          <div class="stat-label">Monthly Active Users</div>
        </div>
        <div class="stat-card">
          <div class="stat-value">\${fmt(data.users?.total)}</div>
          <div class="stat-label">Total Users</div>
        </div>
        <div class="stat-card">
          <div class="stat-value">\${fmt(data.users?.signups_this_week)}</div>
          <div class="stat-label">Signups This Week</div>
        </div>
        <div class="stat-card">
          <div class="stat-value">\${fmt(data.content?.documents)}</div>
          <div class="stat-label">Documents</div>
        </div>
        <div class="stat-card">
          <div class="stat-value">\${fmt(data.traffic?.page_views?.today)}</div>
          <div class="stat-label">Views Today</div>
        </div>
        <div class="stat-card">
          <div class="stat-value">\${fmt(data.traffic?.unique_visitors?.today)}</div>
          <div class="stat-label">Visitors Today</div>
        </div>
      \`;
    }

    function renderTrafficChart(data) {
      const container = document.getElementById('traffic-chart');
      const trafficData = data.data || [];

      if (trafficData.length === 0) {
        container.innerHTML = '<div class="empty-state"><h3>No traffic data yet</h3><p>Traffic will appear here once visitors start using your app.</p></div>';
        return;
      }

      const maxViews = Math.max(...trafficData.map(d => d.page_views || 0), 1);
      const maxVisitors = Math.max(...trafficData.map(d => d.unique_visitors || 0), 1);
      const chartMax = Math.max(maxViews, maxVisitors);
      const displayData = trafficData.slice(-14);

      container.innerHTML = displayData.map(d => {
        const viewsHeight = chartMax > 0 ? ((d.page_views || 0) / chartMax) * 180 : 0;
        const visitorsHeight = chartMax > 0 ? ((d.unique_visitors || 0) / chartMax) * 180 : 0;
        const label = formatLabel(d.period);
        return \`
          <div class="chart-column">
            <div class="chart-bars-group">
              <div class="chart-bar views" style="height:\${viewsHeight}px" data-value="\${d.page_views || 0} views"></div>
              <div class="chart-bar visitors" style="height:\${visitorsHeight}px" data-value="\${d.unique_visitors || 0} visitors"></div>
            </div>
            <div class="chart-label">\${label}</div>
          </div>
        \`;
      }).join('');
    }

    function formatLabel(period) {
      if (!period) return '';
      if (currentPeriod === 'hour') {
        const match = period.match(/(\\d{2})$/);
        return match ? match[1] + ':00' : period;
      }
      if (currentPeriod === 'day') {
        const d = new Date(period);
        return (d.getMonth()+1) + '/' + d.getDate();
      }
      if (currentPeriod === 'week') {
        return 'W' + (period.split('-W')[1] || period);
      }
      if (currentPeriod === 'month') {
        const parts = period.split('-');
        return parts.length > 1 ? parts[1] + '/' + parts[0].slice(2) : period;
      }
      return period;
    }

    function renderAIUsage(data) {
      const container = document.getElementById('ai-usage');
      const aiData = data.data || [];

      if (aiData.length === 0) {
        container.innerHTML = '<div class="empty-state" style="grid-column:1/-1;"><h3>No AI usage this month</h3><p>AI credits and usage will appear here when your app uses the AI features.</p></div>';
        return;
      }

      container.innerHTML = aiData.map(d => \`
        <div class="ai-card">
          <div class="ai-card-header">
            <span class="ai-provider">\${d.provider}</span>
            <span class="ai-tier">\${d.tier}</span>
          </div>
          <div class="ai-stats">
            <div>
              <div class="ai-stat-value">\${fmt(d.requests)}</div>
              <div class="ai-stat-label">Requests</div>
            </div>
            <div>
              <div class="ai-stat-value">\${fmt(d.total_tokens)}</div>
              <div class="ai-stat-label">Tokens</div>
            </div>
            <div>
              <div class="ai-stat-value">\${fmt(d.total_credits)}</div>
              <div class="ai-stat-label">Credits</div>
            </div>
          </div>
        </div>
      \`).join('');
    }

    // Period tab switching
    document.querySelectorAll('.period-tab').forEach(tab => {
      tab.addEventListener('click', async () => {
        document.querySelectorAll('.period-tab').forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        currentPeriod = tab.dataset.period;

        document.getElementById('traffic-chart').innerHTML = '<div class="loading"><div class="spinner"></div></div>';

        const trafficRes = await fetch(API + '/stats/traffic?subdomain=' + subdomain + '&period=' + currentPeriod, { credentials: 'include' });
        const traffic = await trafficRes.json();
        renderTrafficChart(traffic);
      });
    });

    init();
  </script>
</body>
</html>`;
}

function settingsPage(subdomain) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Settings - ${subdomain}.itsalive.co</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: system-ui, -apple-system, sans-serif;
      background: #0a0a0b;
      color: #fff;
      min-height: 100vh;
      padding: 2rem;
    }
    .container {
      max-width: 600px;
      margin: 0 auto;
    }
    .header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 2rem;
      padding-bottom: 1.5rem;
      border-bottom: 1px solid #222;
    }
    .logo {
      font-size: 1.5rem;
      font-weight: 800;
      background: linear-gradient(135deg, #00d4ff 0%, #7b2dff 50%, #ff2d7b 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }
    .back-link {
      color: #666;
      text-decoration: none;
      font-size: 0.9rem;
    }
    .back-link:hover { color: #00d4ff; }
    h1 {
      font-size: 1.75rem;
      margin-bottom: 0.5rem;
    }
    .subdomain {
      color: #666;
      font-family: 'SF Mono', Monaco, monospace;
      margin-bottom: 2rem;
    }
    .card {
      background: rgba(255,255,255,0.02);
      border: 1px solid rgba(255,255,255,0.08);
      border-radius: 12px;
      padding: 1.5rem;
      margin-bottom: 1.5rem;
    }
    .card h2 {
      font-size: 1.1rem;
      margin-bottom: 1rem;
      color: #fff;
    }
    .form-group {
      margin-bottom: 1rem;
    }
    label {
      display: block;
      margin-bottom: 0.5rem;
      color: #888;
      font-size: 0.9rem;
    }
    input[type="text"], input[type="email"] {
      width: 100%;
      padding: 0.75rem 1rem;
      background: #111;
      border: 1px solid #333;
      border-radius: 8px;
      color: #fff;
      font-size: 1rem;
    }
    input:focus {
      outline: none;
      border-color: #00d4ff;
    }
    input:disabled {
      opacity: 0.5;
      cursor: not-allowed;
    }
    .btn {
      display: inline-block;
      padding: 0.75rem 1.5rem;
      background: #fff;
      color: #000;
      border: none;
      border-radius: 8px;
      font-size: 1rem;
      font-weight: 600;
      cursor: pointer;
      transition: transform 0.2s;
    }
    .btn:hover { transform: translateY(-1px); }
    .btn:disabled {
      opacity: 0.5;
      cursor: not-allowed;
      transform: none;
    }
    .btn-secondary {
      background: transparent;
      border: 1px solid #333;
      color: #fff;
    }
    .btn-danger {
      background: #ff4444;
      color: #fff;
    }
    .dns-instructions {
      background: #111;
      border-radius: 8px;
      padding: 1rem;
      margin-top: 1rem;
      font-family: 'SF Mono', Monaco, monospace;
      font-size: 0.85rem;
    }
    .dns-row {
      display: grid;
      grid-template-columns: 80px 1fr 1fr;
      gap: 1rem;
      padding: 0.5rem 0;
      border-bottom: 1px solid #222;
    }
    .dns-row:last-child { border-bottom: none; }
    .dns-label { color: #666; }
    .dns-value { color: #00d4ff; }
    .status {
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      padding: 0.5rem 1rem;
      border-radius: 20px;
      font-size: 0.85rem;
    }
    .status.success {
      background: rgba(39, 202, 64, 0.1);
      color: #27ca40;
    }
    .status.pending {
      background: rgba(255, 189, 46, 0.1);
      color: #ffbd2e;
    }
    .status.error {
      background: rgba(255, 68, 68, 0.1);
      color: #ff4444;
    }
    .message {
      padding: 1rem;
      border-radius: 8px;
      margin-bottom: 1rem;
    }
    .message.success {
      background: rgba(39, 202, 64, 0.1);
      border: 1px solid rgba(39, 202, 64, 0.3);
      color: #27ca40;
    }
    .message.error {
      background: rgba(255, 68, 68, 0.1);
      border: 1px solid rgba(255, 68, 68, 0.3);
      color: #ff4444;
    }
    .login-prompt {
      text-align: center;
      padding: 3rem;
    }
    .login-prompt p {
      color: #888;
      margin-bottom: 1.5rem;
    }
    #loading {
      text-align: center;
      padding: 3rem;
      color: #666;
    }
    .hidden { display: none; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <span class="logo">It's Alive!</span>
      <a href="/" class="back-link">← Back to app</a>
    </div>

    <div id="loading">Loading...</div>

    <div id="login-prompt" class="card hidden">
      <div class="login-prompt">
        <h2>Login Required</h2>
        <p>You need to be logged in as the app owner to access settings.</p>
        <form id="login-form">
          <div class="form-group">
            <input type="email" id="login-email" placeholder="Enter your email" required>
          </div>
          <button type="submit" class="btn">Send Login Link</button>
        </form>
        <p id="login-message" style="margin-top: 1rem; color: #888;"></p>
      </div>
    </div>

    <div id="not-owner" class="card hidden">
      <div class="login-prompt">
        <h2>Access Denied</h2>
        <p>Only the app owner can access these settings.</p>
        <a href="/" class="btn btn-secondary">Back to App</a>
      </div>
    </div>

    <div id="settings" class="hidden">
      <h1>App Settings</h1>
      <p class="subdomain">${subdomain}.itsalive.co</p>

      <div id="message-area"></div>

      <div class="card">
        <h2>Custom Domain</h2>
        <p style="color: #888; font-size: 0.9rem; margin-bottom: 1rem;">
          Use your own domain instead of ${subdomain}.itsalive.co
        </p>

        <div id="current-domain"></div>

        <form id="domain-form">
          <div class="form-group">
            <label for="custom-domain">Domain</label>
            <input type="text" id="custom-domain" placeholder="example.com">
          </div>
          <button type="submit" class="btn" id="save-domain-btn">Save Domain</button>
          <button type="button" class="btn btn-secondary" id="remove-domain-btn" style="margin-left: 0.5rem;">Remove</button>
        </form>

        <div class="dns-instructions" id="dns-instructions" style="display: none;">
          <p style="color: #888; margin-bottom: 0.75rem;">Add this DNS record to your domain:</p>
          <div class="dns-row">
            <span class="dns-label">Type</span>
            <span class="dns-value">CNAME</span>
            <span></span>
          </div>
          <div class="dns-row">
            <span class="dns-label">Name</span>
            <span class="dns-value" id="dns-name">@</span>
            <span style="color: #666; font-size: 0.8rem;">(or www)</span>
          </div>
          <div class="dns-row">
            <span class="dns-label">Target</span>
            <span class="dns-value">${subdomain}.itsalive.co</span>
            <span></span>
          </div>
        </div>

        <div id="domain-status" style="margin-top: 1rem;"></div>
      </div>

      <div class="card">
        <h2>Email Branding</h2>
        <p style="color: #888; font-size: 0.9rem; margin-bottom: 1rem;">
          Customize how login emails appear to your users.
        </p>
        <form id="branding-form">
          <div class="form-group">
            <label for="app-name">App Name</label>
            <input type="text" id="app-name" placeholder="My Awesome App">
          </div>
          <div class="form-group">
            <label for="tagline">Tagline (optional)</label>
            <input type="text" id="tagline" placeholder="Your productivity companion">
          </div>
          <div class="form-group" style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem;">
            <div>
              <label for="primary-color">Primary Color</label>
              <input type="text" id="primary-color" placeholder="#00d4ff">
            </div>
            <div>
              <label for="button-color">Button Color</label>
              <input type="text" id="button-color" placeholder="#ffffff">
            </div>
          </div>
          <button type="submit" class="btn">Save Branding</button>
        </form>
      </div>
    </div>
  </div>

  <script>
    const API = 'https://api.itsalive.co';
    const subdomain = '${subdomain}';

    async function init() {
      try {
        const res = await fetch(API + '/app/settings', { credentials: 'include' });
        const data = await res.json();

        document.getElementById('loading').classList.add('hidden');

        if (res.status === 401) {
          document.getElementById('login-prompt').classList.remove('hidden');
          return;
        }

        if (!data.is_owner) {
          document.getElementById('not-owner').classList.remove('hidden');
          return;
        }

        // Show settings
        document.getElementById('settings').classList.remove('hidden');

        // Populate current values
        if (data.custom_domain) {
          document.getElementById('custom-domain').value = data.custom_domain;
          document.getElementById('dns-instructions').style.display = 'block';
          document.getElementById('current-domain').innerHTML =
            '<p style="margin-bottom: 1rem;"><span class="status success">● Active</span> <strong>' + data.custom_domain + '</strong></p>';
        }

        if (data.branding) {
          document.getElementById('app-name').value = data.branding.appName || '';
          document.getElementById('tagline').value = data.branding.tagline || '';
          document.getElementById('primary-color').value = data.branding.primaryColor || '';
          document.getElementById('button-color').value = data.branding.buttonColor || '';
        }

      } catch (e) {
        document.getElementById('loading').textContent = 'Error loading settings: ' + e.message;
      }
    }

    // Login form
    document.getElementById('login-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const email = document.getElementById('login-email').value;
      const msgEl = document.getElementById('login-message');

      try {
        const res = await fetch(API + '/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({ email })
        });
        const data = await res.json();
        if (data.success) {
          msgEl.style.color = '#27ca40';
          msgEl.textContent = 'Check your email for a login link!';
        } else {
          msgEl.style.color = '#ff4444';
          msgEl.textContent = data.error || 'Failed to send login link';
        }
      } catch (e) {
        msgEl.style.color = '#ff4444';
        msgEl.textContent = 'Error: ' + e.message;
      }
    });

    // Domain form
    document.getElementById('domain-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const domain = document.getElementById('custom-domain').value.trim();
      const msgArea = document.getElementById('message-area');

      try {
        const res = await fetch(API + '/app/settings', {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({ custom_domain: domain })
        });
        const data = await res.json();

        if (data.success) {
          msgArea.innerHTML = '<div class="message success">Custom domain saved! Add the DNS record below.</div>';
          document.getElementById('dns-instructions').style.display = 'block';
          document.getElementById('current-domain').innerHTML =
            '<p style="margin-bottom: 1rem;"><span class="status pending">● Pending DNS</span> <strong>' + domain + '</strong></p>';

          // Verify domain
          setTimeout(verifyDomain, 2000);
        } else {
          msgArea.innerHTML = '<div class="message error">' + (data.error || 'Failed to save') + '</div>';
        }
      } catch (e) {
        msgArea.innerHTML = '<div class="message error">Error: ' + e.message + '</div>';
      }
    });

    // Remove domain
    document.getElementById('remove-domain-btn').addEventListener('click', async () => {
      if (!confirm('Remove custom domain?')) return;

      const msgArea = document.getElementById('message-area');
      try {
        const res = await fetch(API + '/app/settings', {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({ custom_domain: '' })
        });
        const data = await res.json();

        if (data.success) {
          msgArea.innerHTML = '<div class="message success">Custom domain removed.</div>';
          document.getElementById('custom-domain').value = '';
          document.getElementById('dns-instructions').style.display = 'none';
          document.getElementById('current-domain').innerHTML = '';
          document.getElementById('domain-status').innerHTML = '';
        } else {
          msgArea.innerHTML = '<div class="message error">' + (data.error || 'Failed to remove') + '</div>';
        }
      } catch (e) {
        msgArea.innerHTML = '<div class="message error">Error: ' + e.message + '</div>';
      }
    });

    // Branding form
    document.getElementById('branding-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const msgArea = document.getElementById('message-area');

      try {
        const res = await fetch(API + '/settings/branding', {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({
            app_name: document.getElementById('app-name').value,
            tagline: document.getElementById('tagline').value,
            primary_color: document.getElementById('primary-color').value,
            button_color: document.getElementById('button-color').value
          })
        });
        const data = await res.json();

        if (data.success) {
          msgArea.innerHTML = '<div class="message success">Branding saved!</div>';
        } else {
          msgArea.innerHTML = '<div class="message error">' + (data.error || 'Failed to save') + '</div>';
        }
      } catch (e) {
        msgArea.innerHTML = '<div class="message error">Error: ' + e.message + '</div>';
      }
    });

    async function verifyDomain() {
      const statusEl = document.getElementById('domain-status');
      try {
        const res = await fetch(API + '/app/verify-domain', { credentials: 'include' });
        const data = await res.json();

        if (data.configured) {
          statusEl.innerHTML = '<span class="status success">● Domain verified and active</span>';
          document.getElementById('current-domain').innerHTML =
            '<p style="margin-bottom: 1rem;"><span class="status success">● Active</span> <strong>' + data.domain + '</strong></p>';
        } else {
          statusEl.innerHTML = '<span class="status pending">● Waiting for DNS propagation...</span>';
        }
      } catch (e) {
        statusEl.innerHTML = '<span class="status error">● Could not verify domain</span>';
      }
    }

    init();
  </script>
</body>
</html>`;
}

function customDomainsPage() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Custom Domain Setup - itsalive.co</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: system-ui, -apple-system, sans-serif;
      background: #0a0a0b;
      color: #e0e0e0;
      line-height: 1.7;
      min-height: 100vh;
    }
    .header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 1.5rem 2rem;
      border-bottom: 1px solid #1a1a1a;
      background: #0d0d0d;
    }
    .logo {
      font-size: 1.5rem;
      font-weight: 800;
      background: linear-gradient(135deg, #00d4ff 0%, #7b2dff 50%, #ff2d7b 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      text-decoration: none;
    }
    .container {
      max-width: 800px;
      margin: 0 auto;
      padding: 3rem 2rem;
    }
    h1 {
      font-size: 2.5rem;
      margin-bottom: 1rem;
      color: #fff;
    }
    .subtitle {
      font-size: 1.2rem;
      color: #888;
      margin-bottom: 3rem;
    }
    h2 {
      font-size: 1.5rem;
      color: #fff;
      margin: 2.5rem 0 1rem;
      padding-top: 1.5rem;
      border-top: 1px solid #222;
    }
    h2:first-of-type {
      border-top: none;
      padding-top: 0;
    }
    h3 {
      font-size: 1.1rem;
      color: #00d4ff;
      margin: 1.5rem 0 0.75rem;
    }
    p {
      margin-bottom: 1rem;
      color: #b0b0b0;
    }
    code {
      background: #1a1a1a;
      padding: 0.2rem 0.5rem;
      border-radius: 4px;
      font-family: 'SF Mono', Monaco, monospace;
      font-size: 0.9rem;
      color: #00d4ff;
    }
    .dns-example {
      background: #111;
      border: 1px solid #222;
      border-radius: 12px;
      padding: 1.5rem;
      margin: 1rem 0 1.5rem;
      font-family: 'SF Mono', Monaco, monospace;
      font-size: 0.9rem;
    }
    .dns-row {
      display: grid;
      grid-template-columns: 80px 120px 1fr;
      gap: 1rem;
      padding: 0.5rem 0;
      border-bottom: 1px solid #1a1a1a;
    }
    .dns-row:last-child {
      border-bottom: none;
    }
    .dns-header {
      color: #666;
      font-size: 0.8rem;
      text-transform: uppercase;
    }
    .dns-type { color: #ff2d7b; }
    .dns-name { color: #fff; }
    .dns-value { color: #00d4ff; }
    .callout {
      background: rgba(0, 212, 255, 0.1);
      border: 1px solid rgba(0, 212, 255, 0.2);
      border-radius: 12px;
      padding: 1.25rem 1.5rem;
      margin: 1.5rem 0;
    }
    .callout.warning {
      background: rgba(255, 189, 46, 0.1);
      border-color: rgba(255, 189, 46, 0.2);
    }
    .callout.success {
      background: rgba(39, 202, 64, 0.1);
      border-color: rgba(39, 202, 64, 0.2);
    }
    .callout-title {
      font-weight: 600;
      color: #fff;
      margin-bottom: 0.5rem;
    }
    .callout.warning .callout-title { color: #ffbd2e; }
    .callout.success .callout-title { color: #27ca40; }
    ul {
      margin: 1rem 0 1rem 1.5rem;
      color: #b0b0b0;
    }
    li {
      margin-bottom: 0.5rem;
    }
    a {
      color: #00d4ff;
      text-decoration: none;
    }
    a:hover {
      text-decoration: underline;
    }
    .btn {
      display: inline-block;
      padding: 0.75rem 1.5rem;
      background: #fff;
      color: #000;
      border-radius: 8px;
      font-weight: 600;
      text-decoration: none;
      margin-top: 1rem;
    }
    .btn:hover {
      text-decoration: none;
      transform: translateY(-1px);
    }
    .coming-soon {
      display: inline-block;
      background: linear-gradient(135deg, #7b2dff, #ff2d7b);
      padding: 0.25rem 0.75rem;
      border-radius: 20px;
      font-size: 0.75rem;
      font-weight: 600;
      color: #fff;
      margin-left: 0.5rem;
      vertical-align: middle;
    }
  </style>
</head>
<body>
  <header class="header">
    <a href="/" class="logo">It's Alive!</a>
    <a href="/dashboard" style="color: #888; text-decoration: none;">Dashboard</a>
  </header>

  <div class="container">
    <h1>Custom Domain Setup</h1>
    <p class="subtitle">Connect your own domain to your itsalive.co app</p>

    <h2>How It Works</h2>
    <p>Custom domains let you serve your app from your own domain (like <code>app.yourcompany.com</code> or <code>yourproject.com</code>) instead of the default <code>yourapp.itsalive.co</code> subdomain.</p>

    <h2>Setting Up a Subdomain (Recommended)</h2>
    <p>The easiest setup is using a subdomain like <code>app.example.com</code> or <code>www.example.com</code>. Just add a CNAME record pointing to your itsalive subdomain:</p>

    <div class="dns-example">
      <div class="dns-row dns-header">
        <span>Type</span>
        <span>Name</span>
        <span>Value</span>
      </div>
      <div class="dns-row">
        <span class="dns-type">CNAME</span>
        <span class="dns-name">app</span>
        <span class="dns-value">yourapp.itsalive.co</span>
      </div>
    </div>

    <p>Replace <code>app</code> with your desired subdomain and <code>yourapp</code> with your itsalive subdomain.</p>

    <h2>Root Domain Setup (example.com)</h2>

    <div class="callout warning">
      <div class="callout-title">DNS Limitation</div>
      <p style="margin-bottom:0;">Root domains (apex domains) like <code>example.com</code> cannot have standard CNAME records due to DNS specifications. CNAMEs can't coexist with other required records (SOA, NS) at the zone apex.</p>
    </div>

    <p>You have several options for root domains:</p>

    <h3>Option 1: Use CNAME Flattening (Cloudflare, etc.)</h3>
    <p>Some DNS providers offer "CNAME flattening" or similar features that allow CNAME-like behavior on root domains:</p>
    <ul>
      <li><strong>Cloudflare</strong> - Automatic CNAME flattening (free)</li>
      <li><strong>AWS Route 53</strong> - ALIAS records</li>
      <li><strong>DNSimple</strong> - ALIAS records</li>
      <li><strong>DNS Made Easy</strong> - ANAME records</li>
      <li><strong>NS1</strong> - ALIAS records</li>
    </ul>

    <p>If your DNS provider supports this, set up a "flattened CNAME" or ALIAS record:</p>

    <div class="dns-example">
      <div class="dns-row dns-header">
        <span>Type</span>
        <span>Name</span>
        <span>Value</span>
      </div>
      <div class="dns-row">
        <span class="dns-type">CNAME</span>
        <span class="dns-name">@</span>
        <span class="dns-value">yourapp.itsalive.co</span>
      </div>
    </div>

    <h3>Option 2: WWW + Redirect</h3>
    <p>Use <code>www.example.com</code> as your primary domain and redirect the root to it:</p>
    <ol style="margin: 1rem 0 1rem 1.5rem; color: #b0b0b0;">
      <li>Set up a CNAME for <code>www</code> pointing to your itsalive subdomain</li>
      <li>Use your DNS provider's redirect feature (or a service like redirect.pizza) to redirect <code>example.com</code> → <code>www.example.com</code></li>
    </ol>

    <h3>Option 3: Transfer DNS to Cloudflare</h3>
    <p>Cloudflare offers free DNS hosting with automatic CNAME flattening. You can keep your domain registered elsewhere but use Cloudflare's nameservers:</p>
    <ol style="margin: 1rem 0 1rem 1.5rem; color: #b0b0b0;">
      <li>Create a free Cloudflare account</li>
      <li>Add your domain and follow the setup</li>
      <li>Update your domain's nameservers at your registrar</li>
      <li>Add a CNAME record for <code>@</code> (Cloudflare will flatten it automatically)</li>
    </ol>

    <h2>Domain Registration <span class="coming-soon">Coming Soon</span></h2>
    <p>Soon you'll be able to register and manage domains directly through itsalive.co, with automatic DNS configuration. No more manual setup!</p>

    <div class="callout success">
      <div class="callout-title">After DNS Setup</div>
      <p style="margin-bottom:0;">Once your DNS is configured, add your custom domain in the <a href="/dashboard">dashboard</a>. DNS changes can take up to 48 hours to propagate, but usually work within minutes.</p>
    </div>

    <a href="/dashboard" class="btn">Go to Dashboard</a>
  </div>
</body>
</html>`;
}

function landingPage() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>itsalive.co - Go from Vibe to Live in 10 seconds flat</title>
  <meta name="description" content="Everything you need to ship your Claude Code project - auth, database, and hosting in one command.">

  <!-- OpenGraph -->
  <meta property="og:type" content="website">
  <meta property="og:url" content="https://itsalive.co">
  <meta property="og:title" content="It's Alive! - Go from Vibe to Live in 10 seconds flat">
  <meta property="og:description" content="Everything you need to ship your Claude Code project - auth, database, and hosting in one command.">
  <meta property="og:image" content="https://itsalive.co/og-image.png">

  <!-- Twitter -->
  <meta name="twitter:card" content="summary_large_image">
  <meta name="twitter:url" content="https://itsalive.co">
  <meta name="twitter:title" content="It's Alive! - Go from Vibe to Live in 10 seconds flat">
  <meta name="twitter:description" content="Everything you need to ship your Claude Code project - auth, database, and hosting in one command.">
  <meta name="twitter:image" content="https://itsalive.co/og-image.png">
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: system-ui, -apple-system, sans-serif;
      background: #0a0a0b;
      color: #fff;
      line-height: 1.6;
    }
    .container {
      max-width: 1100px;
      margin: 0 auto;
      padding: 0 2rem;
    }

    /* Hero */
    .hero {
      min-height: 100vh;
      display: grid;
      grid-template-columns: 1fr 1fr;
      align-items: center;
      gap: 4rem;
      padding: 4rem;
      max-width: 1400px;
      margin: 0 auto;
    }
    @media (max-width: 900px) {
      .hero {
        grid-template-columns: 1fr;
        text-align: center;
        padding: 2rem;
        gap: 3rem;
      }
      .hero-content { order: -1; }
    }
    .hero-content {
      display: flex;
      flex-direction: column;
      align-items: flex-start;
    }
    @media (max-width: 900px) {
      .hero-content { align-items: center; }
    }
    h1 {
      font-size: clamp(2.5rem, 6vw, 4.5rem);
      font-weight: 800;
      margin-bottom: 1rem;
      background: linear-gradient(135deg, #00d4ff 0%, #7b2dff 50%, #ff2d7b 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
    }
    .tagline {
      font-size: clamp(1.3rem, 2.5vw, 1.8rem);
      color: #ccc;
      margin-bottom: 1rem;
      max-width: 500px;
      font-weight: 500;
    }
    .description {
      font-size: clamp(1rem, 1.5vw, 1.15rem);
      color: #777;
      margin-bottom: 2rem;
      max-width: 500px;
    }
    .cta {
      display: inline-flex;
      align-items: center;
      gap: 0.75rem;
      padding: 1rem 2rem;
      background: #fff;
      color: #000;
      border-radius: 8px;
      font-family: 'SF Mono', Monaco, monospace;
      font-size: 1.1rem;
      font-weight: 500;
      cursor: pointer;
      border: none;
      transition: transform 0.2s, box-shadow 0.2s;
    }
    .cta:hover {
      transform: translateY(-2px);
      box-shadow: 0 10px 40px rgba(0, 212, 255, 0.3);
    }
    .cta-hint {
      margin-top: 1rem;
      color: #555;
      font-size: 0.9rem;
    }

    /* Terminal */
    .terminal {
      width: 100%;
      max-width: 580px;
      background: #0d0d0d;
      border-radius: 12px;
      overflow: hidden;
      box-shadow: 0 25px 80px rgba(0, 0, 0, 0.5);
      border: 1px solid #222;
    }
    .terminal-header {
      background: #1a1a1a;
      padding: 12px 16px;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .terminal-btn {
      width: 12px;
      height: 12px;
      border-radius: 50%;
    }
    .terminal-btn.red { background: #ff5f56; }
    .terminal-btn.yellow { background: #ffbd2e; }
    .terminal-btn.green { background: #27ca40; }
    .terminal-title {
      flex: 1;
      text-align: center;
      color: #666;
      font-size: 13px;
    }
    .terminal-body {
      padding: 20px;
      font-family: 'SF Mono', Monaco, 'Courier New', monospace;
      font-size: 14px;
      line-height: 1.7;
      min-height: 320px;
    }
    .terminal-line {
      opacity: 0;
      animation: fadeIn 0.3s forwards;
    }
    .terminal-line.prompt { color: #27ca40; }
    .terminal-line.command { color: #fff; }
    .terminal-line.output { color: #888; }
    .terminal-line.success { color: #27ca40; }
    .terminal-line.info { color: #00d4ff; }
    .terminal-line.highlight { color: #7b2dff; }
    .terminal-line .url { color: #00d4ff; text-decoration: underline; }

    @keyframes fadeIn {
      to { opacity: 1; }
    }

    .terminal-line {
      min-height: 1.7em;
      white-space: nowrap;
    }
    .terminal-line.empty {
      min-height: 1.7em;
    }
    .terminal-line.final {
      font-size: 15px;
      margin-top: 8px;
    }
    .terminal-line .typed { color: #fff; }
    .cursor {
      display: inline-block;
      width: 8px;
      height: 15px;
      background: #fff;
      margin-left: 1px;
      animation: blink 0.7s step-end infinite;
      vertical-align: text-bottom;
    }
    @keyframes blink {
      0%, 100% { opacity: 1; }
      50% { opacity: 0; }
    }

    /* Features */
    .features {
      padding: 6rem 2rem;
      background: rgba(255,255,255,0.01);
    }
    .features h2 {
      text-align: center;
      font-size: 2.5rem;
      margin-bottom: 1rem;
    }
    .features .subtitle {
      text-align: center;
      color: #777;
      margin-bottom: 4rem;
      font-size: 1.1rem;
    }
    .features-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 2rem;
      max-width: 1000px;
      margin: 0 auto;
    }
    .feature {
      padding: 2rem;
      background: rgba(255,255,255,0.02);
      border: 1px solid rgba(255,255,255,0.08);
      border-radius: 12px;
      text-align: center;
    }
    .feature-icon {
      font-size: 2.5rem;
      margin-bottom: 1rem;
    }
    .feature h3 {
      font-size: 1.25rem;
      margin-bottom: 0.5rem;
      color: #fff;
    }
    .feature p {
      color: #888;
      font-size: 0.95rem;
      line-height: 1.5;
    }

    /* Pricing */
    .pricing {
      padding: 6rem 2rem;
    }
    .pricing h2 {
      text-align: center;
      font-size: 2.5rem;
      margin-bottom: 1rem;
    }
    .pricing .subtitle {
      text-align: center;
      color: #777;
      margin-bottom: 4rem;
      font-size: 1.1rem;
    }
    .pricing-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 2rem;
      max-width: 1000px;
      margin: 0 auto;
    }
    .plan {
      padding: 2.5rem;
      background: rgba(255,255,255,0.02);
      border: 1px solid rgba(255,255,255,0.08);
      border-radius: 16px;
    }
    .plan.featured {
      border-color: #7b2dff;
      background: linear-gradient(135deg, rgba(123, 45, 255, 0.1) 0%, rgba(0, 212, 255, 0.05) 100%);
    }
    .plan-name {
      font-size: 1.5rem;
      font-weight: 700;
      margin-bottom: 0.5rem;
    }
    .plan-price {
      font-size: 2.5rem;
      font-weight: 800;
      margin-bottom: 0.25rem;
    }
    .plan-price span {
      font-size: 1rem;
      font-weight: 400;
      color: #666;
    }
    .plan-desc {
      color: #777;
      margin-bottom: 2rem;
      font-size: 0.95rem;
    }
    .plan-features {
      list-style: none;
      margin-bottom: 2rem;
    }
    .plan-features li {
      padding: 0.5rem 0;
      color: #aaa;
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }
    .plan-features li::before {
      content: "✓";
      color: #00d4ff;
      font-weight: bold;
    }
    .plan-cta {
      display: block;
      width: 100%;
      padding: 1rem;
      background: #fff;
      color: #000;
      border: none;
      border-radius: 8px;
      font-size: 1rem;
      font-weight: 600;
      cursor: pointer;
      text-align: center;
      text-decoration: none;
      transition: transform 0.2s;
    }
    .plan-cta:hover {
      transform: translateY(-2px);
    }
    .plan-cta.secondary {
      background: transparent;
      border: 1px solid #333;
      color: #fff;
    }

    /* Nav */
    nav {
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      z-index: 100;
      padding: 1rem 2rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      background: rgba(10, 10, 11, 0.9);
      backdrop-filter: blur(10px);
      border-bottom: 1px solid rgba(255,255,255,0.05);
    }
    .nav-logo {
      font-size: 1.25rem;
      font-weight: 700;
      color: #fff;
      text-decoration: none;
      background: linear-gradient(135deg, #00d4ff 0%, #7b2dff 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
    }
    .nav-links {
      display: flex;
      gap: 2rem;
      align-items: center;
    }
    .nav-links a {
      color: #888;
      text-decoration: none;
      font-size: 0.95rem;
      transition: color 0.2s;
    }
    .nav-links a:hover {
      color: #fff;
    }
    .nav-btn {
      padding: 0.5rem 1.25rem;
      background: #fff;
      color: #000;
      border-radius: 6px;
      font-weight: 600;
      font-size: 0.9rem;
      text-decoration: none;
      transition: transform 0.2s;
    }
    .nav-btn:hover {
      transform: translateY(-1px);
      color: #000;
    }
    @media (max-width: 600px) {
      .nav-links { gap: 1rem; }
      .nav-links a:not(.nav-btn) { display: none; }
    }

    /* How it Works */
    .how-it-works {
      padding: 6rem 2rem;
      background: rgba(255,255,255,0.01);
    }
    .how-it-works h2 {
      text-align: center;
      font-size: 2.5rem;
      margin-bottom: 1rem;
    }
    .how-it-works .subtitle {
      text-align: center;
      color: #777;
      margin-bottom: 4rem;
      font-size: 1.1rem;
    }
    .steps {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 2rem;
      max-width: 1000px;
      margin: 0 auto;
    }
    .step {
      text-align: center;
      padding: 2rem;
    }
    .step-number {
      width: 50px;
      height: 50px;
      border-radius: 50%;
      background: linear-gradient(135deg, #00d4ff 0%, #7b2dff 100%);
      color: #fff;
      font-size: 1.5rem;
      font-weight: 700;
      display: flex;
      align-items: center;
      justify-content: center;
      margin: 0 auto 1.5rem;
    }
    .step h3 {
      font-size: 1.25rem;
      margin-bottom: 0.75rem;
    }
    .step p {
      color: #888;
      font-size: 0.95rem;
    }

    /* Guides */
    .guides {
      padding: 6rem 2rem;
    }
    .guides h2 {
      text-align: center;
      font-size: 2.5rem;
      margin-bottom: 1rem;
    }
    .guides .subtitle {
      text-align: center;
      color: #777;
      margin-bottom: 4rem;
      font-size: 1.1rem;
    }
    .guides-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      gap: 1.5rem;
      max-width: 1000px;
      margin: 0 auto;
    }
    .guide-card {
      padding: 2rem;
      background: rgba(255,255,255,0.02);
      border: 1px solid rgba(255,255,255,0.08);
      border-radius: 12px;
      text-decoration: none;
      transition: border-color 0.2s, transform 0.2s;
    }
    .guide-card:hover {
      border-color: #7b2dff;
      transform: translateY(-2px);
    }
    .guide-icon {
      font-size: 2rem;
      margin-bottom: 1rem;
    }
    .guide-card h3 {
      font-size: 1.1rem;
      color: #fff;
      margin-bottom: 0.5rem;
    }
    .guide-card p {
      color: #888;
      font-size: 0.9rem;
    }

    /* Support */
    .support {
      padding: 6rem 2rem;
      background: rgba(255,255,255,0.01);
    }
    .support h2 {
      text-align: center;
      font-size: 2.5rem;
      margin-bottom: 1rem;
    }
    .support .subtitle {
      text-align: center;
      color: #777;
      margin-bottom: 4rem;
      font-size: 1.1rem;
    }
    .support-options {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 2rem;
      max-width: 800px;
      margin: 0 auto;
    }
    .support-card {
      text-align: center;
      padding: 2rem;
      background: rgba(255,255,255,0.02);
      border: 1px solid rgba(255,255,255,0.08);
      border-radius: 12px;
    }
    .support-icon {
      font-size: 2.5rem;
      margin-bottom: 1rem;
    }
    .support-card h3 {
      font-size: 1.1rem;
      margin-bottom: 0.5rem;
    }
    .support-card p {
      color: #888;
      font-size: 0.9rem;
      margin-bottom: 1rem;
    }
    .support-link {
      color: #00d4ff;
      text-decoration: none;
      font-weight: 500;
    }
    .support-link:hover {
      text-decoration: underline;
    }

    /* Footer */
    footer {
      padding: 4rem 2rem;
      text-align: center;
      color: #444;
      border-top: 1px solid #151515;
    }
    footer a {
      color: #666;
      text-decoration: none;
    }
    footer a:hover {
      color: #00d4ff;
    }
  </style>
</head>
<body>
  <nav>
    <a href="/" class="nav-logo">itsalive.co</a>
    <div class="nav-links">
      <a href="#how-it-works">How it Works</a>
      <a href="#guides">Guides</a>
      <a href="#support">Support</a>
      <a href="/dashboard" class="nav-btn">Login</a>
    </div>
  </nav>

  <section class="hero" style="padding-top:5rem;">
    <div class="terminal">
      <div class="terminal-header">
        <div class="terminal-btn red"></div>
        <div class="terminal-btn yellow"></div>
        <div class="terminal-btn green"></div>
        <div class="terminal-title">~/my-awesome-app</div>
      </div>
      <div class="terminal-body" id="terminal"></div>
      <script>
        (function() {
          const lines = [
            { type: 'type', prefix: '$ ', text: 'npx itsalive-co', class: 'command', delay: 500 },
            { type: 'line', text: '', class: 'empty', delay: 200 },
            { type: 'line', text: '🚀 itsalive.co', class: 'output', delay: 400 },
            { type: 'line', text: '', class: 'empty', delay: 200 },
            { type: 'type', prefix: '? <b>Subdomain:</b> ', suffix: '<span style="color:#666">.itsalive.co</span>', text: 'my-awesome-app', class: 'highlight', delay: 300 },
            { type: 'replace', text: '✔ <b>Subdomain:</b> <span class="typed">my-awesome-app</span><span style="color:#666">.itsalive.co</span>', class: 'success', delay: 100 },
            { type: 'type', prefix: '? <b>Email:</b> ', text: 'me@example.com', class: 'highlight', delay: 300 },
            { type: 'replace', text: '✔ <b>Email:</b> <span class="typed">me@example.com</span>', class: 'success', delay: 100 },
            { type: 'line', text: '', class: 'empty', delay: 200 },
            { type: 'line', text: '📧 Check your email to verify...', class: 'info', delay: 400 },
            { type: 'line', text: '', class: 'empty', delay: 200 },
            { type: 'line', text: '⠋ Waiting for you...', class: 'output', delay: 1200 },
            { type: 'replace', text: '✔ Verified!', class: 'success', delay: 300 },
            { type: 'line', text: '⠋ Uploading ░░░░░░░░░░░░░░░░░░░░ 0/12', class: 'output', delay: 200 },
            { type: 'replace', text: '⠋ Uploading █████░░░░░░░░░░░░░░░ 3/12', class: 'output', delay: 150 },
            { type: 'replace', text: '⠋ Uploading ██████████░░░░░░░░░░ 6/12', class: 'output', delay: 150 },
            { type: 'replace', text: '⠋ Uploading ███████████████░░░░░ 9/12', class: 'output', delay: 150 },
            { type: 'replace', text: '✔ Uploaded 12 files', class: 'success', delay: 300 },
            { type: 'line', text: '', class: 'empty', delay: 200 },
            { type: 'line', text: '✨ <span class="url">https://my-awesome-app.itsalive.co</span>', class: 'success final', delay: 0 },
          ];
          const terminal = document.getElementById('terminal');
          let lineIndex = 0;

          function typeLine(el, prefix, text, suffix, callback) {
            el.innerHTML = prefix + '<span class="cursor"></span>' + (suffix || '');
            let i = 0;
            function typeChar() {
              if (i < text.length) {
                el.innerHTML = prefix + '<span class="typed">' + text.substring(0, i + 1) + '</span><span class="cursor"></span>' + (suffix || '');
                i++;
                setTimeout(typeChar, 35 + Math.random() * 35);
              } else {
                el.innerHTML = prefix + '<span class="typed">' + text + '</span>' + (suffix || '');
                callback();
              }
            }
            setTimeout(typeChar, 150);
          }

          let lastEl = null;
          function nextLine() {
            if (lineIndex >= lines.length) return;
            const line = lines[lineIndex];
            lineIndex++;

            let el;
            if (line.type === 'replace' && lastEl) {
              el = lastEl;
              el.className = 'terminal-line ' + line.class;
            } else {
              el = document.createElement('div');
              el.className = 'terminal-line ' + line.class;
              terminal.appendChild(el);
            }
            lastEl = el;

            if (line.type === 'type') {
              typeLine(el, line.prefix, line.text, line.suffix, () => setTimeout(nextLine, line.delay));
            } else {
              el.innerHTML = line.text || '&nbsp;';
              setTimeout(nextLine, line.delay);
            }
          }

          setTimeout(nextLine, 600);
        })();
      </script>
    </div>
    <div class="hero-content">
      <h1>It's Alive!</h1>
      <p class="tagline">Go from Vibe to Live in 10 seconds flat.</p>
      <p class="description">Auth, database, AI, email, analytics - everything just works. No API keys. No configuration. Just deploy.</p>
      <button class="cta" onclick="navigator.clipboard.writeText('npx itsalive-co')">
        <span>npx itsalive-co</span>
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
          <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
        </svg>
      </button>
      <p class="cta-hint">Click to copy</p>
    </div>
  </section>

  <section class="features">
    <h2>Everything You Need, Built In</h2>
    <p class="subtitle">Integrates with Claude Code to give it superpowers. No more plumbing, just vibe and watch the magic. &#129668;</p>
    <div class="features-grid">
      <div class="feature">
        <div class="feature-icon">🔐</div>
        <h3>Auth</h3>
        <p>Magic link login for your users. Zero config.</p>
      </div>
      <div class="feature">
        <div class="feature-icon">💾</div>
        <h3>Database</h3>
        <p>Store and query data with simple API calls.</p>
      </div>
      <div class="feature">
        <div class="feature-icon">🤖</div>
        <h3>AI</h3>
        <p>Claude & GPT built in. Just call the API, we handle billing.</p>
      </div>
      <div class="feature">
        <div class="feature-icon">📧</div>
        <h3>Email</h3>
        <p>Send emails from your app. No Sendgrid account needed.</p>
      </div>
      <div class="feature">
        <div class="feature-icon">📊</div>
        <h3>Analytics</h3>
        <p>See visitors, API usage, and more in your dashboard.</p>
      </div>
      <div class="feature">
        <div class="feature-icon">⚡</div>
        <h3>Edge Hosting</h3>
        <p>Deployed globally on Cloudflare. Fast everywhere.</p>
      </div>
      <div class="feature">
        <div class="feature-icon">⏰</div>
        <h3>Cron Jobs</h3>
        <p>Schedule tasks to run on any interval. Background jobs made easy.</p>
      </div>
      <div class="feature">
        <div class="feature-icon">💳</div>
        <h3>Payments</h3>
        <p>Collect payments and subscriptions. E-commerce ready out of the box.</p>
      </div>
    </div>
  </section>

  <section class="pricing">
    <h2>Simple Pricing</h2>
    <p class="subtitle">Start free, upgrade when you need more</p>
    <div class="pricing-grid">
      <div class="plan">
        <div class="plan-name">Free</div>
        <div class="plan-price">$0</div>
        <p class="plan-desc">Perfect for side projects and experiments</p>
        <ul class="plan-features">
          <li>Up to 10 sites</li>
          <li>Auth, database, hosting</li>
          <li>Basic analytics</li>
          <li>100 emails/day</li>
          <li>AI: pay per use</li>
          <li>10,000 visitors/month</li>
        </ul>
        <button class="plan-cta secondary" onclick="navigator.clipboard.writeText('npx itsalive-co')">Get Started Free</button>
      </div>
      <div class="plan featured">
        <div class="plan-name">Pro</div>
        <div class="plan-price">$50<span>/year per site</span></div>
        <p class="plan-desc">For apps that are ready for the real world</p>
        <ul class="plan-features">
          <li>Custom domain</li>
          <li>Staging environment</li>
          <li>Full analytics dashboard</li>
          <li>1,000 emails/day</li>
          <li>AI: pay per use</li>
          <li>100,000 visitors/month</li>
          <li>Priority support</li>
        </ul>
        <button class="plan-cta">Coming Soon</button>
      </div>
      <div class="plan">
        <div class="plan-name">Studio</div>
        <div class="plan-price">$500<span>/year</span></div>
        <p class="plan-desc">For agencies and studios shipping client work</p>
        <ul class="plan-features">
          <li>Up to 100 sites</li>
          <li>White-label subdomain (*.yourstudio.com)</li>
          <li>Custom domains included</li>
          <li>Staging environments</li>
          <li>10,000 emails/day</li>
          <li>Everything in Pro</li>
        </ul>
        <button class="plan-cta">Coming Soon</button>
      </div>
    </div>
  </section>

  <section class="how-it-works" id="how-it-works">
    <h2>How it Works</h2>
    <p class="subtitle">From idea to live app in three steps</p>
    <div class="steps">
      <div class="step">
        <div class="step-number">1</div>
        <h3>Build with Claude</h3>
        <p>Write code with Claude Code or any AI assistant. HTML, CSS, JavaScript - whatever you need.</p>
      </div>
      <div class="step">
        <div class="step-number">2</div>
        <h3>Run npx itsalive-co</h3>
        <p>Pick a subdomain, verify your email, and your files are uploaded to our global CDN.</p>
      </div>
      <div class="step">
        <div class="step-number">3</div>
        <h3>Add Features</h3>
        <p>Need auth? Database? Just use our API. Everything is built in and ready to go.</p>
      </div>
    </div>
  </section>

  <section class="guides" id="guides">
    <h2>Guides</h2>
    <p class="subtitle">Learn how to build with itsalive.co</p>
    <div class="guides-grid">
      <a href="/docs/getting-started" class="guide-card">
        <div class="guide-icon">🚀</div>
        <h3>Getting Started</h3>
        <p>Deploy your first app in under a minute</p>
      </a>
      <a href="/docs/authentication" class="guide-card">
        <div class="guide-icon">🔐</div>
        <h3>Authentication</h3>
        <p>Add magic link login to your app</p>
      </a>
      <a href="/docs/database" class="guide-card">
        <div class="guide-icon">🗄️</div>
        <h3>Database</h3>
        <p>Store and query data with our simple API</p>
      </a>
      <a href="/docs/custom-domains" class="guide-card">
        <div class="guide-icon">🌐</div>
        <h3>Custom Domains</h3>
        <p>Connect your own domain to your app</p>
      </a>
    </div>
  </section>

  <section class="support" id="support">
    <h2>Support</h2>
    <p class="subtitle">We're here to help</p>
    <div class="support-options">
      <div class="support-card">
        <div class="support-icon">📧</div>
        <h3>Email</h3>
        <p>Get help from our team</p>
        <a href="mailto:support@itsalive.co" class="support-link">support@itsalive.co</a>
      </div>
      <div class="support-card">
        <div class="support-icon">💬</div>
        <h3>Community</h3>
        <p>Join the conversation</p>
        <a href="https://discord.gg/itsalive" class="support-link" target="_blank">Discord</a>
      </div>
      <div class="support-card">
        <div class="support-icon">📖</div>
        <h3>Documentation</h3>
        <p>Read the docs</p>
        <a href="/docs" class="support-link">View Docs</a>
      </div>
    </div>
  </section>

  <footer>
    <p>Built for vibe coders everywhere</p>
  </footer>
</body>
</html>`;
}

// ============ OG Tag Injection Helpers ============

// Match URL against configured patterns
async function getOGDataForPath(env, subdomain, pathname) {
  const routes = await env.DB.prepare(
    'SELECT * FROM og_routes WHERE app_subdomain = ?'
  ).bind(subdomain).all();

  for (const route of routes.results) {
    const params = matchPattern(route.pattern, pathname);
    if (params) {
      const docId = params[route.id_param || 'id'];
      if (!docId) continue;

      const doc = await env.DB.prepare(
        'SELECT data FROM app_data WHERE app_subdomain = ? AND collection = ? AND doc_id = ?'
      ).bind(subdomain, route.collection, docId).first();

      if (doc) {
        try {
          const data = JSON.parse(doc.data);
          return {
            title: route.title_field ? data[route.title_field] : null,
            description: route.description_field ? data[route.description_field] : null,
            image: route.image_field ? data[route.image_field] : null,
          };
        } catch (e) {
          // Invalid JSON in document
          continue;
        }
      }
    }
  }
  return null;
}

// Pattern matching: /recipe/:id matches /recipe/abc123
function matchPattern(pattern, pathname) {
  const patternParts = pattern.split('/').filter(Boolean);
  const pathParts = pathname.split('/').filter(Boolean);

  if (patternParts.length !== pathParts.length) return null;

  const params = {};
  for (let i = 0; i < patternParts.length; i++) {
    if (patternParts[i].startsWith(':')) {
      params[patternParts[i].slice(1)] = pathParts[i];
    } else if (patternParts[i] !== pathParts[i]) {
      return null;
    }
  }
  return params;
}

// Escape HTML entities for safe attribute values
function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

// Inject OG tags into HTML
function injectOGTags(html, ogData, subdomain) {
  const tags = [];

  if (ogData.title) {
    tags.push(`<meta property="og:title" content="${escapeHtml(ogData.title)}">`);
    tags.push(`<meta name="twitter:title" content="${escapeHtml(ogData.title)}">`);
    // Replace existing title tag or add new one
    if (html.includes('<title>')) {
      html = html.replace(/<title>[^<]*<\/title>/i, `<title>${escapeHtml(ogData.title)}</title>`);
    } else {
      tags.push(`<title>${escapeHtml(ogData.title)}</title>`);
    }
  }

  if (ogData.description) {
    tags.push(`<meta property="og:description" content="${escapeHtml(ogData.description)}">`);
    tags.push(`<meta name="twitter:description" content="${escapeHtml(ogData.description)}">`);
    tags.push(`<meta name="description" content="${escapeHtml(ogData.description)}">`);
  }

  if (ogData.image) {
    tags.push(`<meta property="og:image" content="${escapeHtml(ogData.image)}">`);
    tags.push(`<meta name="twitter:image" content="${escapeHtml(ogData.image)}">`);
    tags.push(`<meta name="twitter:card" content="summary_large_image">`);
  }

  // Add og:type and og:url
  tags.push(`<meta property="og:type" content="website">`);

  if (tags.length > 0) {
    // Insert after <head>
    return html.replace(/<head>/i, `<head>\n    <!-- Dynamic OG tags -->\n    ${tags.join('\n    ')}`);
  }

  return html;
}
