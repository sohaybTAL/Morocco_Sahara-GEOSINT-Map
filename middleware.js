import { next } from '@vercel/functions';

export const config = {
  matcher: '/(.*)',
};

async function safeEqual(a, b) {
  const enc = new TextEncoder();
  const [hashA, hashB] = await Promise.all([
    crypto.subtle.digest('SHA-256', enc.encode(String(a))),
    crypto.subtle.digest('SHA-256', enc.encode(String(b)))
  ]);
  const viewA = new Uint8Array(hashA);
  const viewB = new Uint8Array(hashB);
  let diff = 0;
  for (let i = 0; i < viewA.length; i++) {
    diff |= viewA[i] ^ viewB[i];
  }
  return diff === 0;
}

export default async function middleware(req) {
  const basicAuth = req.headers.get('authorization');
  let isAuthenticated = false;

  if (basicAuth) {
    try {
      const match = basicAuth.trim().match(/^Basic\s+(.+)$/i);
      if (!match || !match[1]) throw new Error('Missing auth value');

      // Decode the base64 string and split ONLY on the first colon (RFC 7617)
      const decoded = atob(match[1]);
      const colonIdx = decoded.indexOf(':');
      if (colonIdx === -1) throw new Error('Malformed credentials');

      const user = decoded.slice(0, colonIdx);
      const pwd = decoded.slice(colonIdx + 1);

      const validUser = process.env.ADMIN_USERNAME;
      const validPwd = process.env.ADMIN_PASSWORD;

      // Fail-closed: Ensure environment variables are actually configured
      if (!validUser || !validPwd) {
        throw new Error('Server configuration missing');
      }

      const [userOk, pwdOk] = await Promise.all([
        safeEqual(user, validUser),
        safeEqual(pwd, validPwd)
      ]);

      if (userOk && pwdOk) {
        isAuthenticated = true;
      }
    } catch (e) {
      // Catch malformed base64, missing headers, or missing env vars.
      // Silently fall through to the 401 response below instead of throwing 500.
      isAuthenticated = false;
    }
  }

  if (isAuthenticated) {
    const url = new URL(req.url);

    // 1. Dynamic Apple MapKit Satellite token endpoint (authenticated)
    if (url.pathname === '/apple-key') {
      try {
        const ddgRes = await fetch('https://duckduckgo.com/local.js?get_mk_token=1', {
          cache: 'no-store',
          headers: { 'User-Agent': 'Mozilla/5.0' }
        });
        const jwt = (await ddgRes.text()).trim();
        const bootRes = await fetch('https://cdn.apple-mapkit.com/ma/bootstrap?apiVersion=2&mkjsVersion=5.79.95&poi=1', {
          cache: 'no-store',
          headers: {
            'User-Agent': 'Mozilla/5.0',
            'Authorization': `Bearer ${jwt}`,
            'Origin': 'https://duckduckgo.com',
            'Referer': 'https://duckduckgo.com/'
          }
        });
        const boot = await bootRes.json();
        const sat = (boot.tileSources || []).find(t => t.tileSource === 'satellite');
        const accessKey = boot.accessKey || (sat && sat.path && sat.path.split('accessKey=')[1]);
        if (!accessKey) {
          return new Response(JSON.stringify({ error: 'Token unavailable' }), {
            status: 502,
            headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }
          });
        }
        return new Response(JSON.stringify({ accessKey }), {
          status: 200,
          headers: {
            'Content-Type': 'application/json',
            'Cache-Control': 'private, max-age=900'
          }
        });
      } catch (e) {
        return new Response(JSON.stringify({ error: 'Token service unavailable' }), {
          status: 502,
          headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }
        });
      }
    }

    // Officially supported Vercel API for continuing the request to static files
    return next();
  }

  const html = `<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Accès Refusé - Zone Sécurisée GEOINT</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    html, body {
      height: 100%;
      background-color: #080c14;
      color: #f1f5f9;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      display: flex;
      align-items: center;
      justify-content: center;
      text-align: center;
      padding: 20px;
    }
    .card {
      background: rgba(15, 23, 42, 0.9);
      border: 1px solid rgba(239, 68, 68, 0.4);
      border-radius: 12px;
      box-shadow: 0 0 50px rgba(0, 0, 0, 0.8), 0 0 25px rgba(239, 68, 68, 0.15);
      padding: 40px 32px;
      max-width: 480px;
      width: 100%;
      backdrop-filter: blur(8px);
    }
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: rgba(239, 68, 68, 0.15);
      color: #ef4444;
      border: 1px solid rgba(239, 68, 68, 0.35);
      padding: 4px 12px;
      border-radius: 9999px;
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 1.5px;
      margin-bottom: 20px;
      font-family: monospace;
    }
    .badge-dot {
      width: 6px;
      height: 6px;
      background-color: #ef4444;
      border-radius: 50%;
      box-shadow: 0 0 6px #ef4444;
    }
    h1 {
      font-size: 20px;
      font-weight: 700;
      letter-spacing: 0.5px;
      color: #ffffff;
      margin-bottom: 12px;
      text-transform: uppercase;
    }
    p {
      color: #94a3b8;
      font-size: 13.5px;
      line-height: 1.6;
      margin-bottom: 24px;
    }
    .btn {
      display: inline-block;
      padding: 10px 24px;
      background: rgba(239, 68, 68, 0.2);
      border: 1px solid rgba(239, 68, 68, 0.5);
      color: #fca5a5;
      font-size: 13px;
      font-weight: 600;
      border-radius: 6px;
      text-decoration: none;
      cursor: pointer;
      transition: all 0.2s ease;
    }
    .btn:hover {
      background: rgba(239, 68, 68, 0.4);
      color: #ffffff;
      border-color: #ef4444;
    }
    .sub {
      margin-top: 24px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 11px;
      color: #64748b;
      letter-spacing: 1px;
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="badge">
      <span class="badge-dot"></span>
      RESTRICTED AREA // 401
    </div>
    <h1>Accès Refusé - Zone Sécurisée GEOINT</h1>
    <p>Authentification requise pour accéder au système cartographique et aux flux satellitaires.<br><br>Si vous souhaitez obtenir un accès, veuillez contacter le créateur.</p>
    <a href="javascript:location.reload()" class="btn">S'authentifier</a>
    <div class="sub">SYS_ID: GEOINT-FAR // STATUS: LOCKED</div>
  </div>
</body>
</html>`;

  // HTTP 401 for unauthenticated, wrong password, or malformed requests
  return new Response(html, {
    status: 401,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'WWW-Authenticate': 'Basic realm="Secure Area"'
    }
  });
}
