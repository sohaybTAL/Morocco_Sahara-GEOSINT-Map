import { next } from '@vercel/functions';

export const config = {
  matcher: '/(.*)',
};

export default async function middleware(req) {
  const url = new URL(req.url);

  // 1. Dynamic Apple MapKit Satellite token endpoint
  if (url.pathname === '/apple-key') {
    try {
      const ddgRes = await fetch('https://duckduckgo.com/local.js?get_mk_token=1', {
        headers: { 'User-Agent': 'Mozilla/5.0' }
      });
      const jwt = (await ddgRes.text()).trim();
      const bootRes = await fetch('https://cdn.apple-mapkit.com/ma/bootstrap?apiVersion=2&mkjsVersion=5.79.95&poi=1', {
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
      return new Response(JSON.stringify({ accessKey }), {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
          'Cache-Control': 'public, max-age=3600'
        }
      });
    } catch (e) {
      return new Response(JSON.stringify({ error: e.message }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
      });
    }
  }

  // 2. HERE Satellite tile proxy (injects required wego.here.com Referer header)
  if (url.pathname.startsWith('/here-tile/')) {
    const parts = url.pathname.replace('/here-tile/', '').replace(/\.jpe?g|\.png/, '').split('/');
    if (parts.length >= 3) {
      const [z, x, y] = parts;
      try {
        const hereUrl = `https://maps.hereapi.com/v3/base/mc/${z}/${x}/${y}/jpeg?style=satellite.day&apiKey=aZWQ05uSeD_ewwa8pMDqNOfQtAY_vUAjlgiRflJ4_ug`;
        const tileRes = await fetch(hereUrl, {
          headers: {
            'User-Agent': 'Mozilla/5.0',
            'Referer': 'https://wego.here.com/'
          }
        });
        const tileData = await tileRes.arrayBuffer();
        return new Response(tileData, {
          status: tileRes.status,
          headers: {
            'Content-Type': 'image/jpeg',
            'Access-Control-Allow-Origin': '*',
            'Cache-Control': 'public, max-age=86400'
          }
        });
      } catch (e) {
        return new Response('Tile fetch error', { status: 502 });
      }
    }
  }

  const basicAuth = req.headers.get('authorization');

  if (basicAuth) {
    try {
      const authValue = basicAuth.split(' ')[1];
      if (!authValue) throw new Error('Missing auth value');

      // Decode the base64 string
      const decoded = atob(authValue);
      const [user, pwd] = decoded.split(':');

      const validUser = process.env.ADMIN_USERNAME;
      const validPwd = process.env.ADMIN_PASSWORD;

      // Fail-closed: Ensure environment variables are actually configured
      if (!validUser || !validPwd) {
        throw new Error('Server configuration missing');
      }

      // Check credentials
      if (user === validUser && pwd === validPwd) {
        // Officially supported Vercel API for continuing the request to static files
        return next();
      }
    } catch (e) {
      // Catch malformed base64, missing headers, or missing env vars.
      // Silently fall through to the 401 response below instead of throwing 500.
    }
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
