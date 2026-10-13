import { next } from '@vercel/functions';
import defaultUsers from './users.json';
import defaultAlerts from './alerts.json';

export const config = {
  matcher: '/(.*)',
};

// In-memory ring buffer for recent access sessions
const ACCESS_LOGS = [];
const MAX_LOGS = 150;

// Timing-safe string comparison
async function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
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

// Retrieve and merge authorized users: users.json + AUTHORIZED_USERS env + ADMIN_USERNAME/PASSWORD env
function getAuthorizedUsers() {
  const users = {};

  // 1. Load defaults from users.json
  try {
    if (defaultUsers && typeof defaultUsers === 'object') {
      Object.assign(users, defaultUsers);
    }
  } catch (e) {
    console.error('[AUTH] Failed loading users.json:', e);
  }

  // 2. Load from AUTHORIZED_USERS environment variable (e.g. "user1:pass1,user2:pass2" or JSON)
  if (process.env.AUTHORIZED_USERS) {
    try {
      const raw = process.env.AUTHORIZED_USERS.trim();
      if (raw.startsWith('{')) {
        Object.assign(users, JSON.parse(raw));
      } else {
        raw.split(',').forEach(pair => {
          const colonIdx = pair.indexOf(':');
          if (colonIdx !== -1) {
            const u = pair.slice(0, colonIdx).trim();
            const p = pair.slice(colonIdx + 1).trim();
            if (u && p) users[u] = p;
          }
        });
      }
    } catch (e) {
      console.error('[AUTH] Failed parsing AUTHORIZED_USERS:', e);
    }
  }

  // 3. Fallback / backward compatibility: ADMIN_USERNAME & ADMIN_PASSWORD
  if (process.env.ADMIN_USERNAME && process.env.ADMIN_PASSWORD) {
    users[process.env.ADMIN_USERNAME.trim()] = process.env.ADMIN_PASSWORD.trim();
  }

  return users;
}

// Retrieve webhook configuration from env vars OR alerts.json
function getWebhookConfig() {
  let discord = (process.env.DISCORD_WEBHOOK_URL || '').trim();
  let teleToken = (process.env.TELEGRAM_BOT_TOKEN || '').trim();
  let teleChat = (process.env.TELEGRAM_CHAT_ID || '').trim();

  try {
    if (defaultAlerts && typeof defaultAlerts === 'object') {
      if (!discord && defaultAlerts.discord_webhook_url) {
        discord = defaultAlerts.discord_webhook_url.trim();
      }
      if (!teleToken && defaultAlerts.telegram_bot_token) {
        teleToken = defaultAlerts.telegram_bot_token.trim();
      }
      if (!teleChat && defaultAlerts.telegram_chat_id) {
        teleChat = String(defaultAlerts.telegram_chat_id).trim();
      }
    }
  } catch (e) {}

  return { discord, teleToken, teleChat };
}

// Check if user has administrator privileges
function isUserAdmin(username) {
  if (!username) return false;
  const target = username.toLowerCase().trim();
  if (process.env.ADMIN_USERNAME && target === process.env.ADMIN_USERNAME.toLowerCase().trim()) return true;
  if (target === 'admin' || target === 'elmakhchounix' || target === 'sohayb') return true;
  if (process.env.ADMIN_USERS) {
    const admins = process.env.ADMIN_USERS.toLowerCase().split(',').map(s => s.trim());
    if (admins.includes(target)) return true;
  }
  return false;
}

// Record login event and dispatch instant webhook alerts (Discord / Telegram)
function recordAndAlert(user, req) {
  const ip = req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || req.headers.get('x-real-ip') || 'Direct Connection';
  const country = req.headers.get('x-vercel-ip-country') || 'XX';
  const city = req.headers.get('x-vercel-ip-city') || 'Unknown';
  const userAgent = req.headers.get('user-agent') || 'Unknown Client';
  const timestamp = new Date().toISOString();

  const entry = {
    id: `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
    user,
    ip,
    country,
    city,
    userAgent,
    timestamp
  };

  ACCESS_LOGS.unshift(entry);
  if (ACCESS_LOGS.length > MAX_LOGS) ACCESS_LOGS.pop();

  console.log(`[GEOINT_AUDIT] Operator: "${user}" | IP: ${ip} | Location: ${country}/${city} | Time: ${timestamp}`);

  const webhooks = getWebhookConfig();
  const promises = [];

  // 1. Discord Webhook
  if (webhooks.discord) {
    const payload = {
      username: "GEOINT Sentinel",
      avatar_url: "https://pbs.twimg.com/profile_images/2014443944436756480/V07PR1oY_400x400.jpg",
      embeds: [{
        title: "🛡️ [GEOINT ACCESS] Operator Session Initialized",
        description: `Un opérateur s'est connecté au système cartographique GEOINT.`,
        color: isUserAdmin(user) ? 0xef4444 : 0x00ff00,
        fields: [
          { name: "👤 Identifiant Opérateur", value: `\`${user}\``, inline: true },
          { name: "🌍 Localisation", value: `${country} (${city})`, inline: true },
          { name: "🌐 Adresse IP", value: `\`${ip}\``, inline: true },
          { name: "⏱️ Horodatage (UTC)", value: timestamp, inline: false },
          { name: "🖥️ Navigateur / Client", value: `\`${userAgent.slice(0, 150)}\``, inline: false }
        ],
        footer: { text: "Morocco Sahara GEOINT • Audit de Sécurité" }
      }]
    };

    promises.push(
      fetch(webhooks.discord, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      }).catch(err => console.error('[WEBHOOK] Discord error:', err))
    );
  }

  // 2. Telegram Bot
  if (webhooks.teleToken && webhooks.teleChat) {
    const text = `🚨 *[CONNEXION GEOINT DÉTECTÉE]*\n\n` +
      `👤 *Opérateur:* \`${user}\`\n` +
      `🌍 *Lieu:* ${country} (${city})\n` +
      `🌐 *IP:* \`${ip}\`\n` +
      `⏱️ *Heure (UTC):* ${timestamp}\n` +
      `🖥️ *Client:* \`${userAgent.slice(0, 80)}\``;

    promises.push(
      fetch(`https://api.telegram.org/bot${webhooks.teleToken}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chat_id: webhooks.teleChat,
          text,
          parse_mode: 'Markdown'
        })
      }).catch(err => console.error('[WEBHOOK] Telegram error:', err))
    );
  }

  if (promises.length > 0) {
    Promise.allSettled(promises);
  }
}

// -------------------------------------------------------------
// MAIN MIDDLEWARE ENTRY POINT
// -------------------------------------------------------------
export default async function middleware(req) {
  const basicAuth = req.headers.get('authorization');
  let authenticatedUser = null;
  const usersMap = getAuthorizedUsers();

  // 1. Validate credentials via HTTP Basic Auth header
  if (basicAuth && Object.keys(usersMap).length > 0) {
    try {
      const match = basicAuth.trim().match(/^Basic\s+(.+)$/i);
      if (match && match[1]) {
        const decoded = atob(match[1]);
        const colonIdx = decoded.indexOf(':');
        if (colonIdx !== -1) {
          const inputUser = decoded.slice(0, colonIdx);
          const inputPwd = decoded.slice(colonIdx + 1);

          for (const [validUser, validPwd] of Object.entries(usersMap)) {
            const [uOk, pOk] = await Promise.all([
              safeEqual(inputUser, validUser),
              safeEqual(inputPwd, validPwd)
            ]);
            if (uOk && pOk) {
              authenticatedUser = validUser;
              break;
            }
          }
        }
      }
    } catch (e) {
      authenticatedUser = null;
    }
  }

  // 2. Fallback to operator cookie for internal API endpoints
  if (!authenticatedUser) {
    const cookieHeader = req.headers.get('cookie') || '';
    const match = cookieHeader.match(/geoint_operator=([^;]+)/);
    if (match && match[1]) {
      const candidate = decodeURIComponent(match[1]);
      if (usersMap[candidate]) {
        authenticatedUser = candidate;
      }
    }
  }

  // --- AUTHENTICATED REQUESTS ---
  if (authenticatedUser) {
    const url = new URL(req.url);

    // Dynamic Apple MapKit Satellite token endpoint
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

    // WhoAmI Endpoint (Returns caller identity for frontend UI & watermarking)
    if (url.pathname === '/api/whoami') {
      return new Response(JSON.stringify({
        user: authenticatedUser,
        isAdmin: isUserAdmin(authenticatedUser),
        ip: req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || req.headers.get('x-real-ip') || 'Direct',
        country: req.headers.get('x-vercel-ip-country') || 'XX',
        city: req.headers.get('x-vercel-ip-city') || 'Unknown',
        timestamp: new Date().toISOString()
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }
      });
    }

    // Admin Logs API (JSON for dashboard polling)
    if (url.pathname === '/api/admin/logs') {
      if (!isUserAdmin(authenticatedUser)) {
        return new Response(JSON.stringify({ error: 'Forbidden: Admin clearance required' }), {
          status: 403,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      const webhooks = getWebhookConfig();
      return new Response(JSON.stringify({
        logs: ACCESS_LOGS,
        registeredUsers: Object.keys(usersMap),
        webhooks: {
          discord: Boolean(webhooks.discord),
          telegram: Boolean(webhooks.teleToken && webhooks.teleChat)
        }
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }
      });
    }

    // Track new user sessions
    const cookieHeader = req.headers.get('cookie') || '';
    const sessionCookieKey = `geoint_session_${authenticatedUser}`;
    const isNewSession = !cookieHeader.includes(sessionCookieKey);

    if (isNewSession) {
      recordAndAlert(authenticatedUser, req);
    }

    // Admin Audit Dashboard UI (/admin)
    if (url.pathname === '/admin' || url.pathname === '/admin/') {
      if (!isUserAdmin(authenticatedUser)) {
        return new Response(renderForbiddenPage(authenticatedUser), {
          status: 403,
          headers: { 'Content-Type': 'text/html; charset=utf-8' }
        });
      }
      return new Response(renderAdminDashboard(authenticatedUser, usersMap), {
        status: 200,
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });
    }

    // Continue to static files & attach operator cookie
    const res = next();
    res.headers.set('Set-Cookie', `geoint_operator=${encodeURIComponent(authenticatedUser)}; Path=/; SameSite=Lax; Max-Age=86400`);
    if (isNewSession) {
      res.headers.append('Set-Cookie', `${sessionCookieKey}=1; Path=/; SameSite=Lax; Max-Age=1800`);
    }
    return res;
  }

  // --- UNAUTHENTICATED (HTTP 401 GATEWAY) ---
  return new Response(render401Page(), {
    status: 401,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'WWW-Authenticate': 'Basic realm="Zone Securisee GEOINT"'
    }
  });
}

// -------------------------------------------------------------
// HTML TEMPLATES
// -------------------------------------------------------------

function render401Page() {
  return `<!DOCTYPE html>
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
      display: inline-flex;
      align-items: center;
      justify-content: center;
      padding: 10px 22px;
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
    .btn-contact {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 7px;
      padding: 10px 20px;
      background: rgba(255, 255, 255, 0.06);
      border: 1px solid rgba(255, 255, 255, 0.2);
      color: #f1f5f9;
      font-size: 13px;
      font-weight: 600;
      border-radius: 6px;
      text-decoration: none;
      cursor: pointer;
      transition: all 0.2s ease;
    }
    .btn-contact:hover {
      background: rgba(255, 255, 255, 0.15);
      border-color: #38bdf8;
      color: #38bdf8;
      box-shadow: 0 0 15px rgba(56, 189, 248, 0.2);
    }
    .btn-group {
      display: flex;
      gap: 12px;
      justify-content: center;
      align-items: center;
      flex-wrap: wrap;
    }
    .creator-link {
      color: #38bdf8;
      text-decoration: none;
      font-weight: 600;
      transition: color 0.2s ease;
    }
    .creator-link:hover {
      color: #7dd3fc;
      text-decoration: underline;
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
    <p>Authentification requise pour accéder au système cartographique et aux flux satellitaires.<br><br>Si vous souhaitez obtenir un accès, veuillez contacter le créateur : <a href="https://x.com/ElMakhchouniX" target="_blank" rel="noopener noreferrer" class="creator-link">Søhäyb (@ElMakhchouniX)</a>.</p>
    <div class="btn-group">
      <a href="javascript:location.reload()" class="btn">S'authentifier</a>
      <a href="https://x.com/ElMakhchouniX" target="_blank" rel="noopener noreferrer" class="btn-contact">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="currentColor"><path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"/></svg>
        Demander un accès (@ElMakhchouniX)
      </a>
    </div>
    <div class="sub">SYS_ID: GEOINT-FAR // STATUS: LOCKED</div>
  </div>
</body>
</html>`;
}

function renderForbiddenPage(user) {
  return `<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <title>Accès Administrateur Refusé // GEOINT</title>
  <style>
    body { background: #080c14; color: #f1f5f9; font-family: 'Courier New', monospace; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; text-align: center; }
    .box { background: rgba(15, 23, 42, 0.95); border: 1px solid #ef4444; border-radius: 8px; padding: 30px; max-width: 450px; }
    h1 { color: #ef4444; font-size: 18px; margin-bottom: 15px; }
    p { font-size: 13px; color: #94a3b8; line-height: 1.6; }
    .btn { display: inline-block; margin-top: 20px; padding: 8px 16px; background: #0f0; color: #000; font-weight: bold; text-decoration: none; border-radius: 4px; }
  </style>
</head>
<body>
  <div class="box">
    <h1>[ 403 // HABILITATION RESTREINTE ]</h1>
    <p>Opérateur connecté : <strong style="color: #0f0;">${user}</strong><br><br>Votre compte dispose d'une autorisation standard pour consulter la carte, mais l'accès au registre des audits (/admin) est strictement réservé à l'administrateur système.</p>
    <a href="/" class="btn">RETOUR AU SYSTÈME CARTOGRAPHIQUE</a>
  </div>
</body>
</html>`;
}

function renderAdminDashboard(adminUser, usersMap) {
  const usersList = Object.keys(usersMap);
  const webhooks = getWebhookConfig();
  const discordConfigured = Boolean(webhooks.discord);
  const telegramConfigured = Boolean(webhooks.teleToken && webhooks.teleChat);
  const serverLogsJson = JSON.stringify(ACCESS_LOGS);

  return `<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>GEOINT Sentinel // Audit & Contrôle d'Accès</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: #06090e;
      color: #e2e8f0;
      font-family: 'Courier New', monospace, sans-serif;
      padding: 24px;
      min-height: 100vh;
    }
    .container { max-width: 1200px; margin: 0 auto; }
    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 1px solid #1e293b;
      padding-bottom: 16px;
      margin-bottom: 24px;
      flex-wrap: wrap;
      gap: 12px;
    }
    .header-title h1 {
      font-size: 18px;
      color: #0f0;
      letter-spacing: 2px;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .header-title p {
      font-size: 12px;
      color: #64748b;
      margin-top: 4px;
    }
    .btn-tactical {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: rgba(0, 255, 0, 0.1);
      border: 1px solid #0f0;
      color: #0f0;
      padding: 8px 16px;
      font-size: 12px;
      font-weight: bold;
      text-decoration: none;
      border-radius: 4px;
      cursor: pointer;
      transition: 0.2s;
    }
    .btn-tactical:hover { background: #0f0; color: #000; box-shadow: 0 0 10px #0f0; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 16px; margin-bottom: 24px; }
    .stat-card {
      background: rgba(15, 23, 42, 0.7);
      border: 1px solid #1e293b;
      border-left: 3px solid #0f0;
      padding: 16px;
      border-radius: 6px;
    }
    .stat-card.red { border-left-color: #ef4444; }
    .stat-card.blue { border-left-color: #38bdf8; }
    .stat-label { font-size: 11px; color: #64748b; letter-spacing: 1px; text-transform: uppercase; }
    .stat-val { font-size: 18px; font-weight: bold; color: #fff; margin-top: 4px; }
    .section {
      background: rgba(15, 23, 42, 0.8);
      border: 1px solid #1e293b;
      border-radius: 8px;
      padding: 20px;
      margin-bottom: 24px;
    }
    .section-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 16px;
      border-bottom: 1px dashed #334155;
      padding-bottom: 10px;
    }
    .section-header h2 { font-size: 14px; color: #38bdf8; letter-spacing: 1px; }
    table { width: 100%; border-collapse: collapse; font-size: 12px; }
    th { text-align: left; padding: 10px 12px; color: #64748b; border-bottom: 1px solid #334155; font-size: 11px; letter-spacing: 1px; }
    td { padding: 12px; border-bottom: 1px solid rgba(51, 65, 85, 0.4); color: #cbd5e1; }
    tr:hover { background: rgba(255, 255, 255, 0.02); }
    .badge-user {
      display: inline-block;
      padding: 3px 10px;
      border-radius: 3px;
      background: rgba(0, 255, 0, 0.15);
      border: 1px solid #0f0;
      color: #0f0;
      font-weight: bold;
      font-size: 12px;
      letter-spacing: 1px;
    }
    .badge-admin {
      background: rgba(239, 68, 68, 0.2);
      border-color: #ef4444;
      color: #fca5a5;
    }
    .badge-status {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      font-size: 11px;
      padding: 3px 8px;
      border-radius: 3px;
    }
    .status-active { background: rgba(0, 255, 0, 0.15); color: #0f0; border: 1px solid #0f0; }
    .status-off { background: rgba(100, 116, 139, 0.2); color: #94a3b8; border: 1px solid #64748b; }
    .guide-box {
      background: rgba(30, 41, 59, 0.5);
      border: 1px solid #334155;
      border-radius: 6px;
      padding: 14px;
      font-size: 12px;
      line-height: 1.6;
      color: #94a3b8;
    }
    .guide-box code { color: #38bdf8; background: #000; padding: 2px 6px; border-radius: 3px; font-weight: bold; }
    .search-input {
      background: #000;
      border: 1px solid #334155;
      color: #0f0;
      padding: 6px 12px;
      font-family: inherit;
      font-size: 12px;
      border-radius: 4px;
      width: 240px;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="header-title">
        <h1><span>🛡️</span> [ GEOINT SENTINEL // REGISTRE D'ACCÈS & AUDIT ]</h1>
        <p>CONSOLE DE COMMANDEMENT SÉCURISÉE &bull; OPÉRATEUR ACTIF : <strong style="color: #0f0;">${adminUser.toUpperCase()}</strong> (ROOT)</p>
      </div>
      <div>
        <a href="/" class="btn-tactical">&larr; ACCÉDER À LA CARTE</a>
      </div>
    </div>

    <!-- STATS OVERVIEW -->
    <div class="grid">
      <div class="stat-card">
        <div class="stat-label">Comptes Opérateurs Actifs</div>
        <div class="stat-val" style="color: #0f0;">${usersList.length} IDENTIFIANTS</div>
      </div>
      <div class="stat-card blue">
        <div class="stat-label">Sessions Enregistrées</div>
        <div class="stat-val" id="total-sessions-count">0 SESSIONS</div>
      </div>
      <div class="stat-card red">
        <div class="stat-label">Alerte Discord</div>
        <div class="stat-val">
          <span class="badge-status ${discordConfigured ? 'status-active' : 'status-off'}">
            ${discordConfigured ? '● ACTIF (WEBHOOK LIÉ)' : '○ NON CONFIGURÉ'}
          </span>
        </div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Alerte Telegram</div>
        <div class="stat-val">
          <span class="badge-status ${telegramConfigured ? 'status-active' : 'status-off'}">
            ${telegramConfigured ? '● ACTIF (BOT LIÉ)' : '○ NON CONFIGURÉ'}
          </span>
        </div>
      </div>
    </div>

    <!-- REGISTERED OPERATOR ACCOUNTS -->
    <div class="section">
      <div class="section-header">
        <h2>👥 IDENTIFIANTS OPÉRATEURS ENREGISTRÉS (${usersList.length})</h2>
      </div>
      <div style="display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 12px;">
        ${usersList.map(u => `
          <div class="badge-user ${isUserAdmin(u) ? 'badge-admin' : ''}">
            ${isUserAdmin(u) ? '👑 ' : '👤 '}${u}
          </div>
        `).join('')}
      </div>
      <div class="guide-box">
        <strong>💡 Comment gérer les comptes :</strong><br>
        Modifiez simplement le fichier <code>users.json</code> dans votre projet (ex: <code>{"admin": "motdepasse", "matrix": "pass2026"}</code>) et redéployez.
      </div>
    </div>

    <!-- LIVE ACCESS AUDIT TABLE -->
    <div class="section">
      <div class="section-header">
        <h2>📡 HISTORIQUE DES CONNEXIONS EN DIRECT</h2>
        <div style="display: flex; gap: 8px;">
          <input type="text" id="log-search" class="search-input" placeholder="Filtrer (opérateur, IP, pays)..." onkeyup="filterLogs()">
          <button onclick="fetchLatestLogs()" class="btn-tactical" style="padding: 6px 12px;">🔄 ACTUALISER</button>
          <button onclick="exportLogsJson()" class="btn-tactical" style="padding: 6px 12px;">📋 COPIER JSON</button>
        </div>
      </div>

      <div style="overflow-x: auto;">
        <table id="audit-table">
          <thead>
            <tr>
              <th>HORODATAGE (UTC / LOCAL)</th>
              <th>IDENTIFIANT OPÉRATEUR</th>
              <th>ADRESSE IP</th>
              <th>LOCALISATION</th>
              <th>CLIENT / NAVIGATEUR</th>
            </tr>
          </thead>
          <tbody id="logs-tbody">
            <tr><td colspan="5" style="text-align: center; color: #64748b; padding: 25px;">Chargement des données d'audit...</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- INSTANT WEBHOOK CONFIGURATION GUIDE -->
    <div class="section">
      <div class="section-header">
        <h2>⚡ CONFIGURATION DES ALERTES (DISCORD & TELEGRAM)</h2>
      </div>
      <div class="guide-box">
        Vous pouvez configurer les alertes de <strong>deux façons simples</strong> :<br><br>
        <strong>Méthode 1 : Fichier local <code>alerts.json</code> (Le plus rapide)</strong><br>
        Ouvrez <code>alerts.json</code> dans le dossier du projet et collez directement votre webhook :<br>
        <code>{"discord_webhook_url": "https://discord.com/api/webhooks/...", "telegram_bot_token": "...", "telegram_chat_id": "..."}</code><br><br>
        <strong>Méthode 2 : Variables Vercel</strong><br>
        Ajoutez <code>DISCORD_WEBHOOK_URL</code> ou <code>TELEGRAM_BOT_TOKEN</code> + <code>TELEGRAM_CHAT_ID</code> dans <strong>Vercel &rarr; Settings &rarr; Environment Variables</strong>, puis cliquez sur <strong>Redeploy</strong>.
      </div>
    </div>
  </div>

  <script>
    let localLogHistory = [];

    // 1. Load persistent logs from localStorage
    try {
      const saved = localStorage.getItem('geoint_audit_history');
      if (saved) localLogHistory = JSON.parse(saved);
    } catch(e) {}

    // 2. Load server-rendered logs directly
    const serverLogs = ${serverLogsJson} || [];
    const mergeMap = new Map();
    serverLogs.forEach(item => mergeMap.set(item.id || (item.timestamp + item.user), item));
    localLogHistory.forEach(item => mergeMap.set(item.id || (item.timestamp + item.user), item));
    localLogHistory = Array.from(mergeMap.values()).sort((a,b) => new Date(b.timestamp) - new Date(a.timestamp));
    try { localStorage.setItem('geoint_audit_history', JSON.stringify(localLogHistory)); } catch(e){}

    function renderTable(logs) {
      const tbody = document.getElementById('logs-tbody');
      const counter = document.getElementById('total-sessions-count');

      if (!logs || logs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: #64748b; padding: 25px;">📡 Aucun journal de session pour le moment.<br><span style="font-size:11px;color:#475569;">Les connexions apparaîtront ici dès qu\'un opérateur visite la carte.</span></td></tr>';
        if (counter) counter.textContent = '0 SESSIONS';
        return;
      }

      if (counter) counter.textContent = logs.length + ' SESSIONS';

      tbody.innerHTML = logs.map(l => {
        const d = new Date(l.timestamp);
        const dateStr = d.toLocaleDateString() + ' ' + d.toLocaleTimeString();
        const flag = l.country && l.country !== 'XX' ? ' [' + l.country + ']' : '';
        const isAdmin = l.user === 'admin' || l.user === 'elmakhchounix';
        return '<tr>' +
          '<td><strong>' + dateStr + '</strong><br><span style="font-size:10px;color:#64748b;">' + l.timestamp + '</span></td>' +
          '<td><span class="badge-user ' + (isAdmin ? 'badge-admin' : '') + '">' + (isAdmin ? '👑 ' : '👤 ') + l.user + '</span></td>' +
          '<td><code style="color:#38bdf8;">' + l.ip + '</code></td>' +
          '<td>' + (l.city !== 'Unknown' ? l.city + ', ' : '') + l.country + flag + '</td>' +
          '<td style="font-size:11px;color:#94a3b8;max-width:300px;word-break:break-all;">' + (l.userAgent || 'N/A') + '</td>' +
        '</tr>';
      }).join('');
    }

    // Immediately render current logs
    renderTable(localLogHistory);

    async function fetchLatestLogs() {
      try {
        const res = await fetch('/api/admin/logs', { credentials: 'include' });
        if (!res.ok) return;
        const data = await res.json();
        if (!data || !data.logs) return;
        
        const map = new Map();
        data.logs.forEach(item => map.set(item.id || (item.timestamp + item.user), item));
        localLogHistory.forEach(item => map.set(item.id || (item.timestamp + item.user), item));
        
        localLogHistory = Array.from(map.values()).sort((a,b) => new Date(b.timestamp) - new Date(a.timestamp));
        try { localStorage.setItem('geoint_audit_history', JSON.stringify(localLogHistory)); } catch(e){}
        
        renderTable(localLogHistory);
      } catch(err) {
        console.warn('Sync notice:', err);
      }
    }

    function filterLogs() {
      const q = document.getElementById('log-search').value.toLowerCase();
      if (!q) { renderTable(localLogHistory); return; }
      const filtered = localLogHistory.filter(l => 
        (l.user && l.user.toLowerCase().includes(q)) ||
        (l.ip && l.ip.toLowerCase().includes(q)) ||
        (l.country && l.country.toLowerCase().includes(q)) ||
        (l.city && l.city.toLowerCase().includes(q))
      );
      renderTable(filtered);
    }

    function exportLogsJson() {
      const text = JSON.stringify(localLogHistory, null, 2);
      navigator.clipboard.writeText(text).then(() => {
        alert("Journal d'audit copié dans le presse-papier !");
      }).catch(() => {
        prompt("Copiez les logs ci-dessous :", text);
      });
    }

    // Background sync every 10 seconds
    setInterval(fetchLatestLogs, 10000);
  </script>
</body>
</html>`;
}
