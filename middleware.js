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

// Resolve operator profile, clearance, and role
function getUserProfile(username, usersMap = {}) {
  if (!username) {
    return {
      user: 'unknown',
      role: 'operator',
      roleTag: 'OPERATOR',
      roleTitle: 'Opérateur de Terrain',
      clearance: 'LEVEL 02 // TACTICAL',
      isAdmin: false
    };
  }
  const target = username.toLowerCase().trim();
  const entry = usersMap[username] || usersMap[target];
  const customRole = typeof entry === 'object' && entry.role ? entry.role.toLowerCase().trim() : null;

  // Root Admin verification (built-in accounts, env variables, or role: admin)
  const isEnvAdmin = Boolean(process.env.ADMIN_USERNAME && target === process.env.ADMIN_USERNAME.toLowerCase().trim());
  const isEnvAdminList = Boolean(process.env.ADMIN_USERS && process.env.ADMIN_USERS.toLowerCase().split(',').map(s => s.trim()).includes(target));
  const isBuiltInAdmin = (target === 'admin' || target === 'elmakhchounix' || target === 'sohayb' || customRole === 'admin' || customRole === 'root');

  if (isEnvAdmin || isEnvAdminList || isBuiltInAdmin) {
    return {
      user: username,
      role: 'admin',
      roleTag: 'ROOT_ADMIN',
      roleTitle: 'Commandement Suprême (Root Admin)',
      clearance: 'LEVEL 01 // SUPREME CLEARANCE',
      isAdmin: true
    };
  }

  if (target.includes('analyst') || customRole === 'analyst') {
    return {
      user: username,
      role: 'analyst',
      roleTag: 'ANALYST',
      roleTitle: 'Analyste Renseignement GEOINT',
      clearance: 'LEVEL 02 // INTEL ANALYST',
      isAdmin: false
    };
  }

  if (target.includes('guest') || customRole === 'guest') {
    return {
      user: username,
      role: 'guest',
      roleTag: 'GUEST',
      roleTitle: 'Opérateur Invité (Observation)',
      clearance: 'LEVEL 03 // RESTRICTED',
      isAdmin: false
    };
  }

  return {
    user: username,
    role: 'operator',
    roleTag: 'OPERATOR',
    roleTitle: 'Opérateur de Terrain / Analyste',
    clearance: 'LEVEL 02 // TACTICAL SURVEILLANCE',
    isAdmin: false
  };
}

// Check if user has administrator privileges
function isUserAdmin(username, usersMap = {}) {
  return getUserProfile(username, usersMap).isAdmin;
}

// Record login event and dispatch instant webhook alerts (Discord / Telegram) with role differentiation
function recordAndAlert(user, req, usersMap = {}) {
  const profile = getUserProfile(user, usersMap);
  const ip = req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || req.headers.get('x-real-ip') || 'Direct Connection';
  const country = req.headers.get('x-vercel-ip-country') || 'XX';
  const city = req.headers.get('x-vercel-ip-city') || 'Unknown';
  const userAgent = req.headers.get('user-agent') || 'Unknown Client';
  const timestamp = new Date().toISOString();

  const entry = {
    id: `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
    user,
    role: profile.role,
    roleTag: profile.roleTag,
    roleTitle: profile.roleTitle,
    clearance: profile.clearance,
    isAdmin: profile.isAdmin,
    ip,
    country,
    city,
    userAgent,
    timestamp
  };

  ACCESS_LOGS.unshift(entry);
  if (ACCESS_LOGS.length > MAX_LOGS) ACCESS_LOGS.pop();

  console.log(`[GEOINT_AUDIT] Operator: "${user}" [${profile.roleTag}] | IP: ${ip} | Location: ${country}/${city} | Time: ${timestamp}`);

  const webhooks = getWebhookConfig();
  const promises = [];

  // 1. Discord Webhook
  if (webhooks.discord) {
    let embedTitle, embedDesc, embedColor, roleField;

    if (profile.isAdmin) {
      embedTitle = "👑 [ROOT ADMIN CLEARANCE] Console Initialized";
      embedDesc = "👑 **Session Administrateur Suprême Activée**\nAccès total au système cartographique, aux flux satellitaires et au registre d'audit (/admin).";
      embedColor = 0xef4444; // Imperial Crimson Red
      roleField = "👑 `COMMANDEMENT ROOT` (Niveau 1)";
    } else if (profile.role === 'analyst') {
      embedTitle = "🎖️ [INTEL ANALYST ACCESS] Field Session Active";
      embedDesc = "🎖️ **Session Analyste Renseignement Activée**\nAccès opérationnel aux couches cartographiques et installations militaires.";
      embedColor = 0x38bdf8; // Sky Blue
      roleField = "🎖️ `ANALYSTE RENSEIGNEMENT` (Niveau 2)";
    } else {
      embedTitle = "🛡️ [OPERATOR ACCESS] Tactical Map Session Active";
      embedDesc = "🛡️ **Session Opérateur de Terrain Activée**\nConsultation du dispositif cartographique et couches opérationnelles.";
      embedColor = 0x00ff66; // Emerald Tactical Green
      roleField = "🛡️ `OPÉRATEUR DE TERRAIN` (Niveau 2)";
    }

    const payload = {
      username: "GEOINT Sentinel",
      avatar_url: "https://pbs.twimg.com/profile_images/2014443944436756480/V07PR1oY_400x400.jpg",
      embeds: [{
        title: embedTitle,
        description: embedDesc,
        color: embedColor,
        fields: [
          { name: "👤 Identifiant Opérateur", value: `\`${user}\``, inline: true },
          { name: "🔰 Statut Habilitation", value: roleField, inline: true },
          { name: "🔒 Droits Registre /admin", value: profile.isAdmin ? "🔓 **PLEIN ACCÈS**" : "🔒 **VERROUILLÉ (403)**", inline: true },
          { name: "🌍 Localisation", value: `${country} (${city})`, inline: true },
          { name: "🌐 Adresse IP", value: `\`${ip}\``, inline: true },
          { name: "⏱️ Horodatage (UTC)", value: timestamp, inline: true },
          { name: "🖥️ Navigateur / Client", value: `\`${userAgent.slice(0, 150)}\``, inline: false }
        ],
        footer: { text: `Morocco Sahara GEOINT • ${profile.isAdmin ? "Priorité Sécurité Maximale" : "Journal d'Audit Standard"}` }
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
    const iconHeader = profile.isAdmin 
      ? `🚨👑 *[ACCÈS ROOT ADMIN DÉTECTÉ]*` 
      : `🛡️ *[CONNEXION OPÉRATEUR TERRAIN]*`;

    const text = `${iconHeader}\n\n` +
      `👤 *Opérateur:* \`${user}\`\n` +
      `🔰 *Habilitation:* ${profile.roleTitle}\n` +
      `🔒 *Droits /admin:* ${profile.isAdmin ? "✅ Plein Accès" : "⛔ Bloqué (Carte Seule)"}\n` +
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

          for (const [validUser, validVal] of Object.entries(usersMap)) {
            const validPwd = (typeof validVal === 'object' && validVal.password) ? validVal.password : validVal;
            const [uOk, pOk] = await Promise.all([
              safeEqual(inputUser, validUser),
              safeEqual(inputPwd, String(validPwd))
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
      const profile = getUserProfile(authenticatedUser, usersMap);
      return new Response(JSON.stringify({
        user: authenticatedUser,
        role: profile.role,
        roleTag: profile.roleTag,
        roleTitle: profile.roleTitle,
        clearance: profile.clearance,
        isAdmin: profile.isAdmin,
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
      if (!isUserAdmin(authenticatedUser, usersMap)) {
        return new Response(JSON.stringify({ error: 'Forbidden: Admin clearance required' }), {
          status: 403,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      const webhooks = getWebhookConfig();
      const accountsList = Object.keys(usersMap).map(u => {
        const p = getUserProfile(u, usersMap);
        return {
          username: u,
          role: p.role,
          roleTag: p.roleTag,
          roleTitle: p.roleTitle,
          clearance: p.clearance,
          isAdmin: p.isAdmin
        };
      });
      return new Response(JSON.stringify({
        logs: ACCESS_LOGS,
        registeredUsers: accountsList,
        webhooks: {
          discord: Boolean(webhooks.discord),
          telegram: Boolean(webhooks.teleToken && webhooks.teleChat)
        }
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }
      });
    }

    // Test Webhook API
    if (url.pathname === '/api/admin/test-webhook') {
      if (!isUserAdmin(authenticatedUser, usersMap)) {
        return new Response(JSON.stringify({ error: 'Forbidden' }), { status: 403, headers: { 'Content-Type': 'application/json' } });
      }
      const webhooks = getWebhookConfig();
      let sentDiscord = false;
      if (webhooks.discord) {
        try {
          const testRes = await fetch(webhooks.discord, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              username: "GEOINT Sentinel",
              avatar_url: "https://pbs.twimg.com/profile_images/2014443944436756480/V07PR1oY_400x400.jpg",
              embeds: [{
                title: "🔔 [TEST DISCORD RÉUSSI] Alerte Sentinel",
                description: "Le système d'alerte en direct est connecté à votre serveur Discord !",
                color: 0x00ff00,
                fields: [
                  { name: "👤 Déclenché par", value: `\`${authenticatedUser}\``, inline: true },
                  { name: "⏱️ Heure", value: new Date().toISOString(), inline: true }
                ],
                footer: { text: "Morocco Sahara GEOINT • Test de Connexion" }
              }]
            })
          });
          sentDiscord = testRes.ok;
        } catch (e) {}
      }
      return new Response(JSON.stringify({ success: sentDiscord, discordConfigured: Boolean(webhooks.discord) }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Track user sessions (30s cooldown between alerts)
    const cookieHeader = req.headers.get('cookie') || '';
    const sessionCookieKey = `geoint_session_${authenticatedUser}`;
    const isNewSession = !cookieHeader.includes(sessionCookieKey);

    if (isNewSession) {
      recordAndAlert(authenticatedUser, req, usersMap);
    }

    // Admin Audit Dashboard UI (/admin)
    if (url.pathname === '/admin' || url.pathname === '/admin/') {
      if (!isUserAdmin(authenticatedUser, usersMap)) {
        return new Response(renderForbiddenPage(authenticatedUser, usersMap), {
          status: 403,
          headers: { 'Content-Type': 'text/html; charset=utf-8' }
        });
      }
      if (ACCESS_LOGS.length === 0) {
        recordAndAlert(authenticatedUser, req, usersMap);
      }
      const adminHeaders = new Headers({
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store'
      });
      adminHeaders.append('Set-Cookie', `geoint_operator=${encodeURIComponent(authenticatedUser)}; Path=/; SameSite=Lax; Max-Age=86400`);
      return new Response(renderAdminDashboard(authenticatedUser, usersMap), {
        status: 200,
        headers: adminHeaders
      });
    }

    // Continue to static files & attach operator cookie
    const res = next();
    res.headers.set('Set-Cookie', `geoint_operator=${encodeURIComponent(authenticatedUser)}; Path=/; SameSite=Lax; Max-Age=86400`);
    if (isNewSession) {
      res.headers.append('Set-Cookie', `${sessionCookieKey}=1; Path=/; SameSite=Lax; Max-Age=30`);
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

function renderForbiddenPage(user, usersMap = {}) {
  const profile = getUserProfile(user, usersMap);
  return `<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Accès Refusé // Habilitation Restreinte</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: #080c14;
      color: #f1f5f9;
      font-family: 'Courier New', monospace, -apple-system, sans-serif;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      margin: 0;
      padding: 20px;
      text-align: center;
    }
    .box {
      background: rgba(15, 23, 42, 0.95);
      border: 1px solid #ef4444;
      border-radius: 8px;
      padding: 32px 24px;
      max-width: 480px;
      width: 100%;
      box-shadow: 0 0 35px rgba(239, 68, 68, 0.2);
    }
    .badge-forbidden {
      display: inline-block;
      padding: 3px 10px;
      background: rgba(239, 68, 68, 0.15);
      border: 1px solid #ef4444;
      color: #ef4444;
      font-size: 11px;
      font-weight: bold;
      border-radius: 3px;
      letter-spacing: 1px;
      margin-bottom: 14px;
    }
    h1 { color: #ef4444; font-size: 18px; margin-bottom: 16px; letter-spacing: 1px; }
    p { font-size: 13px; color: #94a3b8; line-height: 1.6; margin-bottom: 20px; }
    .profile-card {
      background: rgba(0, 0, 0, 0.6);
      border: 1px dashed #334155;
      border-radius: 4px;
      padding: 12px 14px;
      margin-bottom: 20px;
      font-size: 12px;
      text-align: left;
    }
    .profile-card div { margin-bottom: 5px; }
    .btn {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 10px 18px;
      background: #0f0;
      color: #000;
      font-weight: bold;
      text-decoration: none;
      border-radius: 4px;
      font-size: 12px;
      transition: 0.2s;
    }
    .btn:hover { background: #00dd00; box-shadow: 0 0 15px #0f0; }
  </style>
</head>
<body>
  <div class="box">
    <div class="badge-forbidden">403 // ACCÈS NON AUTORISÉ</div>
    <h1>[ HABILITATION RESTREINTE ]</h1>
    <div class="profile-card">
      <div>👤 Opérateur connecté : <strong style="color: #0f0;">${user}</strong></div>
      <div>🎖️ Rôle détecté : <span style="color: #38bdf8;">${profile.roleTitle}</span></div>
      <div>🔒 Accréditation : <span style="color: #cbd5e1;">${profile.clearance}</span></div>
    </div>
    <p>Votre compte dispose des habilitations nécessaires pour consulter la <strong>carte tactique</strong>.<br><br>Cependant, l&#39;accès au <strong>registre des audits (/admin)</strong>, aux flux d&#39;alertes et aux paramètres de surveillance est strictement réservé au <strong>Root Admin (Commandement Suprême)</strong>.</p>
    <a href="/" class="btn">&larr; RETOUR AU SYSTÈME CARTOGRAPHIQUE</a>
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
        ${discordConfigured ? '<button onclick="testWebhook()" class="btn-tactical" style="margin-top: 8px; padding: 4px 8px; font-size: 10px; width: 100%; justify-content: center;">🔔 ENVOYER UN TEST</button>' : ''}
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
        <h2>👥 IDENTIFIANTS &amp; HABILITATIONS OPÉRATEURS (${usersList.length})</h2>
      </div>
      <div style="overflow-x: auto; margin-bottom: 16px;">
        <table>
          <thead>
            <tr>
              <th>IDENTIFIANT</th>
              <th>RÔLE SYSTÈME</th>
              <th>NIVEAU D'HABILITATION</th>
              <th>DROITS D'ACCÈS</th>
              <th>STATUT</th>
            </tr>
          </thead>
          <tbody>
            ${usersList.map(u => {
              const prof = getUserProfile(u, usersMap);
              const isAdmin = prof.isAdmin;
              return `<tr>
                <td>
                  <span class="badge-user ${isAdmin ? 'badge-admin' : ''}">
                    ${isAdmin ? '👑 ' : '🛡️ '}${u}
                  </span>
                </td>
                <td style="font-weight: bold; color: ${isAdmin ? '#fca5a5' : '#86efac'};">
                  ${prof.roleTitle}
                </td>
                <td>
                  <code style="color: ${isAdmin ? '#ef4444' : '#38bdf8'}; font-size: 11px;">${prof.clearance}</code>
                </td>
                <td style="font-size: 11px; color: ${isAdmin ? '#cbd5e1' : '#94a3b8'};">
                  ${isAdmin ? '✅ Plein Accès (Carte + Registre d&#39;Audit /admin + Webhooks)' : '🔒 Carte Tactique Uniquement (/admin Verrouillé 403)'}
                </td>
                <td>
                  <span class="badge-status status-active">● ACTIF</span>
                </td>
              </tr>`;
            }).join('')}
          </tbody>
        </table>
      </div>
      <div class="guide-box">
        <strong>💡 Comment gérer les comptes et rôles :</strong><br>
        Vous pouvez définir vos utilisateurs dans <code>users.json</code> :<br>
        &bull; <strong>Format standard :</strong> <code>{"admin": "motdepasse", "matrix": "pass2026"}</code> (le compte <code>admin</code> reçoit automatiquement les privilèges Root, les autres sont Opérateurs de terrain).<br>
        &bull; <strong>Ajout d'admins supplémentaires :</strong> ajoutez l'identifiant à la variable d'environnement Vercel <code>ADMIN_USERS</code> (ex: <code>admin,sohayb,matrix</code>).
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
    var localLogHistory = [];

    // 1. Load persistent logs from localStorage
    try {
      var saved = localStorage.getItem("geoint_audit_history");
      if (saved) localLogHistory = JSON.parse(saved);
    } catch(e) {}

    // 2. Load server-rendered logs directly
    var serverLogs = ${serverLogsJson} || [];
    var mergeMap = new Map();
    serverLogs.forEach(function(item) { mergeMap.set(item.id || (item.timestamp + item.user), item); });
    localLogHistory.forEach(function(item) { mergeMap.set(item.id || (item.timestamp + item.user), item); });
    localLogHistory = Array.from(mergeMap.values()).sort(function(a,b) { return new Date(b.timestamp) - new Date(a.timestamp); });
    try { localStorage.setItem("geoint_audit_history", JSON.stringify(localLogHistory)); } catch(e){}

    function renderTable(logs) {
      var tbody = document.getElementById("logs-tbody");
      var counter = document.getElementById("total-sessions-count");

      if (!logs || logs.length === 0) {
        if (tbody) {
          tbody.innerHTML = "<tr><td colspan=\"5\" style=\"text-align: center; color: #64748b; padding: 25px;\">&#128225; Aucun journal de session pour le moment.<br><span style=\"font-size:11px;color:#475569;\">Les connexions apparaitront ici des qu&#39;un operateur visite la carte.</span></td></tr>";
        }
        if (counter) counter.textContent = "0 SESSIONS";
        return;
      }

      if (counter) counter.textContent = logs.length + " SESSIONS";

      if (tbody) {
        tbody.innerHTML = logs.map(function(l) {
          var d = new Date(l.timestamp);
          var dateStr = d.toLocaleDateString() + " " + d.toLocaleTimeString();
          var flag = l.country && l.country !== "XX" ? " [" + l.country + "]" : "";
          var isAdmin = Boolean(l.isAdmin || l.user === "admin" || l.user === "elmakhchounix" || l.user === "sohayb");
          var roleSub = isAdmin ? "👑 NIVEAU 1 // ROOT" : "🛡️ NIVEAU 2 // OPÉRATEUR";
          return "<tr>" +
            "<td><strong>" + dateStr + "</strong><br><span style=\"font-size:10px;color:#64748b;\">" + l.timestamp + "</span></td>" +
            "<td><span class=\"badge-user " + (isAdmin ? "badge-admin" : "") + "\">" + (isAdmin ? "&#128081; " : "&#128737;&#65039; ") + l.user + "</span><br><span style=\"font-size:10px;font-weight:bold;color:" + (isAdmin ? "#fca5a5" : "#86efac") + ";\">" + roleSub + "</span></td>" +
            "<td><code style=\"color:#38bdf8;\">" + l.ip + "</code></td>" +
            "<td>" + (l.city !== "Unknown" ? l.city + ", " : "") + l.country + flag + "</td>" +
            "<td style=\"font-size:11px;color:#94a3b8;max-width:300px;word-break:break-all;\">" + (l.userAgent || "N/A") + "</td>" +
          "</tr>";
        }).join("");
      }
    }

    // Immediately render current logs
    renderTable(localLogHistory);

    async function fetchLatestLogs() {
      try {
        var res = await fetch("/api/admin/logs", { credentials: "include" });
        if (!res.ok) return;
        var data = await res.json();
        if (!data || !data.logs) return;
        
        var map = new Map();
        data.logs.forEach(function(item) { map.set(item.id || (item.timestamp + item.user), item); });
        localLogHistory.forEach(function(item) { map.set(item.id || (item.timestamp + item.user), item); });
        
        localLogHistory = Array.from(map.values()).sort(function(a,b) { return new Date(b.timestamp) - new Date(a.timestamp); });
        try { localStorage.setItem("geoint_audit_history", JSON.stringify(localLogHistory)); } catch(e){}
        
        renderTable(localLogHistory);
      } catch(err) {
        console.warn("Sync notice:", err);
      }
    }

    function filterLogs() {
      var q = (document.getElementById("log-search").value || "").toLowerCase();
      if (!q) { renderTable(localLogHistory); return; }
      var filtered = localLogHistory.filter(function(l) { 
        return (l.user && l.user.toLowerCase().includes(q)) ||
          (l.ip && l.ip.toLowerCase().includes(q)) ||
          (l.country && l.country.toLowerCase().includes(q)) ||
          (l.city && l.city.toLowerCase().includes(q));
      });
      renderTable(filtered);
    }

    function exportLogsJson() {
      var text = JSON.stringify(localLogHistory, null, 2);
      navigator.clipboard.writeText(text).then(function() {
        alert("Journal d'audit copie dans le presse-papier !");
      }).catch(function() {
        prompt("Copiez les logs ci-dessous :", text);
      });
    }

    async function testWebhook() {
      try {
        var res = await fetch("/api/admin/test-webhook", { credentials: "include" });
        var data = await res.json();
        if (data.success) {
          alert("Alerte test envoyee avec succes ! Regardez dans votre salon Discord.");
        } else {
          alert("Impossible d'envoyer l'alerte sur Discord. Verifiez l'URL de votre webhook dans alerts.json.");
        }
      } catch (e) {
        alert("Erreur lors de l'envoi du test : " + e);
      }
    }

    // Background sync every 10 seconds
    setInterval(fetchLatestLogs, 10000);
  </script>
</body>
</html>`;
}
