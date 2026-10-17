import { next } from '@vercel/functions';

export const config = {
  matcher: '/(.*)',
};

// In-memory ring buffer for recent access sessions
const ACCESS_LOGS = [];
const MAX_LOGS = 150;
const LAST_ALERT_BY_USER = new Map();
const SESSION_ALERT_COOLDOWN_MS = 30000;

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

const SESSION_TTL_SECONDS = 86400;

// Require AUTH_SECRET strictly from server environment (no hardcoded fallback, fail-closed)
function getAuthSecret() {
  try {
    const raw = process.env.AUTH_SECRET;
    if (typeof raw !== 'string') return null;
    const trimmed = raw.trim();
    return trimmed.length > 0 ? trimmed : null;
  } catch (e) {
    return null;
  }
}

function bytesToHex(uint8) {
  let out = '';
  for (let i = 0; i < uint8.length; i++) {
    out += uint8[i].toString(16).padStart(2, '0');
  }
  return out;
}

function encodeBase64Url(str) {
  const bytes = new TextEncoder().encode(String(str));
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function decodeBase64Url(b64url) {
  if (typeof b64url !== 'string' || !/^[A-Za-z0-9_-]+$/.test(b64url)) return null;
  let b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4 !== 0) b64 += '=';
  try {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return new TextDecoder().decode(bytes);
  } catch (e) {
    return null;
  }
}

// True HMAC-SHA-256 via Web Crypto API
async function signHmacSha256(secret, message) {
  if (!secret || typeof secret !== 'string') return null;
  const enc = new TextEncoder();
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sigBuf = await crypto.subtle.sign('HMAC', cryptoKey, enc.encode(String(message)));
  return bytesToHex(new Uint8Array(sigBuf));
}

// Create an unambiguous signed session token: <base64url(JSON)>.<hmacHex>
async function createSessionToken(username, password, ttlSeconds = SESSION_TTL_SECONDS, nowMs = Date.now()) {
  const secret = getAuthSecret();
  if (!secret || !username || password === undefined || password === null) return null;
  const pwdDigest = await signHmacSha256(secret, `pwd:${String(password)}`);
  if (!pwdDigest) return null;
  const exp = Math.floor(nowMs / 1000) + Number(ttlSeconds);
  const payloadJson = JSON.stringify({
    u: String(username),
    exp: exp,
    ph: pwdDigest
  });
  const payloadB64 = encodeBase64Url(payloadJson);
  const sigHex = await signHmacSha256(secret, payloadB64);
  if (!sigHex) return null;
  return `${payloadB64}.${sigHex}`;
}

// Verify HMAC-SHA-256 signature, expiration, user existence, and password binding
async function verifyAuthToken(tokenStr, usersMap, nowMs = Date.now()) {
  const secret = getAuthSecret();
  if (!secret) return null;
  if (!tokenStr || typeof tokenStr !== 'string' || !usersMap || typeof usersMap !== 'object') return null;

  const trimmed = tokenStr.trim();
  const dotIdx = trimmed.indexOf('.');
  if (dotIdx <= 0 || trimmed.indexOf('.', dotIdx + 1) !== -1) return null;

  const payloadB64 = trimmed.slice(0, dotIdx);
  const providedSig = trimmed.slice(dotIdx + 1);
  if (!payloadB64 || !/^[0-9a-f]{64}$/i.test(providedSig)) return null;

  const expectedSig = await signHmacSha256(secret, payloadB64);
  if (!expectedSig) return null;
  const sigOk = await safeEqual(providedSig.toLowerCase(), expectedSig.toLowerCase());
  if (!sigOk) return null;

  const decodedJson = decodeBase64Url(payloadB64);
  if (!decodedJson) return null;

  let payload;
  try {
    payload = JSON.parse(decodedJson);
  } catch (e) {
    return null;
  }

  if (!payload || typeof payload !== 'object') return null;
  const user = typeof payload.u === 'string' ? payload.u : '';
  const exp = payload.exp;
  const ph = typeof payload.ph === 'string' ? payload.ph : '';

  if (!user || !Object.prototype.hasOwnProperty.call(usersMap, user)) return null;
  if (typeof exp !== 'number' || !Number.isFinite(exp)) return null;

  const nowSec = Math.floor(nowMs / 1000);
  if (exp <= nowSec || exp > nowSec + SESSION_TTL_SECONDS + 300) return null;

  const validVal = usersMap[user];
  const validPwd = (typeof validVal === 'object' && validVal.password) ? validVal.password : validVal;
  const expectedPh = await signHmacSha256(secret, `pwd:${String(validPwd)}`);
  if (!expectedPh) return null;

  const pwdOk = await safeEqual(ph.toLowerCase(), expectedPh.toLowerCase());
  return pwdOk ? user : null;
}

// Normalize and inspect URL paths to block sensitive/internal files regardless of encoding or casing
function isProtectedPath(rawPathname) {
  if (typeof rawPathname !== 'string' || rawPathname.length === 0) return true;
  let current = rawPathname;
  try {
    for (let i = 0; i < 4; i++) {
      const decoded = decodeURIComponent(current);
      if (decoded === current) break;
      current = decoded;
    }
  } catch (e) {
    // Reject malformed percent-encoded paths
    return true;
  }

  if (current.includes('\0')) return true;

  // Normalize slashes, collapse repeated slashes, strip trailing dots/spaces per segment
  const normalized = current.replace(/\\/g, '/').replace(/\/+/g, '/').toLowerCase();
  const rawSegments = normalized.split('/');
  const cleanSegments = [];

  for (let i = 0; i < rawSegments.length; i++) {
    const seg = rawSegments[i].replace(/[\s.]+$/g, '');
    if (!seg || seg === '.') continue;
    if (seg === '..') return true;
    // Block any hidden dotfile or dot-directory (.env, .git, .vercel, .backups, etc.)
    if (seg.startsWith('.')) return true;
    // Block backup/swap/source artifacts anywhere in the path
    if (
      seg.endsWith('.bak') ||
      seg.endsWith('.old') ||
      seg.endsWith('.orig') ||
      seg.endsWith('.tmp') ||
      seg.endsWith('.swp') ||
      seg.endsWith('.env')
    ) {
      return true;
    }
    cleanSegments.push(seg);
  }

  const canonical = '/' + cleanSegments.join('/');
  const lastSegment = cleanSegments.length > 0 ? cleanSegments[cleanSegments.length - 1] : '';

  const blockedExact = new Set([
    '/users.json',
    '/alerts.json',
    '/package.json',
    '/package-lock.json',
    '/vercel.json',
    '/middleware.js',
    '/middleware.ts',
    '/middleware.mjs',
    '/middleware.cjs'
  ]);

  if (blockedExact.has(canonical) || blockedExact.has('/' + lastSegment)) {
    return true;
  }

  return false;
}


// Retrieve and merge authorized users from environment variables (AUTHORIZED_USERS + ADMIN_USERNAME/ADMIN_PASSWORD)
function getAuthorizedUsers() {
  const users = {};

  // 1. Load from AUTHORIZED_USERS environment variable (e.g. "user1:pass1,user2:pass2" or JSON)
  try {
    const rawAuthUsers = process.env.AUTHORIZED_USERS;
    if (typeof rawAuthUsers === 'string' && rawAuthUsers.trim().length > 0) {
      const raw = rawAuthUsers.trim();
      if (raw.startsWith('{')) {
        const parsed = JSON.parse(raw);
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
          Object.assign(users, parsed);
        }
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
    }
  } catch (e) {
    console.error('[AUTH] Failed parsing AUTHORIZED_USERS:', e);
  }

  // 2. Explicit admin credentials from ADMIN_USERNAME & ADMIN_PASSWORD
  try {
    const adminUser = process.env.ADMIN_USERNAME;
    const adminPass = process.env.ADMIN_PASSWORD;
    if (typeof adminUser === 'string' && typeof adminPass === 'string') {
      const u = adminUser.trim();
      const p = adminPass.trim();
      if (u && p) {
        const existing = users[u];
        if (!existing || typeof existing !== 'object') {
          users[u] = { password: p, role: 'admin' };
        }
      }
    }
  } catch (e) {}

  return users;
}

// Retrieve webhook configuration strictly from environment variables
function getWebhookConfig() {
  let discord = '';
  let teleToken = '';
  let teleChat = '';

  try {
    discord = typeof process.env.DISCORD_WEBHOOK_URL === 'string' ? process.env.DISCORD_WEBHOOK_URL.trim() : '';
  } catch (e) {}
  try {
    teleToken = typeof process.env.TELEGRAM_BOT_TOKEN === 'string' ? process.env.TELEGRAM_BOT_TOKEN.trim() : '';
  } catch (e) {}
  try {
    teleChat = typeof process.env.TELEGRAM_CHAT_ID === 'string' ? process.env.TELEGRAM_CHAT_ID.trim() : '';
  } catch (e) {}

  return { discord, teleToken, teleChat };
}

// Resolve operator profile, clearance, and role based strictly on explicit server authorization
function getUserProfile(username, usersMap = {}) {
  if (typeof username !== 'string' || username.length === 0 || username !== username.trim()) {
    return {
      user: 'unknown',
      role: 'operator',
      roleTag: 'OPERATOR',
      roleTitle: 'Opérateur de Terrain',
      clearance: 'LEVEL 02 // TACTICAL',
      isAdmin: false
    };
  }

  if (!usersMap || typeof usersMap !== 'object' || !Object.prototype.hasOwnProperty.call(usersMap, username)) {
    return {
      user: username,
      role: 'operator',
      roleTag: 'OPERATOR',
      roleTitle: 'Opérateur de Terrain',
      clearance: 'LEVEL 02 // TACTICAL',
      isAdmin: false
    };
  }

  const targetLower = username.toLowerCase();
  const entry = usersMap[username];
  const customRole = (entry && typeof entry === 'object' && typeof entry.role === 'string')
    ? entry.role.toLowerCase().trim()
    : null;

  // An explicitly assigned non-admin role (e.g. 'operator', 'analyst', 'guest') can never be elevated to admin
  const hasExplicitLimitedRole = Boolean(customRole && customRole !== 'admin' && customRole !== 'root');

  let isEnvAdmin = false;
  let isEnvAdminList = false;
  try {
    const rawAdminUser = process.env.ADMIN_USERNAME;
    if (typeof rawAdminUser === 'string' && rawAdminUser.trim().length > 0) {
      isEnvAdmin = (username === rawAdminUser.trim());
    }
  } catch (e) {}

  try {
    const rawAdminList = process.env.ADMIN_USERS;
    if (typeof rawAdminList === 'string' && rawAdminList.trim().length > 0) {
      const allowedAdmins = rawAdminList.split(',').map(s => s.trim()).filter(Boolean);
      isEnvAdminList = allowedAdmins.includes(username);
    }
  } catch (e) {}

  const isExplicitRoleAdmin = (customRole === 'admin' || customRole === 'root');

  if (!hasExplicitLimitedRole && (isExplicitRoleAdmin || isEnvAdmin || isEnvAdminList)) {
    return {
      user: username,
      role: 'admin',
      roleTag: 'ROOT_ADMIN',
      roleTitle: 'Commandement Suprême (Root Admin)',
      clearance: 'LEVEL 01 // SUPREME CLEARANCE',
      isAdmin: true
    };
  }

  if (customRole === 'analyst' || (!customRole && targetLower.includes('analyst'))) {
    return {
      user: username,
      role: 'analyst',
      roleTag: 'ANALYST',
      roleTitle: 'Analyste Renseignement GEOINT',
      clearance: 'LEVEL 02 // INTEL ANALYST',
      isAdmin: false
    };
  }

  if (customRole === 'guest' || (!customRole && targetLower.includes('guest'))) {
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

// Record login event and dispatch webhook alerts (Discord / Telegram) with background lifecycle management
function recordAndAlert(user, req, usersMap = {}, event = null, nowMs = Date.now()) {
  const lastAlertTs = LAST_ALERT_BY_USER.get(user);
  if (typeof lastAlertTs === 'number' && (nowMs - lastAlertTs) < SESSION_ALERT_COOLDOWN_MS && (nowMs >= lastAlertTs)) {
    return Promise.resolve([]);
  }
  LAST_ALERT_BY_USER.set(user, nowMs);

  const profile = getUserProfile(user, usersMap);
  const ip = req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || req.headers.get('x-real-ip') || 'Direct Connection';
  const country = req.headers.get('x-vercel-ip-country') || 'XX';
  const city = req.headers.get('x-vercel-ip-city') || 'Unknown';
  const userAgent = req.headers.get('user-agent') || 'Unknown Client';
  const timestamp = new Date(nowMs).toISOString();

  const entry = {
    id: `${nowMs}-${Math.random().toString(36).slice(2, 7)}`,
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
      embedColor = 0xef4444;
      roleField = "👑 `COMMANDEMENT ROOT` (Niveau 1)";
    } else if (profile.role === 'analyst') {
      embedTitle = "🎖️ [INTEL ANALYST ACCESS] Field Session Active";
      embedDesc = "🎖️ **Session Analyste Renseignement Activée**\nAccès opérationnel aux couches cartographiques et installations militaires.";
      embedColor = 0x38bdf8;
      roleField = "🎖️ `ANALYSTE RENSEIGNEMENT` (Niveau 2)";
    } else {
      embedTitle = "🛡️ [OPERATOR ACCESS] Tactical Map Session Active";
      embedDesc = "🛡️ **Session Opérateur de Terrain Activée**\nConsultation du dispositif cartographique et couches opérationnelles.";
      embedColor = 0x00ff66;
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
      Promise.resolve().then(() => fetch(webhooks.discord, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      })).catch(err => {
        console.error('[WEBHOOK] Discord error:', err);
        return Promise.reject(err);
      })
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
      Promise.resolve().then(() => fetch(`https://api.telegram.org/bot${webhooks.teleToken}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chat_id: webhooks.teleChat,
          text,
          parse_mode: 'Markdown'
        })
      })).catch(err => {
        console.error('[WEBHOOK] Telegram error:', err);
        return Promise.reject(err);
      })
    );
  }

  if (promises.length === 0) {
    return Promise.resolve([]);
  }

  const settledPromise = Promise.allSettled(promises);
  if (event && typeof event.waitUntil === 'function') {
    try {
      event.waitUntil(settledPromise);
    } catch (e) {}
  }
  return settledPromise;
}

// -------------------------------------------------------------
// MAIN MIDDLEWARE ENTRY POINT
// -------------------------------------------------------------
export default async function middleware(req, event) {
  const url = new URL(req.url);

  // 0. Block unauthorized direct access to sensitive system/configuration/backup/source files
  if (isProtectedPath(url.pathname)) {
    return new Response(JSON.stringify({ error: 'Access Denied: Protected Asset' }), {
      status: 403,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }
    });
  }

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

  // 2. Cryptographically signed HMAC-SHA-256 session token verification
  if (!authenticatedUser) {
    const cookieHeader = req.headers.get('cookie') || '';
    const match = cookieHeader.match(/(?:^|;\s*)geoint_auth=([^;]+)/);
    if (match && match[1]) {
      try {
        const rawToken = decodeURIComponent(match[1].trim());
        authenticatedUser = await verifyAuthToken(rawToken, usersMap);
      } catch (e) {
        authenticatedUser = null;
      }
    }
  }

  // 3. Explicit Logout Handler (Revokes session tokens, deletes cookies, and clears client storage)
  if (url.pathname === '/logout' || url.pathname === '/logout/' || url.pathname === '/api/logout') {
    const forwardedProto = (req.headers.get('x-forwarded-proto') || '').split(',')[0].trim().toLowerCase();
    let isProdEnv = false;
    try {
      isProdEnv = process.env.NODE_ENV === 'production';
    } catch (e) {}
    const isSecure = url.protocol === 'https:' ||
      forwardedProto === 'https' ||
      isProdEnv;
    const secureAttr = isSecure ? '; Secure' : '';

    const logoutHeaders = new Headers();
    logoutHeaders.append('Set-Cookie', `geoint_auth=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT${secureAttr}`);
    logoutHeaders.append('Set-Cookie', `geoint_operator=; Path=/; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT${secureAttr}`);
    if (authenticatedUser) {
      const sessionCookieKey = `geoint_session_${encodeURIComponent(authenticatedUser)}`;
      logoutHeaders.append('Set-Cookie', `${sessionCookieKey}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT${secureAttr}`);
    }
    logoutHeaders.set('Clear-Site-Data', '"cookies", "storage"');
    logoutHeaders.set('Cache-Control', 'no-store, no-cache, must-revalidate');

    if (url.pathname === '/api/logout') {
      logoutHeaders.set('Content-Type', 'application/json');
      if (basicAuth && !authenticatedUser) {
        logoutHeaders.set('WWW-Authenticate', 'Basic realm="Zone Securisee GEOINT"');
        return new Response(JSON.stringify({ success: true, loggedOut: true }), {
          status: 401,
          headers: logoutHeaders
        });
      }
      return new Response(JSON.stringify({ success: true, loggedOut: true }), {
        status: 200,
        headers: logoutHeaders
      });
    }

    logoutHeaders.set('Content-Type', 'text/html; charset=utf-8');
    return new Response(renderLogoutPage(), {
      status: 200,
      headers: logoutHeaders
    });
  }

  // --- AUTHENTICATED REQUESTS ---
  if (authenticatedUser) {
    const url = new URL(req.url);
    const forwardedProto = (req.headers.get('x-forwarded-proto') || '').split(',')[0].trim().toLowerCase();
    let isProdEnv = false;
    try {
      isProdEnv = process.env.NODE_ENV === 'production';
    } catch (e) {}
    const isSecure = url.protocol === 'https:' ||
      forwardedProto === 'https' ||
      isProdEnv;
    const secureAttr = isSecure ? '; Secure' : '';

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
      const authoritativeLogs = ACCESS_LOGS.map(l => ({
        ...l,
        isAdmin: Boolean(l && typeof l.user === 'string' && isUserAdmin(l.user, usersMap))
      }));
      return new Response(JSON.stringify({
        logs: authoritativeLogs,
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
    const sessionCookieKey = `geoint_session_${encodeURIComponent(authenticatedUser)}`;
    const isNewSession = !cookieHeader.includes(`${sessionCookieKey}=`);

    if (isNewSession) {
      recordAndAlert(authenticatedUser, req, usersMap, event);
    }

    const userVal = usersMap[authenticatedUser];
    const userPwd = (typeof userVal === 'object' && userVal.password) ? userVal.password : userVal;
    const signedSessionToken = await createSessionToken(authenticatedUser, String(userPwd), SESSION_TTL_SECONDS);

    // Admin Audit Dashboard UI (/admin)
    if (url.pathname === '/admin' || url.pathname === '/admin/') {
      if (!isUserAdmin(authenticatedUser, usersMap)) {
        return new Response(renderForbiddenPage(authenticatedUser, usersMap), {
          status: 403,
          headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' }
        });
      }
      const adminRes = new Response(renderAdminDashboard(authenticatedUser, usersMap), {
        status: 200,
        headers: {
          'Content-Type': 'text/html; charset=utf-8',
          'Cache-Control': 'no-store'
        }
      });
      if (signedSessionToken) {
        adminRes.headers.append('Set-Cookie', `geoint_auth=${encodeURIComponent(signedSessionToken)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_TTL_SECONDS}${secureAttr}`);
      }
      if (isNewSession) {
        adminRes.headers.append('Set-Cookie', `${sessionCookieKey}=1; Path=/; HttpOnly; SameSite=Lax; Max-Age=30${secureAttr}`);
      }
      return adminRes;
    }

    // Continue to static files & attach signed session token cookie
    const res = next();
    if (signedSessionToken) {
      res.headers.set('Set-Cookie', `geoint_auth=${encodeURIComponent(signedSessionToken)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_TTL_SECONDS}${secureAttr}`);
    }
    if (isNewSession) {
      res.headers.append('Set-Cookie', `${sessionCookieKey}=1; Path=/; HttpOnly; SameSite=Lax; Max-Age=30${secureAttr}`);
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

function renderLogoutPage() {
  return `<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Session Clôturée - Zone Sécurisée GEOINT</title>
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
      border: 1px solid rgba(16, 185, 129, 0.4);
      border-radius: 12px;
      box-shadow: 0 0 50px rgba(0, 0, 0, 0.8), 0 0 25px rgba(16, 185, 129, 0.15);
      padding: 40px 32px;
      max-width: 480px;
      width: 100%;
      backdrop-filter: blur(8px);
    }
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: rgba(16, 185, 129, 0.15);
      color: #10b981;
      border: 1px solid rgba(16, 185, 129, 0.35);
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
      background-color: #10b981;
      border-radius: 50%;
      box-shadow: 0 0 6px #10b981;
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
      background: rgba(16, 185, 129, 0.2);
      border: 1px solid rgba(16, 185, 129, 0.5);
      color: #6ee7b7;
      font-size: 13px;
      font-weight: 600;
      border-radius: 6px;
      text-decoration: none;
      cursor: pointer;
      transition: all 0.2s ease;
    }
    .btn:hover {
      background: rgba(16, 185, 129, 0.4);
      color: #ffffff;
      border-color: #10b981;
      box-shadow: 0 0 15px rgba(16, 185, 129, 0.3);
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
  <script>
    function relogin(e) {
      if (e) e.preventDefault();
      var redirected = false;
      function go() {
        if (!redirected) {
          redirected = true;
          window.location.href = '/';
        }
      }
      setTimeout(go, 600);
      try {
        var xhr = new XMLHttpRequest();
        xhr.open('GET', '/api/logout', true, 'reconnect_' + Date.now(), 'invalid');
        xhr.onreadystatechange = function() {
          if (xhr.readyState === 4) go();
        };
        xhr.send();
      } catch (err) {
        go();
      }
    }
  </script>
</head>
<body>
  <div class="card">
    <div class="badge">
      <span class="badge-dot"></span>
      SESSION CLÔTURÉE // 200 OK
    </div>
    <h1>Session Terminée</h1>
    <p>Votre session opérateur a été fermée avec succès.<br><br>Les jetons d'accès cryptographiques et les autorisations locales ont été révoqués sur ce terminal.</p>
    <div class="btn-group">
      <a href="/" onclick="relogin(event)" class="btn">Se reconnecter</a>
      <a href="https://x.com/ElMakhchouniX" target="_blank" rel="noopener noreferrer" class="btn-contact">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="currentColor"><path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"/></svg>
        Søhäyb (@ElMakhchouniX)
      </a>
    </div>
    <div class="sub">SYS_ID: GEOINT-FAR // STATUS: LOGGED_OUT</div>
  </div>
</body>
</html>`;
}

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

function escapeHtmlServer(val) {
  if (val === null || val === undefined) return '';
  return String(val)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function serializeJsonForScript(data) {
  return JSON.stringify(data)
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/&/g, '\\u0026')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
}

function renderForbiddenPage(user, usersMap = {}) {
  const profile = getUserProfile(user, usersMap);
  const safeUser = escapeHtmlServer(user);
  const safeRoleTitle = escapeHtmlServer(profile.roleTitle);
  const safeClearance = escapeHtmlServer(profile.clearance);
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
      <div>👤 Opérateur connecté : <strong style="color: #0f0;">${safeUser}</strong></div>
      <div>🎖️ Rôle détecté : <span style="color: #38bdf8;">${safeRoleTitle}</span></div>
      <div>🔒 Accréditation : <span style="color: #cbd5e1;">${safeClearance}</span></div>
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
  const totalSessions = ACCESS_LOGS.length;
  const safeAdminUpper = escapeHtmlServer(String(adminUser || '').toUpperCase());

  let initialLogsHtml = '';
  if (ACCESS_LOGS.length === 0) {
    initialLogsHtml = '<tr><td colspan="5" style="text-align: center; color: #64748b; padding: 25px;">&#128225; Aucun journal de session pour le moment.<br><span style="font-size:11px;color:#475569;">Les connexions apparaîtront ici dès qu&#39;un opérateur visite la carte.</span></td></tr>';
  } else {
    initialLogsHtml = ACCESS_LOGS.map(l => {
      const d = new Date(l.timestamp);
      const dateStr = escapeHtmlServer(d.toLocaleDateString() + ' ' + d.toLocaleTimeString());
      const safeTs = escapeHtmlServer(l.timestamp || '');
      const rawCountry = l.country ? String(l.country) : 'XX';
      const safeCountry = escapeHtmlServer(rawCountry);
      const flag = rawCountry !== 'XX' ? ' [' + safeCountry + ']' : '';
      const isAdmin = Boolean(l && typeof l.user === 'string' && isUserAdmin(l.user, usersMap));
      const roleSub = isAdmin ? '👑 NIVEAU 1 // ROOT' : '🛡️ NIVEAU 2 // OPÉRATEUR';
      const safeUser = escapeHtmlServer(l.user || 'ANONYME');
      const userTag = (isAdmin ? '&#128081; ' : '&#128737;&#65039; ') + safeUser;
      const safeIp = escapeHtmlServer(l.ip || 'Direct');
      const safeCity = l.city && l.city !== 'Unknown' ? escapeHtmlServer(l.city) + ', ' : '';
      const safeUa = escapeHtmlServer(l.userAgent || 'N/A');
      return '<tr>' +
        '<td><strong>' + dateStr + '</strong><br><span style="font-size:10px;color:#64748b;">' + safeTs + '</span></td>' +
        '<td><span class="badge-user ' + (isAdmin ? 'badge-admin' : '') + '">' + userTag + '</span><br><span style="font-size:10px;font-weight:bold;color:' + (isAdmin ? '#fca5a5' : '#86efac') + ';">' + roleSub + '</span></td>' +
        '<td><code style="color:#38bdf8;">' + safeIp + '</code></td>' +
        '<td>' + safeCity + safeCountry + flag + '</td>' +
        '<td style="font-size:11px;color:#94a3b8;max-width:300px;word-break:break-all;">' + safeUa + '</td>' +
      '</tr>';
    }).join('');
  }

  const authoritativeLogs = ACCESS_LOGS.map(l => ({
    ...l,
    isAdmin: Boolean(l && typeof l.user === 'string' && isUserAdmin(l.user, usersMap))
  }));
  const authorizedAdmins = usersList.filter(u => isUserAdmin(u, usersMap));
  const safeServerLogsJson = serializeJsonForScript(authoritativeLogs);
  const safeAdminUsersJson = serializeJsonForScript(authorizedAdmins);

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
        <p>CONSOLE DE COMMANDEMENT SÉCURISÉE &bull; OPÉRATEUR ACTIF : <strong style="color: #0f0;">${safeAdminUpper}</strong> (ROOT)</p>
      </div>
      <div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap;">
        <a href="/" class="btn-tactical">&larr; ACCÉDER À LA CARTE</a>
        <button onclick="performLogout()" class="btn-tactical" style="background: rgba(239, 68, 68, 0.2); border-color: #ef4444; color: #fca5a5;">🚪 DÉCONNEXION</button>
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
        <div class="stat-val" id="total-sessions-count">${totalSessions} SESSIONS</div>
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
              const safeU = escapeHtmlServer(u);
              const safeRole = escapeHtmlServer(prof.roleTitle);
              const safeClearance = escapeHtmlServer(prof.clearance);
              return `<tr>
                <td>
                  <span class="badge-user ${isAdmin ? 'badge-admin' : ''}">
                    ${isAdmin ? '👑 ' : '🛡️ '}${safeU}
                  </span>
                </td>
                <td style="font-weight: bold; color: ${isAdmin ? '#fca5a5' : '#86efac'};">
                  ${safeRole}
                </td>
                <td>
                  <code style="color: ${isAdmin ? '#ef4444' : '#38bdf8'}; font-size: 11px;">${safeClearance}</code>
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
        Vous pouvez définir vos utilisateurs dans les variables d&#39;environnement Vercel :<br>
        &bull; <strong>Comptes opérateurs :</strong> <code>AUTHORIZED_USERS</code> (ex: <code>matrix:pass2026</code> ou JSON avec <code>role: &quot;admin&quot;|&quot;operator&quot;</code>).<br>
        &bull; <strong>Attribution explicite des droits Root Admin :</strong> définissez <code>ADMIN_USERNAME</code> (associé à <code>ADMIN_PASSWORD</code>) ou listez explicitement les administrateurs dans <code>ADMIN_USERS</code>.
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
            ${initialLogsHtml}
          </tbody>
        </table>
      </div>
    </div>

    <!-- INSTANT WEBHOOK CONFIGURATION GUIDE -->
    <div class="section">
      <div class="section-header">
        <h2>⚡ CONFIGURATION DES ALERTES (DISCORD &amp; TELEGRAM)</h2>
      </div>
      <div class="guide-box">
        Configurez les alertes via les <strong>variables d&#39;environnement Vercel</strong> :<br><br>
        Ajoutez <code>DISCORD_WEBHOOK_URL</code> ou <code>TELEGRAM_BOT_TOKEN</code> + <code>TELEGRAM_CHAT_ID</code> dans <strong>Vercel &rarr; Settings &rarr; Environment Variables</strong>, puis cliquez sur <strong>Redeploy</strong>.
      </div>
    </div>
  </div>

  <script id="geoint-admin-users" type="application/json">${safeAdminUsersJson}</script>
  <script id="geoint-initial-logs" type="application/json">${safeServerLogsJson}</script>
  <script>
    var localLogHistory = [];
    var authorizedAdminSet = new Set();

    // 0. Load server-authoritative admin list
    try {
      var adminUsersEl = document.getElementById("geoint-admin-users");
      var parsedAdmins = adminUsersEl && adminUsersEl.textContent ? JSON.parse(adminUsersEl.textContent) : [];
      if (Array.isArray(parsedAdmins)) {
        parsedAdmins.forEach(function(u) {
          if (typeof u === "string" && u) authorizedAdminSet.add(u);
        });
      }
    } catch(e) {
      console.warn("Admin list parse notice:", e);
    }

    // 1. Safely load persistent logs from localStorage with array/object validation
    try {
      var saved = localStorage.getItem("geoint_audit_history");
      if (saved) {
        var parsed = JSON.parse(saved);
        if (Array.isArray(parsed)) {
          localLogHistory = parsed.filter(function(x) { return x && typeof x === "object" && x.user; });
        }
      }
    } catch(e) {
      console.warn("Storage notice:", e);
      localLogHistory = [];
    }

    // 2. Safely parse server-rendered logs from non-executable JSON container
    try {
      var initEl = document.getElementById("geoint-initial-logs");
      var serverLogs = initEl && initEl.textContent ? JSON.parse(initEl.textContent) : [];
      if (Array.isArray(serverLogs)) {
        var mergeMap = new Map();
        serverLogs.forEach(function(item) {
          if (item && typeof item === "object") {
            var key = item.id || (String(item.timestamp) + "_" + String(item.user));
            mergeMap.set(key, item);
          }
        });
        localLogHistory.forEach(function(item) {
          if (item && typeof item === "object") {
            var key = item.id || (String(item.timestamp) + "_" + String(item.user));
            if (!mergeMap.has(key)) {
              mergeMap.set(key, item);
            }
          }
        });
        localLogHistory = Array.from(mergeMap.values()).sort(function(a, b) {
          return new Date(b.timestamp) - new Date(a.timestamp);
        });
        localStorage.setItem("geoint_audit_history", JSON.stringify(localLogHistory));
      }
    } catch(e) {
      console.warn("Merge notice:", e);
    }

    function renderTable(logs) {
      try {
        var tbody = document.getElementById("logs-tbody");
        var counter = document.getElementById("total-sessions-count");

        if (!logs || !Array.isArray(logs) || logs.length === 0) {
          if (counter) counter.textContent = "0 SESSIONS";
          if (tbody) {
            while (tbody.firstChild) tbody.removeChild(tbody.firstChild);
            var emptyTr = document.createElement("tr");
            var emptyTd = document.createElement("td");
            emptyTd.colSpan = 5;
            emptyTd.style.cssText = "text-align: center; color: #64748b; padding: 25px;";
            emptyTd.textContent = "📡 Aucun journal de session correspondant.";
            emptyTr.appendChild(emptyTd);
            tbody.appendChild(emptyTr);
          }
          return;
        }

        if (counter) counter.textContent = logs.length + " SESSIONS";

        if (tbody) {
          while (tbody.firstChild) tbody.removeChild(tbody.firstChild);
          var frag = document.createDocumentFragment();

          logs.forEach(function(l) {
            if (!l || typeof l !== "object") return;
            var d = new Date(l.timestamp || Date.now());
            var dateStr = d.toLocaleDateString() + " " + d.toLocaleTimeString();
            var countryStr = l.country ? String(l.country) : "XX";
            var flag = countryStr !== "XX" ? " [" + countryStr + "]" : "";
            var isAdmin = Boolean(l && typeof l.user === "string" && authorizedAdminSet.has(l.user));
            var roleSub = isAdmin ? "👑 NIVEAU 1 // ROOT" : "🛡️ NIVEAU 2 // OPÉRATEUR";

            var tr = document.createElement("tr");

            // Col 1: Timestamp
            var tdTime = document.createElement("td");
            var strongDate = document.createElement("strong");
            strongDate.textContent = dateStr;
            var brTime = document.createElement("br");
            var spanIso = document.createElement("span");
            spanIso.style.cssText = "font-size:10px;color:#64748b;";
            spanIso.textContent = String(l.timestamp || "");
            tdTime.appendChild(strongDate);
            tdTime.appendChild(brTime);
            tdTime.appendChild(spanIso);
            tr.appendChild(tdTime);

            // Col 2: Operator & Role
            var tdUser = document.createElement("td");
            var spanBadge = document.createElement("span");
            spanBadge.className = "badge-user" + (isAdmin ? " badge-admin" : "");
            spanBadge.textContent = (isAdmin ? "👑 " : "🛡️ ") + String(l.user || "ANONYME");
            var brUser = document.createElement("br");
            var spanRole = document.createElement("span");
            spanRole.style.cssText = "font-size:10px;font-weight:bold;color:" + (isAdmin ? "#fca5a5" : "#86efac") + ";";
            spanRole.textContent = roleSub;
            tdUser.appendChild(spanBadge);
            tdUser.appendChild(brUser);
            tdUser.appendChild(spanRole);
            tr.appendChild(tdUser);

            // Col 3: IP
            var tdIp = document.createElement("td");
            var codeIp = document.createElement("code");
            codeIp.style.color = "#38bdf8";
            codeIp.textContent = String(l.ip || "Direct");
            tdIp.appendChild(codeIp);
            tr.appendChild(tdIp);

            // Col 4: Location
            var tdLoc = document.createElement("td");
            var cityPrefix = (l.city && l.city !== "Unknown") ? (String(l.city) + ", ") : "";
            tdLoc.textContent = cityPrefix + countryStr + flag;
            tr.appendChild(tdLoc);

            // Col 5: User-Agent
            var tdUa = document.createElement("td");
            tdUa.style.cssText = "font-size:11px;color:#94a3b8;max-width:300px;word-break:break-all;";
            tdUa.textContent = String(l.userAgent || "N/A");
            tr.appendChild(tdUa);

            frag.appendChild(tr);
          });

          tbody.appendChild(frag);
        }
      } catch(renderErr) {
        console.error("Render error:", renderErr);
      }
    }

    // Immediately render current logs if present
    if (localLogHistory && localLogHistory.length > 0) {
      renderTable(localLogHistory);
    }

    async function fetchLatestLogs() {
      try {
        var res = await fetch("/api/admin/logs", { credentials: "include" });
        if (!res.ok) return;
        var data = await res.json();
        if (!data || !Array.isArray(data.logs)) return;

        if (Array.isArray(data.registeredUsers)) {
          authorizedAdminSet = new Set(
            data.registeredUsers
              .filter(function(u) { return u && u.isAdmin === true && typeof u.username === "string"; })
              .map(function(u) { return u.username; })
          );
        }
        
        var map = new Map();
        data.logs.forEach(function(item) {
          if (item && typeof item === "object") {
            var key = item.id || (String(item.timestamp) + "_" + String(item.user));
            map.set(key, item);
          }
        });
        localLogHistory.forEach(function(item) {
          if (item && typeof item === "object") {
            var key = item.id || (String(item.timestamp) + "_" + String(item.user));
            if (!map.has(key)) {
              map.set(key, item);
            }
          }
        });
        
        localLogHistory = Array.from(map.values()).sort(function(a,b) {
          return new Date(b.timestamp) - new Date(a.timestamp);
        });
        localStorage.setItem("geoint_audit_history", JSON.stringify(localLogHistory));
        
        renderTable(localLogHistory);
      } catch(err) {
        console.warn("Sync notice:", err);
      }
    }

    function filterLogs() {
      var q = (document.getElementById("log-search").value || "").toLowerCase().trim();
      if (!q) { renderTable(localLogHistory); return; }
      var filtered = localLogHistory.filter(function(l) { 
        if (!l) return false;
        return (l.user && String(l.user).toLowerCase().includes(q)) ||
          (l.ip && String(l.ip).toLowerCase().includes(q)) ||
          (l.country && String(l.country).toLowerCase().includes(q)) ||
          (l.city && String(l.city).toLowerCase().includes(q));
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
          alert("Impossible d'envoyer l'alerte sur Discord. Verifiez la configuration de votre webhook.");
        }
      } catch (e) {
        alert("Erreur lors de l'envoi du test : " + e);
      }
    }

    function performLogout() {
      if (!confirm("Confirmer la deconnexion de la console d'audit ?")) return;
      try {
        localStorage.removeItem("geoint_operator");
        sessionStorage.clear();
      } catch (e) {}
      var redirected = false;
      function go() {
        if (!redirected) {
          redirected = true;
          window.location.href = "/logout";
        }
      }
      setTimeout(go, 600);
      try {
        var xhr = new XMLHttpRequest();
        xhr.open("GET", "/api/logout", true, "logout_" + Date.now(), "logout");
        xhr.onreadystatechange = function() {
          if (xhr.readyState === 4) go();
        };
        xhr.send();
      } catch (e) {
        go();
      }
    }

    // Call immediately on page load
    fetchLatestLogs();

    // Background sync every 8 seconds
    setInterval(fetchLatestLogs, 8000);
  </script>
</body>
</html>`;
}

