// This Worker runs before static assets on the Cloudflare site. The GitHub
// Pages copy continues to use its existing browser-only sign-in.
const SUPABASE_URL = 'https://ydwbzeabeiythxsgahmz.supabase.co';
const PUBLISHABLE_KEY = 'sb_publishable_1oLuVR0uJpJ2nTPZ61F9gA_ZWVAnAvS';
const ISSUER = SUPABASE_URL + '/auth/v1';
const COOKIE_NAME = '__Host-study-hub-session';

let cachedKeys = null;
let keysExpireAt = 0;
const approvalCache = new Map();

function isPublicPath(path) {
  if (path === '/' || path === '/index.html') return true;
  // These are the login card's public images and scripts, never course files.
  return path.startsWith('/assets/') && !path.includes('..') && !path.includes('%');
}

function base64UrlBytes(value) {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '='));
  return Uint8Array.from(binary, character => character.charCodeAt(0));
}

function base64UrlJson(value) {
  return JSON.parse(new TextDecoder().decode(base64UrlBytes(value)));
}

async function getSigningKey(kid) {
  if (!cachedKeys || Date.now() >= keysExpireAt) {
    const response = await fetch(ISSUER + '/.well-known/jwks.json', {
      headers: { accept: 'application/json' }
    });
    if (!response.ok) throw new Error('Supabase signing keys unavailable');
    const body = await response.json();
    if (!Array.isArray(body.keys)) throw new Error('Invalid Supabase signing keys');
    cachedKeys = body.keys;
    keysExpireAt = Date.now() + 5 * 60 * 1000;
  }
  const key = cachedKeys.find(item =>
    item.kid === kid && item.kty === 'EC' && item.crv === 'P-256' &&
    (!item.alg || item.alg === 'ES256') && (!item.use || item.use === 'sig')
  );
  if (!key) throw new Error('Unknown Supabase signing key');
  return key;
}

async function verifyAccessToken(token) {
  if (!token || token.length > 8192) return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  try {
    const header = base64UrlJson(parts[0]);
    const claims = base64UrlJson(parts[1]);
    const now = Math.floor(Date.now() / 1000);
    if (header.alg !== 'ES256' || typeof header.kid !== 'string' ||
        claims.iss !== ISSUER ||
        !(claims.aud === 'authenticated' ||
          (Array.isArray(claims.aud) && claims.aud.includes('authenticated'))) ||
        !Number.isFinite(claims.exp) || claims.exp <= now ||
        (claims.nbf && claims.nbf > now + 60) ||
        (claims.iat && claims.iat > now + 60) ||
        typeof claims.sub !== 'string' ||
        typeof claims.email !== 'string' ||
        !/^[^@\s]+@une\.edu$/i.test(claims.email)) return null;
    const metadata = claims.app_metadata || {};
    if (metadata.provider !== 'google' &&
        !(Array.isArray(metadata.providers) && metadata.providers.includes('google'))) return null;
    const jwk = await getSigningKey(header.kid);
    const key = await crypto.subtle.importKey('jwk', jwk, {
      name: 'ECDSA', namedCurve: 'P-256'
    }, false, ['verify']);
    const valid = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' }, key,
      base64UrlBytes(parts[2]),
      new TextEncoder().encode(parts[0] + '.' + parts[1])
    );
    return valid ? claims : null;
  } catch (error) {
    console.error('Study Hub token verification failed', error);
    return null;
  }
}

async function isApproved(token, email) {
  const query = '?select=email&email=eq.' + encodeURIComponent(email.toLowerCase()) + '&limit=1';
  const response = await fetch(SUPABASE_URL + '/rest/v1/study_hub_approved_emails' + query, {
    headers: {
      apikey: PUBLISHABLE_KEY,
      authorization: 'Bearer ' + token,
      accept: 'application/json'
    }
  });
  if (!response.ok) throw new Error('Approval service unavailable');
  const rows = await response.json();
  return Array.isArray(rows) && rows.length === 1 &&
    rows[0].email === email.toLowerCase();
}

async function checkApproval(token, claims) {
  const cacheKey = claims.sub + ':' + claims.email.toLowerCase();
  const cached = approvalCache.get(cacheKey);
  if (cached && cached.expiresAt > Date.now()) return cached.allowed;
  const allowed = await isApproved(token, claims.email);
  if (approvalCache.size >= 512) approvalCache.clear();
  approvalCache.set(cacheKey, {
    allowed,
    // Keep revocations reasonably prompt without querying once per image.
    expiresAt: Date.now() + (allowed ? 60_000 : 10_000)
  });
  return allowed;
}

function readSessionCookie(request) {
  const header = request.headers.get('cookie') || '';
  const match = header.match(/(?:^|;\s*)__Host-study-hub-session=([A-Za-z0-9._-]+)/);
  return match ? match[1] : null;
}

function cookieFor(token, maxAge) {
  return COOKIE_NAME + '=' + token + '; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=' + maxAge;
}

function forbidden(message, status) {
  return new Response(message, {
    status,
    headers: { 'cache-control': 'no-store', 'content-type': 'text/plain; charset=utf-8' }
  });
}

async function handleSession(request, url) {
  if (request.method !== 'POST') return forbidden('Method not allowed', 405);
  if (request.headers.get('origin') !== url.origin) return forbidden('Invalid origin', 403);
  const authorization = request.headers.get('authorization') || '';
  const match = authorization.match(/^Bearer ([A-Za-z0-9._-]+)$/);
  if (!match) return forbidden('Missing access token', 401);
  const token = match[1];
  const claims = await verifyAccessToken(token);
  if (!claims) return forbidden('Invalid access token', 401);
  try {
    if (!await checkApproval(token, claims)) return forbidden('Account not approved', 403);
  } catch (error) {
    console.error('Study Hub approval lookup failed', error);
    return forbidden('Access check unavailable', 503);
  }
  const maxAge = Math.min(3600, claims.exp - Math.floor(Date.now() / 1000));
  return new Response(null, {
    status: 204,
    headers: {
      'set-cookie': cookieFor(token, maxAge),
      'cache-control': 'no-store'
    }
  });
}

function handleLogout(request, url) {
  if (request.method !== 'POST') return forbidden('Method not allowed', 405);
  if (request.headers.get('origin') !== url.origin) return forbidden('Invalid origin', 403);
  return new Response(null, {
    status: 204,
    headers: {
      'set-cookie': cookieFor('', 0),
      'cache-control': 'no-store'
    }
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === '/api/session') return handleSession(request, url);
    if (url.pathname === '/api/logout') return handleLogout(request, url);
    if (url.pathname.startsWith('/api/')) return forbidden('Not found', 404);
    if (request.method !== 'GET' && request.method !== 'HEAD')
      return forbidden('Method not allowed', 405);
    if (isPublicPath(url.pathname)) return env.ASSETS.fetch(request);

    const token = readSessionCookie(request);
    const claims = await verifyAccessToken(token);
    if (!claims) {
      if (request.mode === 'navigate' || request.headers.get('sec-fetch-mode') === 'navigate' ||
          (request.headers.get('accept') || '').includes('text/html')) {
        const destination = new URL('/', url);
        destination.searchParams.set('return', url.pathname + url.search);
        return Response.redirect(destination, 302);
      }
      return forbidden('Sign in to Study Hub to view this file.', 401);
    }
    try {
      if (!await checkApproval(token, claims))
        return forbidden('Account not approved', 403);
    } catch (error) {
      console.error('Study Hub approval lookup failed', error);
      return forbidden('Access check unavailable', 503);
    }
    // This review is intentionally unreleased for other students.
    if (url.pathname === '/OMK/Cardio/summative/OMK_2A_Cardio_Summative_Objective_Review.html' &&
        claims.email.toLowerCase() !== 'jmehta@une.edu') {
      return forbidden('This review is not available yet.', 403);
    }
    const asset = await env.ASSETS.fetch(request);
    const headers = new Headers(asset.headers);
    headers.set('cache-control', 'private, no-store');
    headers.set('x-content-type-options', 'nosniff');
    const response = new Response(asset.body, {
      status: asset.status,
      statusText: asset.statusText,
      headers
    });
    return response;
  }
};
