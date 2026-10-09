import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import worker from '../worker/index.js';

const origin = 'https://second-year.mehtajeeval1.workers.dev';
const issuer = 'https://ydwbzeabeiythxsgahmz.supabase.co/auth/v1';
const keyPair = await webcrypto.subtle.generateKey(
  { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']
);
const publicKey = await webcrypto.subtle.exportKey('jwk', keyPair.publicKey);
publicKey.kid = 'study-hub-test-key';
publicKey.alg = 'ES256';
const encode = value => Buffer.from(value).toString('base64url');
const assets = {
  fetch: async request => new Response('course content', {
    status: 200,
    headers: { 'content-type': request.url.endsWith('.html') ? 'text/html' : 'image/png' }
  })
};

async function tokenFor(overrides = {}) {
  const claims = {
    iss: issuer,
    aud: 'authenticated',
    sub: '7aa5a4dc-a259-4b33-8add-27236f7331b7',
    email: 'student@une.edu',
    app_metadata: { provider: 'google' },
    exp: Math.floor(Date.now() / 1000) + 3600,
    ...overrides
  };
  const header = encode(JSON.stringify({ alg: 'ES256', kid: publicKey.kid }));
  const payload = encode(JSON.stringify(claims));
  const data = header + '.' + payload;
  const signature = await webcrypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    keyPair.privateKey,
    Buffer.from(data)
  );
  return data + '.' + encode(Buffer.from(signature));
}

const originalFetch = globalThis.fetch;
globalThis.fetch = async url => {
  if (String(url).endsWith('/.well-known/jwks.json'))
    return Response.json({ keys: [publicKey] });
  if (String(url).includes('/study_hub_approved_emails'))
    return Response.json(String(url).includes('outsider%40une.edu') ? [] : [{ email: 'student@une.edu' }]);
  throw new Error('Unexpected network request');
};

test.after(() => { globalThis.fetch = originalFetch; });

test('anonymous course navigation returns to Study Hub login', async () => {
  const response = await worker.fetch(new Request(origin + '/OMK/Cardio/Week%2013/Notes/Quiz/index.html', {
    headers: { accept: 'text/html' }
  }), { ASSETS: assets });
  assert.equal(response.status, 302);
  assert.equal(new URL(response.headers.get('location')).searchParams.get('return'),
    '/OMK/Cardio/Week%2013/Notes/Quiz/index.html');
});

test('anonymous asset request is denied without a redirect', async () => {
  const response = await worker.fetch(new Request(origin + '/Neuro/week1/image.png'), { ASSETS: assets });
  assert.equal(response.status, 401);
});

test('approved Google student can open course content after session exchange', async () => {
  const token = await tokenFor();
  const issue = await worker.fetch(new Request(origin + '/api/session', {
    method: 'POST',
    headers: { origin, authorization: 'Bearer ' + token }
  }), { ASSETS: assets });
  assert.equal(issue.status, 204);
  assert.match(issue.headers.get('set-cookie'), /HttpOnly; SameSite=Lax/);
  const cookie = issue.headers.get('set-cookie').split(';')[0];
  const course = await worker.fetch(new Request(origin + '/OMK/Cardio/Week%2013/Notes/Quiz/index.html', {
    headers: { cookie, accept: 'text/html' }
  }), { ASSETS: assets });
  assert.equal(course.status, 200);
  assert.equal(course.headers.get('cache-control'), 'private, no-store');
  assert.equal(await course.text(), 'course content');
});

test('expired, tampered and non-Google tokens cannot access course content', async () => {
  const expired = await tokenFor({ exp: Math.floor(Date.now() / 1000) - 1 });
  const password = await tokenFor({ app_metadata: { provider: 'email' } });
  const valid = await tokenFor();
  const parts = valid.split('.');
  const tampered = parts[0] + '.' + parts[1] + '.' + (parts[2][0] === 'A' ? 'B' : 'A') + parts[2].slice(1);
  for (const token of [expired, password, tampered]) {
    const response = await worker.fetch(new Request(origin + '/Neuro/week1/notes.html', {
      headers: { cookie: '__Host-study-hub-session=' + token, accept: 'application/octet-stream' }
    }), { ASSETS: assets });
    assert.equal(response.status, 401);
  }
});

test('a signed UNE token without approval cannot bypass the cookie setup', async () => {
  const token = await tokenFor({
    sub: '11111111-1111-4111-8111-111111111111',
    email: 'outsider@une.edu'
  });
  const response = await worker.fetch(new Request(origin + '/Neuro/week1/notes.html', {
    headers: { cookie: '__Host-study-hub-session=' + token }
  }), { ASSETS: assets });
  assert.equal(response.status, 403);
});

test('unreleased Cardio review remains restricted', async () => {
  const token = await tokenFor();
  const response = await worker.fetch(new Request(
    origin + '/OMK/Cardio/summative/OMK_2A_Cardio_Summative_Objective_Review.html', {
      headers: { cookie: '__Host-study-hub-session=' + token }
    }
  ), { ASSETS: assets });
  assert.equal(response.status, 403);
});

test('public login page and assets remain available', async () => {
  for (const path of ['/', '/index.html', '/assets/study-hub-config.js']) {
    const response = await worker.fetch(new Request(origin + path), { ASSETS: assets });
    assert.equal(response.status, 200);
  }
});
