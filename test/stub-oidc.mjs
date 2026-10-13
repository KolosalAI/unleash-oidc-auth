// SPDX-License-Identifier: AGPL-3.0-or-later
// Minimal fake OIDC provider (discovery, authorize, token, userinfo) for testing ../server.mjs without Zitadel.
// The test harness drives /authorize by hand and picks the identity with test_* query parameters.
import { createHash, randomBytes } from 'node:crypto';
import http from 'node:http';

const PORT = Number(process.env.PORT || 9000);
const ISSUER = process.env.ISSUER || `http://oidc-stub:${PORT}`; // what the Unleash container calls
const PUBLIC = process.env.PUBLIC_URL || `http://localhost:${PORT}`; // what the test's curl calls
const CLIENT_ID = process.env.CLIENT_ID || 'test-client';

const codes = new Map(); // code -> { challenge, redirectUri, identity }
const tokens = new Map(); // access_token -> identity
const b64url = (buf) => buf.toString('base64url');

const send = (res, status, body, headers = {}) => {
  res.writeHead(status, { 'content-type': 'application/json', ...headers });
  res.end(typeof body === 'string' ? body : JSON.stringify(body));
};

const readForm = (req) =>
  new Promise((resolve) => {
    let raw = '';
    req.on('data', (chunk) => (raw += chunk));
    req.on('end', () => resolve(new URLSearchParams(raw)));
  });

http
  .createServer(async (req, res) => {
    const url = new URL(req.url, PUBLIC);
    if (url.pathname === '/.well-known/openid-configuration') {
      return send(res, 200, {
        issuer: ISSUER,
        authorization_endpoint: `${PUBLIC}/authorize`,
        token_endpoint: `${ISSUER}/token`,
        userinfo_endpoint: `${ISSUER}/userinfo`,
      });
    }
    if (url.pathname === '/authorize') {
      const q = url.searchParams;
      if (q.get('client_id') !== CLIENT_ID || q.get('response_type') !== 'code' || q.get('code_challenge_method') !== 'S256') {
        return send(res, 400, { error: 'invalid_request' });
      }
      const target = new URL(q.get('redirect_uri'));
      if (q.get('test_error')) {
        target.searchParams.set('error', q.get('test_error'));
        target.searchParams.set('state', q.get('state') || '');
        return send(res, 302, '', { location: target.toString() });
      }
      const code = b64url(randomBytes(16));
      codes.set(code, {
        challenge: q.get('code_challenge'),
        redirectUri: q.get('redirect_uri'),
        identity: {
          sub: `sub-${q.get('test_email')}`,
          email: q.get('test_email'),
          email_verified: q.get('test_verified') !== 'false',
          name: q.get('test_name') || 'Test User',
        },
      });
      target.searchParams.set('code', code);
      target.searchParams.set('state', q.get('test_state') || q.get('state') || '');
      return send(res, 302, '', { location: target.toString() });
    }
    if (url.pathname === '/token' && req.method === 'POST') {
      const form = await readForm(req);
      const entry = codes.get(form.get('code'));
      codes.delete(form.get('code')); // single use
      const challenge = createHash('sha256').update(form.get('code_verifier') || '').digest('base64url');
      if (
        !entry ||
        form.get('grant_type') !== 'authorization_code' ||
        form.get('client_id') !== CLIENT_ID ||
        form.get('redirect_uri') !== entry.redirectUri ||
        challenge !== entry.challenge ||
        form.get('client_secret')
      ) {
        return send(res, 400, { error: 'invalid_grant' });
      }
      const accessToken = b64url(randomBytes(24));
      tokens.set(accessToken, entry.identity);
      return send(res, 200, { access_token: accessToken, token_type: 'Bearer', expires_in: 300 });
    }
    if (url.pathname === '/userinfo') {
      const identity = tokens.get((req.headers.authorization || '').replace(/^Bearer /, ''));
      return identity ? send(res, 200, identity) : send(res, 401, { error: 'invalid_token' });
    }
    return send(res, 404, { error: 'not_found' });
  })
  .listen(PORT, () => console.log(`stub OIDC provider on :${PORT} (issuer ${ISSUER})`));
