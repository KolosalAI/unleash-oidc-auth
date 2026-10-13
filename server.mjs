// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Zitadel (OIDC) login for the Unleash admin UI. Unleash's own SSO is Enterprise-only; this replaces the
// local login with a custom auth hook (`authentication.type = 'custom'`). Extends unleash-server (AGPL-3.0-or-later),
// so this file is licensed the same way — see ./README.md for the source/licence notes.
//
// Flow: Authorization Code + PKCE (public client, no client secret) -> token endpoint -> userinfo -> verified,
// allowed e-mail -> userService.loginUserSSO() as Admin -> Unleash session. We read the e-mail from the userinfo
// endpoint instead of verifying an ID token: the code is exchanged straight with Zitadel over TLS (OIDC Core 3.1.3.7),
// PKCE + `state` bind the browser round-trip, so no JWT/signature handling (and no nonce, which only protects ID tokens).
//
// API-token traffic (/api/client, /api/frontend, the admin token) is authenticated by Unleash before this hook runs
// and is untouched. If the OIDC_* settings are incomplete the server starts with Unleash's stock behaviour
// (AUTH_TYPE, default local login) so a missing secret can never lock the UI out.
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

import { start } from './dist/lib/server-impl.js';

const env = (name) => (process.env[name] || '').trim();

const oidc = {
  issuer: env('OIDC_ISSUER').replace(/\/+$/, ''),
  clientId: env('OIDC_CLIENT_ID'),
  redirectUri: env('OIDC_REDIRECT_URI'),
  // Defence in depth on top of Zitadel's "Check authorization on authentication". Empty = no domain restriction.
  allowedDomain: env('OIDC_ALLOWED_EMAIL_DOMAIN').toLowerCase().replace(/^@/, ''),
};
const enabled = Boolean(oidc.issuer && oidc.clientId && oidc.redirectUri);

const PENDING_TTL_MS = 10 * 60 * 1000;
const FETCH_TIMEOUT_MS = 10_000;

const b64url = (buf) => buf.toString('base64url');
const sha256 = (value) => createHash('sha256').update(value).digest();
const safeEqual = (a, b) => {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  return x.length === y.length && timingSafeEqual(x, y);
};

// Only same-site relative paths; blocks `//evil.example` and `/\evil.example` open redirects.
const safeReturnTo = (value, fallback) =>
  typeof value === 'string' && /^\/(?![/\\])/.test(value) ? value : fallback;

const fetchJson = async (url, init = {}) => {
  const response = await fetch(url, { ...init, signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
  if (!response.ok) {
    throw new Error(`${init.method || 'GET'} ${new URL(url).pathname} -> HTTP ${response.status}`);
  }
  return response.json();
};

class LoginDenied extends Error {}

// Plain stdout/stderr lines, deliberately not config.getLogger(): Unleash defaults to LOG_LEVEL=error, which would hide
// the "login ok" / "login denied" audit lines. They end up in docker logs -> journald like every other service.
const logger = {
  info: (message) => console.log(`[zitadel-auth] ${message}`),
  warn: (message) => console.warn(`[zitadel-auth] ${message}`),
  error: (message) => console.error(`[zitadel-auth] ${message}`),
};

const sessionCall = (fn) => new Promise((resolve, reject) => fn((err) => (err ? reject(err) : resolve())));

let discovery;
const getDiscovery = () => {
  discovery ??= fetchJson(`${oidc.issuer}/.well-known/openid-configuration`)
    .then((doc) => {
      if (String(doc.issuer || '').replace(/\/+$/, '') !== oidc.issuer) {
        throw new Error('discovery issuer does not match OIDC_ISSUER');
      }
      for (const key of ['authorization_endpoint', 'token_endpoint', 'userinfo_endpoint']) {
        if (!doc[key]) throw new Error(`discovery document has no ${key}`);
      }
      return doc;
    })
    .catch((err) => {
      discovery = undefined; // retry on the next login instead of caching the failure
      throw err;
    });
  return discovery;
};

function customAuthHandler(app, config, services) {
  const base = config.server.baseUriPath || '';
  const { userService } = services;
  const loginPath = `${base}/auth/zitadel/login`;

  app.get(loginPath, async (req, res) => {
    try {
      const doc = await getDiscovery();
      const state = b64url(randomBytes(32));
      const verifier = b64url(randomBytes(48));
      req.session.oidc = {
        state,
        verifier,
        returnTo: safeReturnTo(req.query.redirect, `${base}/`),
        at: Date.now(),
      };
      const url = new URL(doc.authorization_endpoint);
      url.searchParams.set('response_type', 'code');
      url.searchParams.set('client_id', oidc.clientId);
      url.searchParams.set('redirect_uri', oidc.redirectUri);
      url.searchParams.set('scope', 'openid email profile');
      url.searchParams.set('state', state);
      url.searchParams.set('code_challenge', b64url(sha256(verifier)));
      url.searchParams.set('code_challenge_method', 'S256');
      await sessionCall((cb) => req.session.save(cb));
      res.redirect(url.toString());
    } catch (err) {
      logger.error(`could not start Zitadel login: ${err.message}`);
      res.status(502).type('text/plain').send('Sign-in is temporarily unavailable.');
    }
  });

  app.get(`${base}/auth/zitadel/callback`, async (req, res) => {
    const pending = req.session?.oidc;
    if (req.session) delete req.session.oidc; // single use, even when the login fails
    try {
      if (req.query.error) throw new LoginDenied(`provider returned error=${String(req.query.error).slice(0, 80)}`);
      if (!pending || Date.now() - pending.at > PENDING_TTL_MS) throw new LoginDenied('no pending login (expired?)');
      if (typeof req.query.state !== 'string' || !safeEqual(req.query.state, pending.state)) {
        throw new LoginDenied('state mismatch');
      }
      if (typeof req.query.code !== 'string' || !req.query.code) throw new LoginDenied('missing code');

      const doc = await getDiscovery();
      const tokens = await fetchJson(doc.token_endpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: req.query.code,
          redirect_uri: oidc.redirectUri,
          client_id: oidc.clientId,
          code_verifier: pending.verifier,
        }),
      });
      if (!tokens.access_token) throw new Error('token response has no access_token');

      const info = await fetchJson(doc.userinfo_endpoint, {
        headers: { authorization: `Bearer ${tokens.access_token}`, accept: 'application/json' },
      });
      const email = String(info.email || '').trim().toLowerCase();
      if (!email || info.email_verified !== true) throw new LoginDenied('e-mail missing or not verified');
      if (oidc.allowedDomain && !email.endsWith(`@${oidc.allowedDomain}`)) {
        throw new LoginDenied(`e-mail domain not allowed (${email.split('@')[1] || '?'})`);
      }

      // Everyone Zitadel lets in is an Admin (access is controlled by the Zitadel project grant).
      const user = await userService.loginUserSSO({
        email,
        name: info.name || undefined,
        rootRole: 'Admin',
        autoCreate: true,
      });
      await sessionCall((cb) => req.session.regenerate(cb)); // new session id on login (fixation)
      req.session.user = user;
      await sessionCall((cb) => req.session.save(cb));
      logger.info(`Zitadel login ok for ${email}`);
      res.redirect(safeReturnTo(pending?.returnTo, `${base}/`));
    } catch (err) {
      if (err instanceof LoginDenied) {
        logger.warn(`Zitadel login denied: ${err.message}`);
        res.status(403).type('text/plain').send('Sign-in was not allowed for this account.');
      } else {
        logger.error(`Zitadel login failed: ${err.message}`);
        res.status(502).type('text/plain').send('Sign-in is temporarily unavailable.');
      }
    }
  });

  // Same shape as Unleash's own demo auth: API-token users are already set on req.user by earlier middleware.
  app.use(`${base}/api/admin/`, (req, _res, next) => {
    if (!req.user && req.session?.user?.email) req.user = req.session.user;
    next();
  });
  app.use(`${base}/api`, (req, res, next) => {
    if (req.user) return next();
    // type 'custom' makes the UI render this message and a "Sign In" button linking to `path`.
    return res
      .status(401)
      .json({
        type: 'custom',
        path: loginPath,
        message: 'Sign in with your Zitadel account to use Unleash.',
        defaultHidden: false,
      })
      .end();
  });
}

if (enabled) {
  await start({ authentication: { type: 'custom', customAuthHandler } }).catch((err) => {
    console.error(err);
    process.exit(1);
  });
} else {
  console.warn('[unleash-oidc-auth] OIDC_ISSUER/OIDC_CLIENT_ID/OIDC_REDIRECT_URI not all set: starting stock Unleash auth (AUTH_TYPE).');
  await start().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
