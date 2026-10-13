# unleash-oidc-auth

[Unleash](https://github.com/Unleash/unleash) with **OIDC single sign-on for the admin UI**, built on Unleash's
documented `custom` authentication option. Unleash's own SSO is an Enterprise feature; this adds a small auth hook
([`server.mjs`](server.mjs)) on top of the official `unleashorg/unleash-server` image so people can sign in through an
OIDC provider (we use [Zitadel](https://zitadel.com); any provider with standard OIDC discovery and a `userinfo`
endpoint should work).

This project is not affiliated with or endorsed by Unleash.

## Licence and source (AGPL)

`unleash-server` is **AGPL-3.0-or-later**. This image modifies it, so everything here is licensed the same way
([`LICENSE`](LICENSE)), and **this repository is the complete corresponding source of the changes** (`Dockerfile`,
`server.mjs`). Upstream licence notices inside the image are untouched. Built images carry the labels
`org.opencontainers.image.source` (this repository) and `org.opencontainers.image.revision` (the commit they were built
from).

## What it does

| Request | Result |
| --- | --- |
| `/api/client/*`, `/api/frontend/*`, any API token | Unchanged: token auth, no login |
| UI or `/api/admin/*` without a session | `401 {type:"custom", path:"/auth/zitadel/login"}`, so the UI shows a **Sign In** button |
| `/auth/zitadel/login` | Redirect to the provider (state + PKCE S256 kept in the Unleash session) |
| `/auth/zitadel/callback` | Code, then token endpoint, then `userinfo`; requires a **verified** e-mail (optionally in `OIDC_ALLOWED_EMAIL_DOMAIN`); finds or creates the user as **Admin**; new session id; redirect (same-site paths only) |

- **Authorization Code + PKCE, public client, no client secret.** The e-mail is read from the `userinfo` endpoint: the
  code is exchanged directly with the provider over TLS (OIDC Core 3.1.3.7), so no ID-token or signature handling is
  needed and the hook has no dependencies (Node built-ins and the Unleash session only).
- **Everyone the provider lets in is an Admin.** Control who may sign in at the provider (for Zitadel: a project grant
  with "Check authorization on authentication"), and optionally with `OIDC_ALLOWED_EMAIL_DOMAIN`.
- **Fallback:** if `OIDC_ISSUER`, `OIDC_CLIENT_ID` or `OIDC_REDIRECT_URI` is missing, the container starts **stock
  Unleash auth** (`AUTH_TYPE`, local login) so a missing setting can never lock the UI out.
- **Audit lines** (`[zitadel-auth] Zitadel login ok for ...` / `login denied: ...`) go to stdout/stderr regardless of
  Unleash's `LOG_LEVEL`.
- **Logout** ends only the Unleash session; the provider session stays, so *Sign In* afterwards signs straight back in
  (normal SSO behavior).

## Configuration (environment)

| Variable | Meaning |
| --- | --- |
| `OIDC_ISSUER` | Provider issuer URL, e.g. `https://zitadel.example.com` (must match the discovery document's `issuer`) |
| `OIDC_CLIENT_ID` | Client ID of a **PKCE public client** (Zitadel: web app, auth method `None`) |
| `OIDC_REDIRECT_URI` | `https://<your-unleash-host>/auth/zitadel/callback`, registered exactly at the provider |
| `OIDC_ALLOWED_EMAIL_DOMAIN` | Optional: only e-mails in this domain may sign in; empty means no extra restriction |
| `SECURE_HEADERS=true` | Recommended behind TLS: Secure session cookie (set by Unleash) |

All the usual Unleash settings (`DATABASE_URL`, `INIT_*_API_TOKENS`, ...) work as documented upstream.
Zitadel scopes: `openid email profile`.

## Build

```sh
docker build --build-arg UNLEASH_IMAGE_VERSION=8.2.0 --build-arg SOURCE_REVISION="$(git rev-parse HEAD)" -t unleash-oidc-auth .
```

Single stage, no `npm`, so the build only pulls the pinned upstream image.

## Testing

[`test/smoke.sh`](test/smoke.sh) builds the image, runs it against a fake OIDC provider
([`test/stub-oidc.mjs`](test/stub-oidc.mjs)) and checks the login flow, the refusals (wrong domain, unverified e-mail,
forged state, replay, provider error, open redirect), that token APIs are unaffected, that the audit lines are logged
and that the no-OIDC fallback works. Run it after every change here **and after every Unleash version bump**: the hook
imports `./dist/lib/server-impl.js`, an internal Unleash path that is not a public API.

```sh
bash test/smoke.sh   # needs docker + curl; uses ports 14242 and 19000
```

## Break-glass

If the provider is down and you need the UI: start the container without `OIDC_CLIENT_ID` (stock local login with the
admin user seeded by `UNLEASH_DEFAULT_ADMIN_USERNAME` / `UNLEASH_DEFAULT_ADMIN_PASSWORD`), or call the admin API with an
admin token from inside the container network.
