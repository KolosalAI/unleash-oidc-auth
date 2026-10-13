#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# End-to-end test of ../server.mjs against a fake OIDC provider (stub-oidc.mjs). Run it after every change to the hook
# and after every UNLEASH_IMAGE_VERSION bump (the hook imports an internal Unleash module path).
#   bash test/smoke.sh     (needs docker + curl; uses ports 14242 and 19000)
set -uo pipefail
cd "$(dirname "$0")"

U=http://localhost:14242
ADMIN='*:*.test-admin-token-000000000000000000000000000000'
CLIENT='default:development.test-client-token-0000000000000000000000'
FRONTEND='default:development.test-frontend-token-00000000000000000000'
# Unleash only sets the Secure session cookie when it believes the request was HTTPS (it is behind Traefik in prod).
XFP=(-H 'X-Forwarded-Proto: https')
fail=0
tmp="$(mktemp -d)"
cleanup() { docker compose -f docker-compose.test.yml down -v >/dev/null 2>&1; rm -rf "$tmp"; }
trap cleanup EXIT

check() { # check NAME EXPECTED ACTUAL
  if [ "$2" = "$3" ]; then echo "ok   $1"; else echo "FAIL $1 (expected '$2', got '$3')"; fail=1; fi
}
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
location() { grep -i '^location:' | tr -d '\r' | sed 's/^[Ll]ocation: //'; }
wait_ready() {
  for _ in $(seq 1 60); do [ "$(code "$U/health")" = 200 ] && return 0; sleep 2; done
  echo "FAIL unleash did not become healthy"; docker compose -f docker-compose.test.yml logs unleash | tail -30; exit 1
}

# login_flow JAR [authorize-extras...] -> prints the callback HTTP status; the callback URL and its Location header
# are left in $tmp/cb_url and $tmp/cb_loc (it runs in a subshell, so no variables).
login_flow() {
  local jar="$1"; shift
  local url
  url="$(curl -s -i -c "$jar" -b "$jar" "${XFP[@]}" "$U/auth/zitadel/login${LOGIN_QUERY:-}" | location)"
  [ -n "$url" ] || { echo "no-redirect"; return; }
  curl -s -i "${url}$*" | location > "$tmp/cb_url"
  curl -s -i -c "$jar" -b "$jar" "${XFP[@]}" "$(cat "$tmp/cb_url")" > "$tmp/callback.out"
  location < "$tmp/callback.out" > "$tmp/cb_loc"
  head -1 "$tmp/callback.out" | awk '{print $2}'
}

echo "== build + start"
docker compose -f docker-compose.test.yml up -d --build >/dev/null 2>&1 || { echo "FAIL compose up"; exit 1; }
wait_ready

echo "== token APIs are untouched and need no login"
check "health" 200 "$(code "$U/health")"
check "client API + client token" 200 "$(code -H "Authorization: $CLIENT" "$U/api/client/features")"
check "frontend API + frontend token" 200 "$(code -H "Authorization: $FRONTEND" "$U/api/frontend")"
check "client API without token" 401 "$(code "$U/api/client/features")"
check "admin API + admin token" 200 "$(code -H "Authorization: $ADMIN" "$U/api/admin/projects")"

echo "== unauthenticated UI/admin API"
body="$(curl -s "$U/api/admin/projects")"
check "admin API without login" 401 "$(code "$U/api/admin/projects")"
check "401 body type" custom "$(echo "$body" | sed -n 's/.*"type":"\([^"]*\)".*/\1/p')"
check "401 body path" /auth/zitadel/login "$(echo "$body" | sed -n 's/.*"path":"\([^"]*\)".*/\1/p')"

echo "== happy path"
jar="$tmp/ok.jar"
check "callback status" 302 "$(login_flow "$jar" '&test_email=Tester@Example.com&test_name=Tester')"
check "callback redirects home" / "$(cat "$tmp/cb_loc")"
check "session reaches admin API" 200 "$(code -b "$jar" "${XFP[@]}" "$U/api/admin/projects")"
user="$(curl -s -b "$jar" "${XFP[@]}" "$U/api/admin/user")"
check "session user is the e-mail (lower-cased)" tester@example.com "$(echo "$user" | sed -n 's/.*"email":"\([^"]*\)".*/\1/p')"
roles="$(curl -s -H "Authorization: $ADMIN" "$U/api/admin/user-admin")"
check "user was created as Admin (rootRole 1)" 1 "$(echo "$roles" | tr '{' '\n' | grep 'tester@example.com' | sed -n 's/.*"rootRole":\([0-9]*\).*/\1/p')"
cookie_line="$(grep -i 'unleash-session' "$jar" | head -1)"
check "session cookie is HttpOnly" 1 "$(echo "$cookie_line" | grep -c '^#HttpOnly_')"
check "session cookie is Secure" TRUE "$(echo "$cookie_line" | awk -F'	' '{print $4}')"
check "replaying the callback is refused" 403 "$(curl -s -o /dev/null -w '%{http_code}' -b "$jar" -c "$jar" "${XFP[@]}" "$(cat "$tmp/cb_url")")"

echo "== refusals"
check "foreign e-mail domain" 403 "$(login_flow "$tmp/a.jar" '&test_email=eve@evil.example')"
check "unverified e-mail" 403 "$(login_flow "$tmp/b.jar" '&test_email=tester@example.com&test_verified=false')"
check "state mismatch" 403 "$(login_flow "$tmp/c.jar" '&test_email=tester@example.com&test_state=forged')"
check "provider error" 403 "$(login_flow "$tmp/d.jar" '&test_error=access_denied')"
check "no session after refusal" 401 "$(code -b "$tmp/a.jar" "$U/api/admin/projects")"
check "callback without a pending login" 403 "$(code "${XFP[@]}" "$U/auth/zitadel/callback?code=x&state=y")"

echo "== audit lines reach docker logs (Unleash itself logs at error level only)"
logs="$(docker compose -f docker-compose.test.yml logs unleash 2>&1)"
check "login ok is logged" 1 "$(echo "$logs" | grep -c 'Zitadel login ok for tester@example.com' | awk '{ print ($1 > 0) }')"
check "denied login is logged" 1 "$(echo "$logs" | grep -c 'Zitadel login denied: e-mail domain not allowed' | awk '{ print ($1 > 0) }')"

echo "== open redirect is blocked"
LOGIN_QUERY='?redirect=//evil.example' login_flow "$tmp/e.jar" '&test_email=tester@example.com' >/dev/null
check "protocol-relative redirect falls back to /" / "$(cat "$tmp/cb_loc")"
LOGIN_QUERY='?redirect=/ui/projects' login_flow "$tmp/f.jar" '&test_email=tester@example.com' >/dev/null
check "same-site redirect is honoured" /ui/projects "$(cat "$tmp/cb_loc")"

echo "== fallback: incomplete OIDC settings start stock local login (no lock-out)"
TEST_OIDC_CLIENT_ID= docker compose -f docker-compose.test.yml up -d unleash >/dev/null 2>&1
wait_ready
check "stock password login works" 200 "$(code -X POST -H 'Content-Type: application/json' -d '{"username":"localadmin","password":"localadmin123"}' "$U/auth/simple/login")"
check "token APIs still work" 200 "$(code -H "Authorization: $CLIENT" "$U/api/client/features")"

[ "$fail" = 0 ] && echo "ALL OK" || echo "FAILURES"
exit "$fail"
