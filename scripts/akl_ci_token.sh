#!/usr/bin/env bash
# Exchange a CI OIDC/JWT token for a short-lived Akeyless token (REST POST /auth),
# so CLI commands can run with --token without storing any credential.
#   AKEYLESS_API          default https://api.akeyless.io (or https://<gw>:8000/api/v2)
#   AKEYLESS_ACCESS_ID    access ID of the CI OAuth2/JWT auth method (bootstrap output)
#   CI_JWT                the CI-issued JWT
# Prints the Akeyless token on stdout.
set -euo pipefail
api="${AKEYLESS_API:-https://api.akeyless.io}"
: "${AKEYLESS_ACCESS_ID:?set AKEYLESS_ACCESS_ID}" "${CI_JWT:?set CI_JWT}"
body="$(jq -n --arg id "$AKEYLESS_ACCESS_ID" --arg jwt "$CI_JWT" '{"access-id":$id,"access-type":"jwt","jwt":$jwt}')"
resp="$(curl -sS --fail-with-body -X POST "${api%/}/auth" -H 'Content-Type: application/json' -d "$body")"
token="$(jq -r '.token // empty' <<<"$resp")"
[ -n "$token" ] || { echo "authentication failed: $resp" >&2; exit 1; }
printf '%s\n' "$token"
