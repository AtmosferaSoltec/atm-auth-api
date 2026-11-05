#!/usr/bin/env bash
# Seeds a LOCAL atm-auth-api with a test user that can sign in to every system, in two fictitious companies.
#
#   scripts/dev-seed.sh                      # against http://localhost:3130
#   AUTH_URL=http://localhost:8080 scripts/dev-seed.sh
#
# Idempotent: running it again changes nothing. It refuses to run against anything that is not localhost, and the
# user it creates must never exist in production. See "Local test user" in README.md.
set -euo pipefail
cd "$(dirname "$0")/.."

AUTH_URL="${AUTH_URL:-http://localhost:3130}"
case "$AUTH_URL" in
  http://localhost:*|http://127.0.0.1:*) ;;
  *) echo "Refusing to seed $AUTH_URL: this script is for local development only." >&2; exit 1 ;;
esac

# Superadmin credentials of the local instance, read from .env (never printed).
ADMIN_USER="${ADMIN_USER:-$(grep -E '^ADMIN_USER=' .env | head -1 | cut -d= -f2- | tr -d "'\"")}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-$(grep -E '^ADMIN_PASSWORD=' .env | head -1 | cut -d= -f2- | tr -d "'\"")}"

# The test user. Public on purpose: it only exists on developer machines.
TEST_DNI="99999999"
TEST_NAME="Usuario de Pruebas"
TEST_PASSWORD="Local-Test-2026"

# Fictitious companies (RUC, legal name, trade name).
TENANTS=(
  "20999999991|Bodega de Pruebas S.A.C.|Bodega de Pruebas"
  "20999999992|Empresa de Pruebas S.A.C.|Empresa de Pruebas"
)

api() { # api METHOD PATH [JSON_BODY]
  local method="$1" path="$2" body="${3:-}"
  local args=(-sS -X "$method" "$AUTH_URL$path" -H "Content-Type: application/json")
  [ -n "${TOKEN:-}" ] && args+=(-H "Authorization: Bearer $TOKEN")
  [ -n "$body" ] && args+=(-d "$body")
  curl "${args[@]}"
}

TOKEN=$(api POST /v1/admin/login "$(jq -nc --arg d "$ADMIN_USER" --arg p "$ADMIN_PASSWORD" '{dni:$d,password:$p}')" | jq -r '.access_token // empty')
[ -n "$TOKEN" ] || { echo "Superadmin login failed at $AUTH_URL (is the API running? are ADMIN_USER/ADMIN_PASSWORD in .env right?)" >&2; exit 1; }

list() { api GET "$1" | jq -c '(.items // .)'; }

SYSTEMS=$(list /v1/admin/systems)

# --- user -------------------------------------------------------------------------------------------------------
USER_ID=$(list /v1/admin/users | jq -r --arg d "$TEST_DNI" '.[] | select(.dni==$d) | .id' | head -1)
if [ -z "$USER_ID" ]; then
  USER_ID=$(api POST /v1/admin/users "$(jq -nc --arg d "$TEST_DNI" --arg n "$TEST_NAME" '{dni:$d,full_name:$n}')" | jq -r '.id')
  echo "created user $TEST_DNI"
fi

# New accounts start with the DNI as password and must change it; do that once so the password is a known one.
MUST_CHANGE=$(list /v1/admin/users | jq -r --arg d "$TEST_DNI" '.[] | select(.dni==$d) | .must_change_password')
if [ "$MUST_CHANGE" = "true" ]; then
  api POST /v1/password/change "$(jq -nc --arg d "$TEST_DNI" --arg p "$TEST_PASSWORD" '{dni:$d,current_password:$d,new_password:$p}')" >/dev/null
  echo "set the test password"
fi

# --- companies ----------------------------------------------------------------------------------------------------
TENANT_IDS=()
for entry in "${TENANTS[@]}"; do
  IFS='|' read -r ruc legal trade <<<"$entry"
  id=$(list /v1/admin/tenants | jq -r --arg r "$ruc" '.[] | select(.ruc==$r) | .id' | head -1)
  if [ -z "$id" ]; then
    id=$(api POST /v1/admin/tenants "$(jq -nc --arg r "$ruc" --arg l "$legal" --arg t "$trade" '{ruc:$r,legal_name:$l,trade_name:$t}')" | jq -r '.id')
    echo "created company $trade"
  fi
  TENANT_IDS+=("$id")
done

# --- access: every system, every company, role admin ---------------------------------------------------------------
ACCESS=$(api GET "/v1/admin/users/$USER_ID/access" | jq -c '(.items // .)')

while read -r system; do
  sid=$(jq -r '.id' <<<"$system"); code=$(jq -r '.code' <<<"$system")
  if [ "$(jq -r '.personal // false' <<<"$system")" = "true" ] || [ "$code" = "orbita" ]; then
    scope=("")           # personal systems have no company
  else
    scope=("${TENANT_IDS[@]}")
  fi
  for tid in "${scope[@]}"; do
    if [ -n "$tid" ]; then
      api GET "/v1/admin/tenants/$tid" | jq -e --arg s "$sid" '.systems[]? | select(.id==$s)' >/dev/null \
        || { api POST "/v1/admin/tenants/$tid/systems" "$(jq -nc --arg s "$sid" '{system_id:$s}')" >/dev/null; echo "enabled $code for company $tid"; }
    fi
    if ! jq -e --arg s "$sid" --arg t "$tid" '.[] | select(.system_id==$s and ((.tenant_id // "")==$t))' <<<"$ACCESS" >/dev/null; then
      body=$(jq -nc --arg u "$USER_ID" --arg s "$sid" --arg t "$tid" '{user_id:$u,system_id:$s,role:"admin",manage_users:true} + (if $t=="" then {} else {tenant_id:$t} end)')
      res=$(api POST /v1/admin/access "$body")
      jq -e '.error' <<<"$res" >/dev/null 2>&1 && echo "skipped $code: $(jq -r '.error.code' <<<"$res")" || echo "granted admin in $code"
    fi
  done
done < <(jq -c '.[]' <<<"$SYSTEMS")

echo "Done. Sign in with DNI $TEST_DNI / $TEST_PASSWORD at $AUTH_URL"
