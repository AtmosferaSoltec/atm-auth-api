# ATM-Auth-API

Single source of truth for identity and access across all ATM systems. See `AGENTS.md` for the architecture and rules.

## Configuration

Environment variables (see `.env.example`):

| Variable | Default | Description |
|---|---|---|
| `APP_ENV` | `development` | `development` or `production` |
| `HTTP_ADDR` | `:8080` | Listen address |
| `DATABASE_URL` | required | PostgreSQL connection string |

## Local development

```
docker compose up -d          # PostgreSQL on localhost:5433
cp .env.example .env
```

Migrations in `migrations/` run automatically on startup.

Tests that touch PostgreSQL need `TEST_DATABASE_URL` (a database that can be wiped, for example `atm_auth_test`) and run one package at a time:

```
go test ./... -race -p 1
```

Set the superadmin in `.env` (`ADMIN_USER` and `ADMIN_PASSWORD`, at least 12 characters; the service hashes it when it starts) and generate the signing key:

```
go run ./cmd/genkey     # -> JWT_PRIVATE_KEY
```

## Run

```
go run ./cmd/api
```

## Routes

| Method | Path | Description |
|---|---|---|
| GET | `/health` | Liveness |
| GET | `/ready` | Readiness (checks the database) |
| GET | `/.well-known/jwks.json` | Public key (JWKS) other services use to validate access tokens |
| POST | `/v1/login` | User login. Body: `{"dni", "password", "system"}`. The token carries `system`, `tenant` and `app_role`. `403 no_access` if the user cannot enter that system |
| POST | `/v1/token` | Service token for a system's backend. Body: `{"client_id": <system code>, "client_secret"}`. Returns a short-lived `access_token` (role `service`, subject `system:<code>`) with no refresh token; the backend asks again when it expires. One secret per system works on every microservice, which only verify the token with the JWKS. Throttled like logins |
| POST | `/v1/admin/login` | Superadmin login. Body: `{"dni", "password"}` |
| POST | `/v1/password/change` | Body: `{"dni", "current_password", "new_password"}`. Ends all sessions; the user logs in again |
| POST | `/v1/refresh` | Rotate a refresh token. Body: `{"refresh_token"}` |
| POST | `/v1/logout` | Revoke the session. Body: `{"refresh_token"}` |
| GET | `/v1/admin/me` | Returns the authenticated superadmin (requires bearer token) |

### Superadmin API (`/v1/admin`, requires the superadmin token)

| Method | Path | Description |
|---|---|---|
| POST, GET | `/systems` | Create and list systems. Create accepts `session_mode` and `session_minutes` (persistent by default) |
| POST | `/systems/{id}/secret` | Generate (or regenerate) the system's secret. Returns `{client_id, client_secret}` once; the old secret stops working at once |
| DELETE | `/systems/{id}/secret` | Revoke the system's secret. Tokens already issued last until they expire |
| PUT | `/systems/{id}/session` | Session policy of a system. Body: `{"mode": "persistent" \| "temporary", "minutes"}`. Persistent keeps users signed in for `REFRESH_TOKEN_TTL`; temporary signs them out after `minutes` (5 to 1440) without use. Open sessions pick it up at their next refresh |
| DELETE | `/systems/{id}?confirm={code}` | Delete a system for good, with its tenant enablements, accesses and sessions. `confirm` must equal the system code or it answers `400 code_mismatch` |
| POST, GET | `/tenants` | Create and list tenants (RUC, legal name, trade name) |
| GET | `/tenants/{id}` | One tenant. Tenants (here and in the list) carry `systems`: the systems enabled for them |
| POST | `/tenants/{id}/systems` | Enable a system for a tenant. Body: `{"system_id"}` |
| DELETE | `/tenants/{id}/systems/{system_id}` | Disable a system for a tenant. Removes the access its users had in that system (accounts stay) |
| POST, GET | `/users` | Create and list users. Body: `{dni, full_name}`. The DNI is always the initial password and must be changed at first login; a `password` field is rejected |
| POST | `/users/{id}/reset-password` | Back to the DNI, change required, sessions ended |
| PUT | `/users/{id}/status` | `{"status": "active" \| "disabled"}`. Disabling ends all sessions |
| POST | `/access` | Give a user access: `{user_id, system_id, tenant_id, role, manage_users}` |
| GET | `/users/{id}/access` | A user's accesses (with system and tenant names) |
| GET | `/systems/{id}/access` | Who has access to a system: user, tenant and role |
| DELETE | `/users/{id}/access/{system_id}` | Remove an access |

`manage_users` marks the owner of a tenant in a system, who will be able to manage the members of their own tenant.

### Tenant owner API (`/v1/tenant/members`, requires a user token with `manage_users`)

The scope (system and tenant) comes from the owner's current access in the database, never from the request.

| Method | Path | Description |
|---|---|---|
| GET | `/members` | People of the owner's tenant in the owner's system |
| POST | `/members` | `{dni, full_name, role}`. Creates the account (DNI as initial password) or, if the DNI already exists, only adds the access |
| PUT | `/members/{user_id}` | `{role}`. Change a member's role |
| DELETE | `/members/{user_id}` | Remove the member from the tenant (the account is kept) |
| POST | `/members/{user_id}/reset-password` | Only for people who exist solely in this tenant |

Owners (`manage_users`) cannot be changed, removed or reset through this API, not even by themselves.
`manage_users` is granted only by the superadmin.

Login is throttled per DNI and per IP (`LOGIN_*` variables) and answers `429 too_many_attempts` with `Retry-After`.
Presenting a refresh token that was already used revokes its whole session.

## Access model

- A **tenant** is a customer company (RUC, legal name, trade name). A **system** is a product (Olympus, Pulso...).
- `tenant_systems`: which systems a tenant has contracted.
- `access`: which user enters which system, in which tenant, with which role. `UNIQUE (user_id, system_id)`: a user is in
  one tenant per system; to move them, remove the old access first. The same user can be in different tenants in different systems.
- The role inside a system is free text (`app_role` in the token). Only `role` (`superadmin` or `user`) is used for authorization here.
- Refreshing a user session re-checks the account and the access: removing access or disabling the user ends the session at the next refresh.

## Deploy

Pushing to the `production` branch runs `.github/workflows/deploy.yml`: tests (against a throwaway PostgreSQL), builds the image, publishes it to GHCR and restarts the stack on the VPS.

| | |
|---|---|
| Domain | `auth.atmosferast.com` (nginx on the host, Cloudflare in front) |
| Container | `auth-api`, loopback port `3130` |
| Server folder | `/opt/auth-api` (`docker-compose.yml` is copied on every deploy) |
| Configuration | `/opt/auth-api/.env`, only on the server (same variables as `.env.example`, plus `CLIENT_IP_HEADER=X-Forwarded-For`) |
| Database | `auth`, owned by the role `auth_app`, in the `atm-postgres` stack |

The app applies its migrations when it starts. To change the superadmin password, edit `ADMIN_PASSWORD` in the server `.env` and restart the container. The image also carries the signing key generator:

```
docker run --rm ghcr.io/atmosferasoltec/atm-auth-api:latest /app/genkey      # JWT_PRIVATE_KEY
```

Replacing `JWT_PRIVATE_KEY` ends every open session.
