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

Generate the two secrets the service needs and paste them into `.env`:

```
go run ./cmd/hashpw     # -> ADMIN_PASSWORD_HASH (wrap the value in single quotes: it contains $)
go run ./cmd/genkey     # -> JWT_PRIVATE_KEY
```

## Run

```
export $(cat .env | xargs) && go run ./cmd/api
```

## Routes

| Method | Path | Description |
|---|---|---|
| GET | `/health` | Liveness |
| GET | `/ready` | Readiness (checks the database) |
| GET | `/.well-known/jwks.json` | Public key (JWKS) other services use to validate access tokens |
| POST | `/v1/login` | User login. Body: `{"dni", "password", "system"}`. The token carries `system`, `tenant` and `app_role`. `403 no_access` if the user cannot enter that system |
| POST | `/v1/admin/login` | Superadmin login. Body: `{"dni", "password"}` |
| POST | `/v1/password/change` | Body: `{"dni", "current_password", "new_password"}`. Ends all sessions; the user logs in again |
| POST | `/v1/refresh` | Rotate a refresh token. Body: `{"refresh_token"}` |
| POST | `/v1/logout` | Revoke the session. Body: `{"refresh_token"}` |
| GET | `/v1/admin/me` | Returns the authenticated superadmin (requires bearer token) |

### Superadmin API (`/v1/admin`, requires the superadmin token)

| Method | Path | Description |
|---|---|---|
| POST, GET | `/systems` | Create and list systems |
| POST, GET | `/tenants` | Create and list tenants (RUC, legal name, trade name) |
| GET | `/tenants/{id}` | One tenant |
| POST | `/tenants/{id}/systems` | Enable a system for a tenant. Body: `{"system_id"}` |
| POST, GET | `/users` | Create and list users. Without `password`, the DNI is the initial password and must be changed at first login |
| POST | `/users/{id}/reset-password` | Back to the DNI, change required, sessions ended |
| PUT | `/users/{id}/status` | `{"status": "active" \| "disabled"}`. Disabling ends all sessions |
| POST | `/access` | Give a user access: `{user_id, system_id, tenant_id, role, manage_users}` |
| GET | `/users/{id}/access` | A user's accesses |
| DELETE | `/users/{id}/access/{system_id}` | Remove an access |

`manage_users` marks the owner of a tenant in a system, who will be able to manage the members of their own tenant.

Login is throttled per DNI and per IP (`LOGIN_*` variables) and answers `429 too_many_attempts` with `Retry-After`.
Presenting a refresh token that was already used revokes its whole session.

## Access model

- A **tenant** is a customer company (RUC, legal name, trade name). A **system** is a product (Olympus, Pulso...).
- `tenant_systems`: which systems a tenant has contracted.
- `access`: which user enters which system, in which tenant, with which role. `UNIQUE (user_id, system_id)`: a user is in
  one tenant per system; to move them, remove the old access first. The same user can be in different tenants in different systems.
- The role inside a system is free text (`app_role` in the token). Only `role` (`superadmin` or `user`) is used for authorization here.
- Refreshing a user session re-checks the account and the access: removing access or disabling the user ends the session at the next refresh.
