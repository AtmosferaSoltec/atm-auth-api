# ATM-Auth-API

Single source of truth for identity and access across all ATM systems. See `AGENTS.md` for the architecture and rules.

## Configuration

Environment variables (see `.env.example`):

| Variable | Default | Description |
|---|---|---|
| `APP_ENV` | `development` | `development` or `production` |
| `HTTP_ADDR` | `:8080` | Listen address |
| `DATABASE_URL` | required | PostgreSQL connection string |
| `CORS_ALLOWED_ORIGINS` | empty | Browser origins (comma separated) allowed to call the API directly, e.g. each system's web. Tokens travel in the `Authorization` header, so credentials/cookies are never allowed |

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
| POST | `/v1/login` | User login. Body: `{"dni", "password", "system"}`, plus an optional `tenant_id` to enter a specific company. Without it the person enters the company they used last, or else the first one they were given. The token carries `system`, `tenant` and `app_role`, plus `name`, `dni`, `tenant_ruc`, `client` (the id of the customer that owns the company) and `client_name`, so the system can link or create its own record of the person, the company and its owner. Pulso, for example, reads `client` as the organization and each `tenant` as one of its gyms. The response also says `session_mode` and `refresh_expires_in` (seconds), so the client knows whether to remember the session. `403 no_access` if the user cannot enter that system |
| POST | `/v1/token` | Service token for a system's backend. Body: `{"client_id": <system code>, "client_secret"}`. Returns a short-lived `access_token` (role `service`, subject `system:<code>`) with no refresh token; the backend asks again when it expires. One secret per system works on every microservice, which only verify the token with the JWKS. Throttled like logins |
| POST | `/v1/admin/login` | Superadmin login. Body: `{"dni", "password"}` |
| POST | `/v1/password/change` | Body: `{"dni", "current_password", "new_password"}`. Ends all sessions; the user logs in again |
| POST | `/v1/refresh` | Rotate a refresh token. Body: `{"refresh_token"}`, plus an optional `tenant_id` to **switch the session to another company** the person works for in the system (no password needed; `403 no_access` if they do not, and their session stays). That company becomes the one login enters next time |
| GET | `/v1/session/tenants` | The companies the signed-in person can work for in the system of their token: `{items: [{tenant_id, ruc, name, role, current}]}`. Clients show a selector when there is more than one |
| POST | `/v1/logout` | Revoke the session. Body: `{"refresh_token"}` |
| GET | `/v1/admin/me` | Returns the authenticated superadmin (requires bearer token) |

### Superadmin API (`/v1/admin`, requires the superadmin token)

| Method | Path | Description |
|---|---|---|
| GET | `/systems` | List the systems (each with `requires_ruc`). They are not created from the console: see "Systems and roles are defined in code" below |
| POST | `/systems/{id}/secret` | Generate (or regenerate) the system's secret. Returns `{client_id, client_secret}` once; the old secret stops working at once |
| DELETE | `/systems/{id}/secret` | Revoke the system's secret. Tokens already issued last until they expire |
| PUT | `/systems/{id}/session` | How a system treats its users' sessions. Body: `{"mode": "persistent" \| "temporary"}`. **Persistent** remembers the user: the session lasts `REFRESH_TOKEN_TTL` (90 days by default) without use. **Temporary** does not: the client keeps no session after the tab closes, and the server only bounds it with `TEMPORARY_REFRESH_TTL` (12 h by default). Open sessions pick the change up at their next refresh |
| POST, GET | `/tenants` | Create and list tenants. Create body: `{legal_name, trade_name, ruc, client_id}`; only `legal_name` is required (for a person, their own name or the gym's). The **RUC is optional**: missing, empty or blank means the company has none (stored as NULL, unique only when present). `400 invalid_ruc` if given but not 11 digits, `409 ruc_taken` if another company has it. Every tenant JSON returns `"ruc": ""` when it has none (never null) |
| GET | `/tenants/{id}` | One tenant. Tenants (here and in the list) carry `systems`: the systems enabled for them |
| PUT | `/tenants/{id}` | Edit the company profile. Body (all fields are sent; an empty one is cleared, only `legal_name` is required): `{legal_name, trade_name, address, department, province, district, ubigeo, phone, email, logo_file_id}`. `ubigeo` is 6 digits, `logo_file_id` the id of the logo in atm-storage-api (never a URL). `ruc` may also be sent: a company that already has one keeps it (sending the same value is fine, a different one is `409 ruc_immutable`, an empty one changes nothing); a company **without** one may set it once. Systems read this data instead of keeping their own copy |
| POST | `/tenants/{id}/systems` | Enable a system for a tenant. Body: `{"system_id"}`. `409 ruc_required` if the system has `requires_ruc` and the tenant has no RUC (Pulso does not) |
| DELETE | `/tenants/{id}/systems/{system_id}` | Disable a system for a tenant. Removes the access its users had in that system (accounts stay) |
| POST, GET | `/users` | Create and list users. Body: `{dni, full_name}`. The DNI is always the initial password and must be changed at first login; a `password` field is rejected |
| POST | `/users/{id}/reset-password` | Back to the DNI, change required, sessions ended |
| PUT | `/users/{id}/status` | `{"status": "active" \| "disabled"}`. Disabling ends all sessions |
| GET | `/systems/{id}/roles` | The roles a system defines (each with how many people have it). They are fixed in code: there is no endpoint to create, change or delete them |
| POST | `/access` | Give a user access: `{user_id, system_id, tenant_id, role, manage_users}`. `role` must be one of the roles in the system's catalog (`400 unknown_role` otherwise) |
| GET | `/users/{id}/access` | A user's accesses (with system and tenant names) |
| GET | `/systems/{id}/access` | Who has access to a system: user, tenant and role |
| DELETE | `/access/{id}` | Remove one access (the `id` comes from the access lists), so a person with several companies in a system loses only that one |
| DELETE | `/users/{id}/access/{system_id}` | Remove every access the user has in a system |

`manage_users` marks the owner of a tenant in a system, who will be able to manage the members of their own tenant.

### System service API (`/v1/service`, requires the service token of a system)

For a system's own backend, with the token from `POST /v1/token`. The system is the one the token was issued to; nothing in the request can change it.

| Method | Path | Description |
|---|---|---|
| GET | `/tenants` | The customers of the system: active tenants that have it enabled. Each is `{id, ruc, legal_name, trade_name, display_name, address, department, province, district, ubigeo, phone, email, logo_file_id, client_id, client_name}` (profile fields are empty strings, and `logo_file_id` null, when not set); the list never says what other systems a customer uses |

### Tenant owner API (`/v1/tenant/members`, requires a user token with `manage_users`)

The scope (system and tenant) comes from the owner's current access in the database, never from the request.

| Method | Path | Description |
|---|---|---|
| GET | `/roles` | The roles of the owner's system, to choose from when adding or changing a member |
| GET | `/members` | People of the owner's tenant in the owner's system |
| POST | `/members` | `{dni, full_name, role}`. Creates the account (DNI as initial password) or, if the DNI already exists, only adds the access |
| PUT | `/members/{user_id}` | `{role}`. Change a member's role |
| DELETE | `/members/{user_id}` | Remove the member from the tenant (the account is kept) |
| POST | `/members/{user_id}/reset-password` | Only for people who exist solely in this tenant |

Owners (`manage_users`) cannot be changed, removed or reset through this API, not even by themselves.
The role `superadmin` is reserved for the platform's own team: it is hidden from `GET /roles`, owners cannot give it (`400 unknown_role`), and people who have it cannot be changed or removed through this API. Only the superadmin API grants it.
`manage_users` is granted only by the superadmin.

Login is throttled per DNI and per IP (`LOGIN_*` variables) and answers `429 too_many_attempts` with `Retry-After`.
Presenting a refresh token that was already used revokes its whole session.

## Systems and roles are defined in code

The superadmin does not create systems or roles from the console. Both are declared in `internal/catalog/model.go` (`catalog.Systems`), and on every start the service syncs them into the database (idempotent upsert): a missing system or role is created; a system that exists keeps its name, secret and session policy; a role's description follows the code. To add a role, add one line to the system in that file and deploy. To add a system, add a block there. Secrets are never declared in code; generate them per environment from the console. `requires_ruc` (false for `pulso`) says whether a system can only be enabled for companies that have a RUC.

Nothing is ever deleted. Roles in the database that the catalog does not declare are marked `active = false` on every start (and set back to `true` if they return to the catalog): they cannot be given or changed to (`400 unknown_role`), they are hidden from `GET /roles`, and `GET /v1/admin/systems/{id}/roles` returns `active` so the console shows them as retired; accesses already pointing at them are kept until cleaned by hand. Systems or roles that exist in the database but not in the catalog (leftovers) are logged as warnings at startup (`system in the database is not in the catalog`, `role in the database is not in the catalog` with the number of `users`); clean them by hand once nobody uses them. Giving a person a role outside the system's roles is refused with `400 unknown_role`.

Catalog today: `pulso` (`admin`, `receptionist`; `member` is prepared as a commented line, not active yet), `lavendimia` (`admin`, `cashier`), `nova` (`admin`, `receptionist`, `cashier`, `dentist`), `orbita` (`admin`) and `olympus` (`admin`, `user`, `delivery`; declared only, its production client does not use this service yet). Migrations `0012` and `0013` seeded the same data before the sync existed; they stay as history.

## Access model

- A **client** is the real customer who owns one or more companies; a **tenant** is one of those companies (RUC, legal name, trade name). Systems use the client to decide what the companies of one owner share (in Pulso, the client is the organization and each company is a gym).
- A **tenant** is a customer company (legal name, trade name and, optionally, a RUC; a gym run by one person may have none). A **system** is a product (Olympus, Pulso...).
- `tenant_systems`: which systems a tenant has contracted.
- `access`: which user enters which system, in which tenant, with which role. `UNIQUE (user_id, system_id, tenant_id)`: a person can work for **several companies in the same system** (for example the owner of two businesses), once each. Only the superadmin gives a person a second company: an owner cannot add someone who already belongs to another company of the system (`409`).
- The token always names **one** company (`tenant`). Login enters the company used last, or else the first one given; the person switches with `POST /v1/refresh` and a `tenant_id`, and each session remembers its company so a refresh keeps it. Systems keep reading `tenant` from the token and need no change. `/v1/tenant/members` acts on the company of the token.
- Each system defines its own roles (a catalog per system). An access points at one of them, so a role cannot be mistyped. In the token the role is still the name, as text (`app_role`): what each role allows is up to the system. Only `role` (`superadmin` or `user`) is used for authorization here.
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
