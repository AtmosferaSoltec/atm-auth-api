# ATM-Auth-API

Single source of truth for identity and access across all ATM systems. See `AGENTS.md` for the architecture and rules.

## Configuration

Environment variables (see `.env.example`):

| Variable | Default | Description |
|---|---|---|
| `APP_ENV` | `development` | `development` or `production` |
| `HTTP_ADDR` | `:8080` | Listen address |
| `DATABASE_URL` | required | PostgreSQL connection string |
| `MESSAGING_URL` | empty | Base URL of atm-messaging-api. Empty: recovery requests are accepted but no email is sent |
| `GOOGLE_CLIENT_IDS` | empty | Comma separated OAuth client IDs (web, Android, iOS). Empty: Google sign-in is off |
| `ACCOUNT_DELETION_HOOKS` | empty | `code=https://url` pairs: where each personal system deletes its data of a person who deletes their account |
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

## Local test user (for agents and developers)

Every local system (Zenit, Nova, Pulso, Orbita, Olympus Courier) can be tested by signing in through a local copy of this API with one shared test user. **It exists only in local databases, never in production**: do not create it there.

| | |
|---|---|
| Local API | `http://localhost:3130` (the production container uses the same loopback port). The default `HTTP_ADDR=:8080` is often taken by other dev servers on the owner's Mac, so start it with `HTTP_ADDR=:3130` |
| DNI | `99999999` |
| Password | `Local-Test-2026` |
| Role | `admin` in every system, with `manage_users` |
| Companies | `Bodega de Pruebas S.A.C.` (RUC `20999999991`, the one login enters by default) and `Empresa de Pruebas S.A.C.` (RUC `20999999992`), both fictitious, with every company system enabled. Orbita is personal: access without a company |

Log in like any user: `POST /v1/login` with `{"dni": "99999999", "password": "Local-Test-2026", "system": "zenit"}`. Switch company with `POST /v1/refresh` and a `tenant_id`.

Bring it up from scratch:

```
docker compose up -d                                   # PostgreSQL on localhost:5433
HTTP_ADDR=:3130 CORS_ALLOWED_ORIGINS=http://localhost:3000,http://localhost:3002 go run ./cmd/api
scripts/dev-seed.sh                                    # creates the user, the two companies and the accesses
```

`scripts/dev-seed.sh` is idempotent, reads the superadmin from `.env` and refuses any URL that is not `localhost`. A system's backend that asks this API for its companies (as Zenit does) also needs that system's secret: log in as superadmin, `POST /v1/admin/systems/{id}/secret`, and put `client_secret` in that backend's `AUTH_CLIENT_SECRET`. Point each backend's `AUTH_API_URL` and each web's `NEXT_PUBLIC_AUTH_URL` at `http://localhost:3130`.

A system that keeps its own company record links it by RUC the first time someone from that company signs in. To test with existing local data, give that record RUC `20999999991` (and the tenant id in its `auth_tenant_id`, if the system stores one).

## Routes

| Method | Path | Description |
|---|---|---|
| GET | `/health` | Liveness |
| GET | `/ready` | Readiness (checks the database) |
| GET | `/.well-known/jwks.json` | Public key (JWKS) other services use to validate access tokens |
| POST | `/v1/login` | User login. Body: `{"document" or "email", "password", "system"}` (exactly one of `document` / `email`; `document` is the number of a DNI, CE or passport, and spaces, dashes and lower case are ignored; the older name `dni` is still accepted), plus an optional `tenant_id` to enter a specific company. Without it the person enters the company they used last, or else the first one they were given. The token carries `system`, `tenant` and `app_role`, plus `name`, `document_type` (`dni`, `ce` or `passport`), `document_number`, `dni` (deprecated: the same number, whatever its type), `tenant_ruc`, `client` (the id of the customer that owns the company) and `client_name`, so the system can link or create its own record of the person, the company and its owner. Pulso, for example, reads `client` as the organization and each `tenant` as one of its gyms. The response also says `session_mode` and `refresh_expires_in` (seconds), so the client knows whether to remember the session. `403 no_access` if the user cannot enter that system |
| POST | `/v1/register` | Self sign-up for **personal systems** (catalog `Personal` with a `SelfSignupRole`, today Orbita). Body: `{"system", "email", "full_name", "password"}` (password 8-128 characters). Creates the account and an access without a company, and answers `201` with the same tokens as login. `403 signup_closed` if the system does not accept it, `409 email_taken`, `400 invalid_email` / `invalid_full_name` / `weak_password`. Throttled per IP like logins |
| POST | `/v1/password/forgot` | Body: `{"email", "system"}`. Always `204` for a well-formed request: if the email has an account, a 6-digit code (15 minutes, 3 per day) is sent through atm-messaging-api on behalf of `system`. `400 unknown_system` / `invalid_email`, `429` throttled per IP and per email |
| POST | `/v1/password/verify` | Body: `{"email", "code"}`. `204` if the code works (it is not consumed); `422 reset_code_invalid` otherwise. A wrong guess counts: the code stops at the fifth |
| POST | `/v1/password/reset` | Body: `{"email", "code", "new_password", "system"}`. Sets the password (also the first one of a Google account), ends every session and emails "your password changed". Does not sign in. A weak password (`400 weak_password`) does not consume the code |
| POST | `/v1/google/challenge` | `{"nonce", "expires_in"}`: single-use nonce (5 minutes) the app must put in its Google request. `503 google_unavailable` without `GOOGLE_CLIENT_IDS` |
| POST | `/v1/google` | Body: `{"system", "credential", "nonce", "password"?, "tenant_id"?}`. `credential` is the Google ID token the app got with its own SDK (web, Android, iOS client IDs are all accepted). Signs in the linked account; or links the account that has that email if `password` confirms it (`409 password_required_to_link` asks for it, without burning the nonce); or creates a passwordless account in a system that accepts sign-up (`403 signup_closed` otherwise). Returns the same tokens as login |
| DELETE | `/v1/account` | Needs a user token. Body: `{"password"}` or, for accounts without one, `{"credential", "nonce"}` of the linked Google identity. Only for people whose accesses are all in personal systems (`409 account_shared` otherwise). Calls each system's `ACCOUNT_DELETION_HOOKS` URL first (POST `{user_id, system}` with a service token of subject `system:auth`); if one fails, nothing is deleted (`502 account_cleanup_failed`) |
| POST | `/v1/token` | Service token for a system's backend. Body: `{"client_id": <system code>, "client_secret"}`. Returns a short-lived `access_token` (role `service`, subject `system:<code>`) with no refresh token; the backend asks again when it expires. One secret per system works on every microservice, which only verify the token with the JWKS. Throttled like logins |
| POST | `/v1/admin/login` | Superadmin login. Body: `{"dni", "password"}` |
| POST | `/v1/password/change` | Body: `{"document", "current_password", "new_password"}` (`dni` still accepted). Ends all sessions; the user logs in again |
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
| POST, GET | `/users` | Create and list users. Body: `{document_type, document_number, full_name}`, or the older `{dni, full_name}` for a DNI. The document number is always the initial password and must be changed at first login; a `password` field is rejected |
| POST | `/users/{id}/reset-password` | Back to the document number, change required, sessions ended |
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
| POST | `/members` | `{document_type, document_number, full_name, role}` (or the older `{dni, ...}`). Creates the account (document number as initial password) or, if the number already exists, only adds the access |
| PUT | `/members/{user_id}` | `{role}`. Change a member's role |
| DELETE | `/members/{user_id}` | Remove the member from the tenant (the account is kept) |
| POST | `/members/{user_id}/reset-password` | Only for people who exist solely in this tenant |

Owners (`manage_users`) cannot be changed, removed or reset through this API, not even by themselves.
The role `superadmin` is reserved for the platform's own team: it is hidden from `GET /roles`, owners cannot give it (`400 unknown_role`), and people who have it cannot be changed or removed through this API. Only the superadmin API grants it.
`manage_users` is granted only by the superadmin.

Login is throttled per document and per IP (`LOGIN_*` variables) and answers `429 too_many_attempts` with `Retry-After`.
Presenting a refresh token that was already used revokes its whole session.

## Identity documents

A person is identified by one document: `dni` (8 digits), `ce`, the foreign resident card (9 to 12 digits), or `passport`, which also covers any other foreign ID (6 to 12 letters or digits). Numbers are stored without spaces or dashes and in upper case, and are unique across types. Users, members and access listings answer `document_type` and `document_number` (and `dni`, deprecated, with the same number). Errors: `400 invalid_document`, `409 document_taken`.

## Systems and roles are defined in code

The superadmin does not create systems or roles from the console. Both are declared in `internal/catalog/model.go` (`catalog.Systems`), and on every start the service syncs them into the database (idempotent upsert): a missing system or role is created; a system that exists keeps its name, secret and session policy; a role's description follows the code. To add a role, add one line to the system in that file and deploy. To add a system, add a block there. Secrets are never declared in code; generate them per environment from the console. `requires_ruc` (false for `pulso`) says whether a system can only be enabled for companies that have a RUC.

Nothing is ever deleted. Roles in the database that the catalog does not declare are marked `active = false` on every start (and set back to `true` if they return to the catalog): they cannot be given or changed to (`400 unknown_role`), they are hidden from `GET /roles`, and `GET /v1/admin/systems/{id}/roles` returns `active` so the console shows them as retired; accesses already pointing at them are kept until cleaned by hand. Systems or roles that exist in the database but not in the catalog (leftovers) are logged as warnings at startup (`system in the database is not in the catalog`, `role in the database is not in the catalog` with the number of `users`); clean them by hand once nobody uses them. Giving a person a role outside the system's roles is refused with `400 unknown_role`.

Catalog today: `pulso` (`admin`, `receptionist`; `member` is prepared as a commented line, not active yet), `zenit` (`admin`, `cashier`; it was La Vendimia, the code in the database is `zenit`), `nova` (`admin`, `receptionist`, `cashier`, `dentist`), `orbita` (`admin`) and `olympuscourier` (`admin`, `user`, `delivery`; declared only, its production client does not use this service yet). Migrations `0012` and `0013` seeded the same data before the sync existed; they stay as history.

## Personal systems

A system declared `Personal: true` in the catalog has no companies: its people sign in with an email, their access has no tenant (`access.tenant_id` is NULL, at most one per user and system) and their token carries no `tenant`, `tenant_ruc` or `client`, but does carry `email`. A system with `SelfSignupRole` also lets anyone create their own account with `POST /v1/register`. Accounts may have a document, an email or both (`users.dni` is optional, `users.email` is unique), and may have no password yet (reserved for Google sign-in). Resetting a password to the document number only works for accounts that have one (`409 no_document` otherwise). The superadmin can still give access to a personal system without `tenant_id`; any other system requires it (`400 tenant_required`).

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
