# AGENTS.md — ATM-Auth-API

Instructions for every AI agent (and human) working in this repository. Read it fully before changing anything.

## Language rules

- ALL code is written in English: file names, folder names, packages, types, functions, variables, constants, error codes, error messages, log messages, comments, test names, commit messages, and documentation inside the repo.
- Talk to the user in Spanish. Never put Spanish inside the repository.
- Repositories follow the pattern `ATM-<Name>-<Type>` (this one is `ATM-Auth-API`).

## What this service does

ATM-Auth-API is the single source of truth for identity and access across all ATM systems:

- Global user accounts: one account per person, identified by national ID (DNI).
- Systems (Olympus, Lavendimia, Pulso, Nova, Orbita) and tenants (customers).
- Access: which user can enter which system, in which tenant, with which role.
- Login, refresh, and logout. Issues short-lived RS256 JWT access tokens.
- Admin API (superadmin only) used by ATM-Console-Web to manage all of the above.
- There is exactly one superadmin (the owner). It is NOT a row in `users`: its credentials come from the environment (`ADMIN_DNI`, `ADMIN_PASSWORD_HASH` as an argon2id hash, never plaintext) and it logs in through its own endpoint, `POST /v1/admin/login`. Its token carries `role: superadmin` and no system or tenant.
- New accounts get their DNI as the initial password and `must_change_password = true`. While it is set, login answers `403 password_change_required` and no token is issued. `POST /v1/password/change` clears it and ends all sessions.
- `access.manage_users` marks the owner of a tenant in a system; the owner will manage only members of their own (system, tenant), taken from their token and checked again in the database. An owner can reset the password only of users who exist solely in their tenant. Only the superadmin grants `manage_users`.
- Rule: a user belongs to at most one tenant per system (`UNIQUE (user_id, system_id)` in `access`). Across different systems the same user can belong to different tenants.

Out of scope: business permissions inside each system (what a "cashier" can do in Olympus stays in Olympus), billing, messaging, and file storage.

Other services never call this service on every request. They validate tokens locally with the public key.

## Stack

- Go 1.24. Standard library first (`net/http`, `log/slog`).
- PostgreSQL. SQL migrations live in `migrations/`.
- Password hashing: argon2id only (`golang.org/x/crypto/argon2`). There is no bcrypt support: users of existing systems set a new password when they are migrated.
- Tokens: JWT signed with RS256. The private key never leaves this service.
- Created from the `ATM-Go-Template` repository. Keep its conventions.

## Architecture: package by feature, lightweight hexagonal

```
cmd/api/              entry point: wiring only, no business logic
cmd/hashpw/           prints an argon2id hash (used to set ADMIN_PASSWORD_HASH)
migrations/           numbered .sql files
internal/
  config/             environment configuration
  httpx/              shared HTTP middlewares and helpers
  auth/               token verification middleware from the template (protects /v1/admin)
  server/             route registration, wires the features together
  platform/           database connection, clock, id generation, password hasher, token signer
  user/               one folder per feature (see below)
  tenant/
  system/
  access/
  session/            login, refresh, logout
```

Each feature folder contains:

- `model.go`: domain types and rules. No HTTP or SQL imports.
- `service.go`: use cases. Depends only on interfaces.
- `repository.go`: the interface the service needs, defined where it is used.
- `postgres.go`: repository implementation. The ONLY place with SQL for that feature.
- `handler.go`: HTTP handlers. Decode the request, call the service, encode the response.
- `errors.go`: the feature's error codes.
- `*_test.go`: tests next to the code.

Dependency rules (never break them):

1. `handler` depends on `service`, and `service` depends on the `repository` interface. Never the other way around.
2. SQL lives only in `postgres.go`. Handlers never touch the database.
3. `model.go` and `service.go` never import `net/http` or `database/sql`.
4. A feature never imports another feature's `postgres.go` or `handler.go`. If it needs another feature, it depends on a small interface.
5. `cmd/*` and `internal/server` are the only places that construct concrete implementations.

Keep it simple. Do not add layers, generic base types, or abstractions until a second use case needs them. This is not full hexagonal ceremony.

## Naming

- Files: lowercase, snake_case when needed (`refresh_token.go`).
- Packages: short, lowercase, singular, no underscores.
- Exported identifiers describe intent (`CreateUser`, not `DoUser`).
- Tables: plural snake_case (`users`, `tenant_systems`). Columns: snake_case. IDs: UUIDs.

## Errors

- Every domain error has a stable snake_case English code, defined in the feature's `errors.go` (for example `invalid_credentials`, `user_not_found`, `tenant_disabled`).
- HTTP error body: `{"error": {"code": "invalid_credentials", "message": "Invalid DNI or password."}}`.
- On login failures never reveal whether a DNI exists. Always answer `invalid_credentials`.
- Wrap errors with context (`fmt.Errorf("create user: %w", err)`). Do not log and return the same error.

## Security rules

- Never log passwords, hashes, tokens, or private keys.
- Never commit secrets. `.env`, `*.pem`, and `*.key` are git-ignored.
- All SQL uses parameters. Never build SQL with string concatenation.
- Accept only RS256. Access tokens last minutes. Refresh tokens are stored hashed, rotated on every use, and revocable.
- Rate-limit login attempts per DNI and per IP.
- Compare secrets in constant time.
- Hashing parameters come from configuration. Do not hard-code them.

## HTTP conventions

- Business routes live under `/v1`. `/health` and `/ready` are public.
- Admin routes live under `/v1/admin` and require the role `superadmin`.
- JSON only. Always propagate `X-Request-ID`.

## Testing and quality

- Every use case has tests. Services are tested with in-memory fakes of the repository interface. `postgres.go` is tested against a real PostgreSQL.
- Before finishing any task, all of these must pass: `gofmt -l .` (no output), `go vet ./...`, and `go test ./... -race`.
- Fix the cause of a failing test. Never delete or weaken a test to make it pass.

## Working agreement

- Make small, focused changes. Do not refactor unrelated code.
- Add a third-party dependency only when the standard library is not reasonable, and tell the user why.
- Never edit a migration that was already applied. Add a new one.
- When a request is ambiguous or touches a security decision, ask before building.
- Update `README.md` when behavior, configuration, or routes change.
