package server_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AtmosferaSoltec/atm-auth-api/internal/access"
	"github.com/AtmosferaSoltec/atm-auth-api/internal/platform"
	"github.com/AtmosferaSoltec/atm-auth-api/internal/server"
	"github.com/AtmosferaSoltec/atm-auth-api/internal/session"
	"github.com/AtmosferaSoltec/atm-auth-api/internal/system"
	"github.com/AtmosferaSoltec/atm-auth-api/internal/tenant"
	"github.com/AtmosferaSoltec/atm-auth-api/internal/user"
)

type okPinger struct{}

func (okPinger) Ping(context.Context) error { return nil }

type e2e struct {
	handler http.Handler
	users   *user.Service
	systems *system.Service
	tenants *tenant.Service
	access  *access.Service
}

func newE2E(t *testing.T) http.Handler { return newE2EFull(t).handler }

func newE2EFull(t *testing.T) *e2e {
	t.Helper()
	pool := platform.NewTestPool(t)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	keyB64 := base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	signer, err := platform.NewTokenSigner(keyB64, "atm-auth-api", time.Now)
	if err != nil {
		t.Fatal(err)
	}
	jwks, _ := signer.JWKS()

	hasher := platform.NewPasswordHasher(platform.Argon2Params{MemoryKiB: 8, Time: 1, Threads: 1})
	hash, _ := hasher.Hash("a-long-admin-password")
	repo := session.NewPostgresRepository(pool)
	accessSvc := access.NewService(access.NewPostgresRepository(pool))
	svc := session.NewService(session.Deps{
		Tokens: repo, Attempts: repo, Users: user.NewPostgresRepository(pool), Access: accessSvc,
		Hasher: hasher, Signer: signer,
	}, session.Config{
		Admin:      session.AdminCredentials{DNI: "74455518", PasswordHash: hash},
		DummyHash:  hash,
		Limits:     session.Limits{MaxPerSubject: 3, MaxPerIP: 20, Window: time.Minute},
		AccessTTL:  time.Minute,
		RefreshTTL: time.Hour,
	}, time.Now)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	usersSvc := user.NewService(user.NewPostgresRepository(pool), hasher, svc)
	systemsSvc := system.NewService(system.NewPostgresRepository(pool))
	tenantsSvc := tenant.NewService(tenant.NewPostgresRepository(pool))
	return &e2e{
		handler: server.New(log, server.Deps{
			DB: okPinger{}, Verifier: signer, JWKS: jwks,
			Session: session.NewHandler(svc, log, ""),
			Systems: system.NewHandler(systemsSvc, log),
			Tenants: tenant.NewHandler(tenantsSvc, log),
			Users:   user.NewHandler(usersSvc, log),
			Access:  access.NewHandler(accessSvc, log),
		}),
		users:   usersSvc,
		systems: systemsSvc,
		tenants: tenantsSvc,
		access:  accessSvc,
	}
}

func call(h http.Handler, method, path, bearer string, body any) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestAdminSessionFlow(t *testing.T) {
	h := newE2E(t)

	if rec := call(h, "GET", "/v1/admin/me", "", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: got %d", rec.Code)
	}
	if rec := call(h, "POST", "/v1/admin/login", "", map[string]string{"dni": "74455518", "password": "wrong"}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad login: got %d", rec.Code)
	}

	rec := call(h, "POST", "/v1/admin/login", "", map[string]string{"dni": "74455518", "password": "a-long-admin-password"})
	if rec.Code != http.StatusOK {
		t.Fatalf("login: got %d %s", rec.Code, rec.Body)
	}
	var tok struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &tok)
	if tok.TokenType != "Bearer" || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("unexpected response: %+v headers %v", tok, rec.Header())
	}

	me := call(h, "GET", "/v1/admin/me", tok.AccessToken, nil)
	if me.Code != http.StatusOK {
		t.Fatalf("me: got %d %s", me.Code, me.Body)
	}

	rec = call(h, "POST", "/v1/refresh", "", map[string]string{"refresh_token": tok.RefreshToken})
	if rec.Code != http.StatusOK {
		t.Fatalf("refresh: got %d %s", rec.Code, rec.Body)
	}
	var next struct {
		RefreshToken string `json:"refresh_token"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &next)

	if rec := call(h, "POST", "/v1/refresh", "", map[string]string{"refresh_token": tok.RefreshToken}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("reused refresh: got %d", rec.Code)
	}
	if rec := call(h, "POST", "/v1/logout", "", map[string]string{"refresh_token": next.RefreshToken}); rec.Code != http.StatusNoContent {
		t.Fatalf("logout: got %d", rec.Code)
	}

	jwks := call(h, "GET", "/.well-known/jwks.json", "", nil)
	if jwks.Code != http.StatusOK || !bytes.Contains(jwks.Body.Bytes(), []byte(`"RS256"`)) {
		t.Fatalf("jwks: got %d %s", jwks.Code, jwks.Body)
	}
}

func TestLoginThrottleAndBadBody(t *testing.T) {
	h := newE2E(t)
	for i := 0; i < 3; i++ {
		call(h, "POST", "/v1/admin/login", "", map[string]string{"dni": "74455518", "password": "wrong"})
	}
	rec := call(h, "POST", "/v1/admin/login", "", map[string]string{"dni": "74455518", "password": "a-long-admin-password"})
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("got %d headers %v", rec.Code, rec.Header())
	}

	if rec := call(h, "POST", "/v1/admin/login", "", map[string]string{"dni": ""}); rec.Code != http.StatusBadRequest {
		t.Fatalf("empty body: got %d", rec.Code)
	}
	if rec := call(h, "POST", "/v1/refresh", "", map[string]any{"refresh_token": "x", "extra": 1}); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown field: got %d", rec.Code)
	}
}

func claimsOf(t *testing.T, accessToken string) platform.Claims {
	t.Helper()
	parts := strings.Split(accessToken, ".")
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var c platform.Claims
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestUserFlowAcrossSystems(t *testing.T) {
	ctx := context.Background()
	e := newE2EFull(t)
	h := e.handler

	u, err := e.users.Create(ctx, user.CreateInput{DNI: "11111111", FullName: "Ana Pérez", Password: "ana-password"})
	if err != nil {
		t.Fatal(err)
	}
	olympus, _ := e.systems.Create(ctx, system.CreateInput{Code: "olympus", Name: "Olympus"})
	pulso, _ := e.systems.Create(ctx, system.CreateInput{Code: "pulso", Name: "Pulso"})
	_, _ = e.systems.Create(ctx, system.CreateInput{Code: "nova", Name: "Nova"})
	acme, err := e.tenants.Create(ctx, tenant.CreateInput{RUC: "20123456789", LegalName: "Acme SAC", TradeName: "Acme"})
	if err != nil {
		t.Fatal(err)
	}
	for _, sys := range []string{olympus.ID, pulso.ID} {
		if err := e.tenants.EnableSystem(ctx, acme.ID, sys); err != nil {
			t.Fatal(err)
		}
	}
	// Same account, two systems, different roles. No access to "nova".
	for sys, role := range map[string]string{olympus.ID: "cajero", pulso.ID: "supervisor"} {
		if _, err := e.access.Assign(ctx, access.AssignInput{UserID: u.ID, SystemID: sys, TenantID: acme.ID, Role: role}); err != nil {
			t.Fatal(err)
		}
	}

	login := func(system string) *httptest.ResponseRecorder {
		return call(h, "POST", "/v1/login", "", map[string]string{"dni": "11111111", "password": "ana-password", "system": system})
	}

	rec := login("olympus")
	if rec.Code != http.StatusOK {
		t.Fatalf("olympus login: %d %s", rec.Code, rec.Body)
	}
	var tok struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &tok)
	c := claimsOf(t, tok.AccessToken)
	if c.Subject != u.ID || c.Role != "user" || c.System != "olympus" || c.Tenant != acme.ID || c.AppRole != "cajero" {
		t.Fatalf("unexpected claims: %+v", c)
	}

	rec = login("pulso")
	_ = json.Unmarshal(rec.Body.Bytes(), &tok)
	if c := claimsOf(t, tok.AccessToken); rec.Code != http.StatusOK || c.System != "pulso" || c.AppRole != "supervisor" {
		t.Fatalf("pulso login: %d %+v", rec.Code, c)
	}

	// A normal user's token is not a superadmin token.
	if rec := call(h, "GET", "/v1/admin/me", tok.AccessToken, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("user token on admin route: got %d", rec.Code)
	}

	for _, system := range []string{"nova", "unknown"} {
		if rec := login(system); rec.Code != http.StatusForbidden || !bytes.Contains(rec.Body.Bytes(), []byte("no_access")) {
			t.Fatalf("%s: got %d %s", system, rec.Code, rec.Body)
		}
	}

	// Removing access ends the session at the next refresh.
	if err := e.access.Remove(ctx, u.ID, pulso.ID); err != nil {
		t.Fatal(err)
	}
	if rec := call(h, "POST", "/v1/refresh", "", map[string]string{"refresh_token": tok.RefreshToken}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("refresh after removal: got %d", rec.Code)
	}
	if rec := login("pulso"); rec.Code != http.StatusForbidden {
		t.Fatalf("login after removal: got %d", rec.Code)
	}
}

func decode(t *testing.T, rec *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), v); err != nil {
		t.Fatalf("bad json %q: %v", rec.Body, err)
	}
}

func TestSuperadminAPIAndFirstLoginFlow(t *testing.T) {
	h := newE2E(t)

	var admin struct {
		AccessToken string `json:"access_token"`
	}
	rec := call(h, "POST", "/v1/admin/login", "", map[string]string{"dni": "74455518", "password": "a-long-admin-password"})
	decode(t, rec, &admin)
	adm := admin.AccessToken

	// Every admin route rejects anonymous callers.
	for _, route := range [][2]string{
		{"POST", "/v1/admin/systems"}, {"GET", "/v1/admin/systems"}, {"POST", "/v1/admin/tenants"}, {"GET", "/v1/admin/tenants"},
		{"POST", "/v1/admin/users"}, {"GET", "/v1/admin/users"}, {"POST", "/v1/admin/access"},
	} {
		if rec := call(h, route[0], route[1], "", map[string]string{}); rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s without token: got %d", route[0], route[1], rec.Code)
		}
	}

	var sys, ten, usr struct {
		ID string `json:"id"`
	}
	rec = call(h, "POST", "/v1/admin/systems", adm, map[string]string{"code": "olympus", "name": "Olympus"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create system: %d %s", rec.Code, rec.Body)
	}
	decode(t, rec, &sys)
	if rec := call(h, "POST", "/v1/admin/systems", adm, map[string]string{"code": "olympus", "name": "Dup"}); rec.Code != http.StatusConflict {
		t.Fatalf("duplicate system: %d", rec.Code)
	}
	if rec := call(h, "POST", "/v1/admin/systems", adm, map[string]string{"code": "Bad Code", "name": "x"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad system code: %d", rec.Code)
	}

	rec = call(h, "POST", "/v1/admin/tenants", adm, map[string]string{"ruc": "20123456789", "legal_name": "Gym SAC", "trade_name": "Gym Fit"})
	if rec.Code != http.StatusCreated || !bytes.Contains(rec.Body.Bytes(), []byte(`"display_name":"Gym Fit"`)) {
		t.Fatalf("create tenant: %d %s", rec.Code, rec.Body)
	}
	decode(t, rec, &ten)
	if rec := call(h, "POST", "/v1/admin/tenants/"+ten.ID+"/systems", adm, map[string]string{"system_id": sys.ID}); rec.Code != http.StatusNoContent {
		t.Fatalf("enable system: %d %s", rec.Code, rec.Body)
	}
	if rec := call(h, "GET", "/v1/admin/tenants/not-a-uuid", adm, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad tenant id: %d", rec.Code)
	}

	// The owner is created without a password: the DNI is the initial password.
	rec = call(h, "POST", "/v1/admin/users", adm, map[string]string{"dni": "44444444", "full_name": "Dueño Gym"})
	if rec.Code != http.StatusCreated || !bytes.Contains(rec.Body.Bytes(), []byte(`"must_change_password":true`)) ||
		bytes.Contains(rec.Body.Bytes(), []byte("password_hash")) || bytes.Contains(rec.Body.Bytes(), []byte("argon2")) {
		t.Fatalf("create user: %d %s", rec.Code, rec.Body)
	}
	decode(t, rec, &usr)

	rec = call(h, "POST", "/v1/admin/access", adm, map[string]any{
		"user_id": usr.ID, "system_id": sys.ID, "tenant_id": ten.ID, "role": "dueño", "manage_users": true,
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("assign access: %d %s", rec.Code, rec.Body)
	}
	if rec := call(h, "POST", "/v1/admin/access", adm, map[string]any{
		"user_id": usr.ID, "system_id": sys.ID, "tenant_id": ten.ID, "role": "otro",
	}); rec.Code != http.StatusConflict {
		t.Fatalf("second access in the same system: %d", rec.Code)
	}
	if rec := call(h, "GET", "/v1/admin/users/"+usr.ID+"/access", adm, nil); rec.Code != http.StatusOK ||
		!bytes.Contains(rec.Body.Bytes(), []byte(`"tenant_name":"Gym Fit"`)) {
		t.Fatalf("list access: %d %s", rec.Code, rec.Body)
	}

	login := func(password string) *httptest.ResponseRecorder {
		return call(h, "POST", "/v1/login", "", map[string]string{"dni": "44444444", "password": password, "system": "olympus"})
	}

	// First login with the DNI: blocked until the password is changed. No tokens in the body.
	rec = login("44444444")
	if rec.Code != http.StatusForbidden || !bytes.Contains(rec.Body.Bytes(), []byte("password_change_required")) ||
		bytes.Contains(rec.Body.Bytes(), []byte("access_token")) {
		t.Fatalf("pending login: %d %s", rec.Code, rec.Body)
	}
	change := func(next string) *httptest.ResponseRecorder {
		return call(h, "POST", "/v1/password/change", "", map[string]string{"dni": "44444444", "current_password": "44444444", "new_password": next})
	}
	if rec := change("44444444"); rec.Code != http.StatusBadRequest {
		t.Fatalf("DNI as new password: %d", rec.Code)
	}
	if rec := change("my-own-password"); rec.Code != http.StatusNoContent {
		t.Fatalf("change password: %d %s", rec.Code, rec.Body)
	}
	if rec := login("44444444"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("old password: %d", rec.Code)
	}
	rec = login("my-own-password")
	if rec.Code != http.StatusOK {
		t.Fatalf("login after change: %d %s", rec.Code, rec.Body)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	decode(t, rec, &tok)
	c := claimsOf(t, tok.AccessToken)
	if c.Tenant != ten.ID || c.AppRole != "dueño" || !c.ManageUsers || c.Role != "user" {
		t.Fatalf("unexpected claims: %+v", c)
	}
	if rec := call(h, "GET", "/v1/admin/users", tok.AccessToken, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("a manager is not a superadmin: %d", rec.Code)
	}

	// Superadmin reset: back to the DNI, change required again, sessions ended.
	if rec := call(h, "POST", "/v1/admin/users/"+usr.ID+"/reset-password", adm, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("reset: %d", rec.Code)
	}
	if rec := login("my-own-password"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("after reset the old password must fail: %d", rec.Code)
	}
	if rec := login("44444444"); rec.Code != http.StatusForbidden {
		t.Fatalf("after reset the DNI requires a change: %d", rec.Code)
	}

	// Disabled accounts cannot log in.
	_ = change("my-own-password")
	if rec := call(h, "PUT", "/v1/admin/users/"+usr.ID+"/status", adm, map[string]string{"status": "disabled"}); rec.Code != http.StatusNoContent {
		t.Fatalf("disable: %d", rec.Code)
	}
	if rec := login("my-own-password"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("disabled login: %d", rec.Code)
	}
	if rec := call(h, "PUT", "/v1/admin/users/"+usr.ID+"/status", adm, map[string]string{"status": "banned"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad status: %d", rec.Code)
	}

	// Removing access.
	if rec := call(h, "DELETE", "/v1/admin/users/"+usr.ID+"/access/"+sys.ID, adm, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("remove access: %d", rec.Code)
	}
	if rec := call(h, "DELETE", "/v1/admin/users/"+usr.ID+"/access/"+sys.ID, adm, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("remove twice: %d", rec.Code)
	}
}
