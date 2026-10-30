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
	"github.com/AtmosferaSoltec/atm-auth-api/internal/credential"
	"github.com/AtmosferaSoltec/atm-auth-api/internal/member"
	"github.com/AtmosferaSoltec/atm-auth-api/internal/platform"
	"github.com/AtmosferaSoltec/atm-auth-api/internal/role"
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
	roles   *role.Service
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
	credentialSvc := credential.NewService(credential.NewPostgresRepository(pool), time.Now)
	svc := session.NewService(session.Deps{
		Tokens: repo, Attempts: repo, Users: user.NewPostgresRepository(pool), Access: accessSvc,
		Hasher: hasher, Signer: signer, Clients: credentialSvc,
	}, session.Config{
		Admin:      session.AdminCredentials{DNI: "74455518", PasswordHash: hash},
		DummyHash:  hash,
		Limits:     session.Limits{MaxPerSubject: 3, MaxPerIP: 20, Window: time.Minute},
		AccessTTL:  time.Minute,
		RefreshTTL: time.Hour,
	}, time.Now)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	userRepo := user.NewPostgresRepository(pool)
	usersSvc := user.NewService(userRepo, hasher, svc)
	systemsSvc := system.NewService(system.NewPostgresRepository(pool))
	tenantsSvc := tenant.NewService(tenant.NewPostgresRepository(pool))
	rolesSvc := role.NewService(role.NewPostgresRepository(pool))
	return &e2e{
		handler: server.New(log, server.Deps{
			DB: okPinger{}, Verifier: signer, JWKS: jwks,
			Session: session.NewHandler(svc, log, ""),
			Systems: system.NewHandler(systemsSvc, log),
			Tenants: tenant.NewHandler(tenantsSvc, log),
			Users:   user.NewHandler(usersSvc, log),
			Access:  access.NewHandler(accessSvc, log),
			Secrets: credential.NewHandler(credentialSvc, log),
			Roles:   role.NewHandler(rolesSvc, log),
			Members: member.NewHandler(member.NewService(member.NewPostgresRepository(pool), userRepo, usersSvc, accessSvc), log, signer),
		}),
		users:   usersSvc,
		systems: systemsSvc,
		tenants: tenantsSvc,
		access:  accessSvc,
		roles:   rolesSvc,
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
	for sys, name := range map[string]string{olympus.ID: "cajero", pulso.ID: "supervisor"} {
		if _, err := e.roles.Create(ctx, role.CreateInput{SystemID: sys, Name: name}); err != nil {
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
	if c.Subject != u.ID || c.Role != "user" || c.System != "olympus" || c.Tenant != acme.ID || c.AppRole != "cajero" ||
		c.DNI != "11111111" || c.Name != "Ana Pérez" || c.TenantRUC != "20123456789" {
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
		{"POST", "/v1/admin/systems"}, {"GET", "/v1/admin/systems"}, {"DELETE", "/v1/admin/systems/x"}, {"GET", "/v1/admin/systems/x/roles"}, {"POST", "/v1/admin/systems/x/roles"}, {"PUT", "/v1/admin/systems/x/session"}, {"POST", "/v1/admin/systems/x/secret"}, {"DELETE", "/v1/admin/systems/x/secret"}, {"GET", "/v1/admin/systems/x/access"}, {"DELETE", "/v1/admin/tenants/x/systems/y"}, {"POST", "/v1/admin/tenants"}, {"GET", "/v1/admin/tenants"},
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

	// One secret per system gets a service token that works as a machine identity, and opens no admin route.
	rec = call(h, "POST", "/v1/admin/systems/"+sys.ID+"/secret", adm, nil)
	var issued struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("generate secret: %d %s", rec.Code, rec.Body)
	}
	decode(t, rec, &issued)
	if issued.ClientID != "olympus" || !strings.HasPrefix(issued.ClientSecret, "atm_") {
		t.Fatalf("unexpected secret: %+v", issued)
	}
	if rec := call(h, "GET", "/v1/admin/systems", adm, nil); !bytes.Contains(rec.Body.Bytes(), []byte(`"has_secret":true`)) ||
		bytes.Contains(rec.Body.Bytes(), []byte(issued.ClientSecret)) || bytes.Contains(rec.Body.Bytes(), []byte("secret_hash")) {
		t.Fatalf("a system must say it has a secret and never reveal it: %s", rec.Body)
	}
	if rec := call(h, "POST", "/v1/token", "", map[string]string{"client_id": "olympus", "client_secret": "atm_wrong"}); rec.Code != http.StatusUnauthorized ||
		!bytes.Contains(rec.Body.Bytes(), []byte("invalid_client")) {
		t.Fatalf("wrong secret: %d %s", rec.Code, rec.Body)
	}
	rec = call(h, "POST", "/v1/token", "", map[string]string{"client_id": "olympus", "client_secret": issued.ClientSecret})
	var svcToken struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if rec.Code != http.StatusOK || bytes.Contains(rec.Body.Bytes(), []byte("refresh_token")) {
		t.Fatalf("service token: %d %s", rec.Code, rec.Body)
	}
	decode(t, rec, &svcToken)
	if svcToken.AccessToken == "" || svcToken.ExpiresIn <= 0 {
		t.Fatalf("unexpected token: %+v", svcToken)
	}
	for _, path := range []string{"/v1/admin/systems", "/v1/admin/me", "/v1/tenant/members"} {
		if rec := call(h, "GET", path, svcToken.AccessToken, nil); rec.Code != http.StatusForbidden {
			t.Fatalf("a service token must not open %s: %d", path, rec.Code)
		}
	}
	if rec := call(h, "POST", "/v1/token", "", map[string]string{"client_id": "olympus"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("missing secret: %d", rec.Code)
	}
	// Regenerating kills the old secret; revoking kills the new one.
	rec = call(h, "POST", "/v1/admin/systems/"+sys.ID+"/secret", adm, nil)
	var second struct {
		ClientSecret string `json:"client_secret"`
	}
	decode(t, rec, &second)
	if rec := call(h, "POST", "/v1/token", "", map[string]string{"client_id": "olympus", "client_secret": issued.ClientSecret}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("old secret after regenerating: %d", rec.Code)
	}
	if rec := call(h, "POST", "/v1/token", "", map[string]string{"client_id": "olympus", "client_secret": second.ClientSecret}); rec.Code != http.StatusOK {
		t.Fatalf("new secret: %d", rec.Code)
	}
	if rec := call(h, "DELETE", "/v1/admin/systems/"+sys.ID+"/secret", adm, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("revoke: %d", rec.Code)
	}
	if rec := call(h, "POST", "/v1/token", "", map[string]string{"client_id": "olympus", "client_secret": second.ClientSecret}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("revoked secret: %d", rec.Code)
	}

	// Session mode: set per system (persistent or temporary, no minutes) and visible in the login response.
	if rec := call(h, "PUT", "/v1/admin/systems/"+sys.ID+"/session", adm, map[string]any{"mode": "forever"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown mode: %d %s", rec.Code, rec.Body)
	}
	if rec := call(h, "PUT", "/v1/admin/systems/"+sys.ID+"/session", adm, map[string]any{"mode": "temporary", "minutes": 20}); rec.Code != http.StatusBadRequest {
		t.Fatalf("minutes no longer exist: %d %s", rec.Code, rec.Body)
	}
	if rec := call(h, "PUT", "/v1/admin/systems/"+sys.ID+"/session", adm, map[string]any{"mode": "temporary"}); rec.Code != http.StatusOK ||
		!bytes.Contains(rec.Body.Bytes(), []byte(`"session_mode":"temporary"`)) || bytes.Contains(rec.Body.Bytes(), []byte("session_minutes")) {
		t.Fatalf("set temporary: %d %s", rec.Code, rec.Body)
	}
	if rec := call(h, "PUT", "/v1/admin/systems/"+sys.ID+"/session", adm, map[string]any{"mode": "persistent"}); rec.Code != http.StatusOK ||
		!bytes.Contains(rec.Body.Bytes(), []byte(`"session_mode":"persistent"`)) {
		t.Fatalf("set persistent: %d %s", rec.Code, rec.Body)
	}

	// Deleting a system needs its code as confirmation and takes its dependants with it.
	rec = call(h, "POST", "/v1/admin/systems", adm, map[string]string{"code": "temp", "name": "Temp"})
	var temp struct {
		ID string `json:"id"`
	}
	decode(t, rec, &temp)
	for _, tc := range []struct {
		path string
		want int
	}{
		{"/v1/admin/systems/not-a-uuid?confirm=temp", http.StatusBadRequest},
		{"/v1/admin/systems/" + temp.ID, http.StatusBadRequest},
		{"/v1/admin/systems/" + temp.ID + "?confirm=other", http.StatusBadRequest},
		{"/v1/admin/systems/" + temp.ID + "?confirm=temp", http.StatusNoContent},
		{"/v1/admin/systems/" + temp.ID + "?confirm=temp", http.StatusNotFound},
	} {
		if rec := call(h, "DELETE", tc.path, adm, nil); rec.Code != tc.want {
			t.Fatalf("DELETE %s: got %d, want %d", tc.path, rec.Code, tc.want)
		}
	}

	rec = call(h, "POST", "/v1/admin/tenants", adm, map[string]string{"ruc": "20123456789", "legal_name": "Gym SAC", "trade_name": "Gym Fit"})
	if rec.Code != http.StatusCreated || !bytes.Contains(rec.Body.Bytes(), []byte(`"display_name":"Gym Fit"`)) {
		t.Fatalf("create tenant: %d %s", rec.Code, rec.Body)
	}
	decode(t, rec, &ten)
	if rec := call(h, "POST", "/v1/admin/tenants/"+ten.ID+"/systems", adm, map[string]string{"system_id": sys.ID}); rec.Code != http.StatusNoContent {
		t.Fatalf("enable system: %d %s", rec.Code, rec.Body)
	}
	if rec := call(h, "GET", "/v1/admin/tenants/"+ten.ID, adm, nil); rec.Code != http.StatusOK || !bytes.Contains(rec.Body.Bytes(), []byte(`"code":"olympus"`)) {
		t.Fatalf("tenant must list its systems: %d %s", rec.Code, rec.Body)
	}
	if rec := call(h, "GET", "/v1/admin/tenants", adm, nil); !bytes.Contains(rec.Body.Bytes(), []byte(`"systems":[{`)) {
		t.Fatalf("list must carry systems: %s", rec.Body)
	}
	if rec := call(h, "DELETE", "/v1/admin/tenants/"+ten.ID+"/systems/not-a-uuid", adm, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad system id: %d", rec.Code)
	}
	if rec := call(h, "GET", "/v1/admin/tenants/not-a-uuid", adm, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad tenant id: %d", rec.Code)
	}

	// The owner is created without a password: the DNI is the initial password.
	// The API never takes a password at creation: the DNI is the initial one.
	if rec := call(h, "POST", "/v1/admin/users", adm, map[string]string{"dni": "55555555", "full_name": "Con Clave", "password": "elegida-por-el-cliente"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("a password at creation must be refused: %d %s", rec.Code, rec.Body)
	}
	rec = call(h, "POST", "/v1/admin/users", adm, map[string]string{"dni": "44444444", "full_name": "Dueño Gym"})
	if rec.Code != http.StatusCreated || !bytes.Contains(rec.Body.Bytes(), []byte(`"must_change_password":true`)) ||
		bytes.Contains(rec.Body.Bytes(), []byte("password_hash")) || bytes.Contains(rec.Body.Bytes(), []byte("argon2")) {
		t.Fatalf("create user: %d %s", rec.Code, rec.Body)
	}
	decode(t, rec, &usr)

	// Roles are a catalog per system, and an access can only use one of them.
	rolesPath := "/v1/admin/systems/" + sys.ID + "/roles"
	var dueno, spare struct {
		ID string `json:"id"`
	}
	rec = call(h, "POST", rolesPath, adm, map[string]string{"name": "dueño", "description": "Dirige la empresa"})
	if rec.Code != http.StatusCreated || !bytes.Contains(rec.Body.Bytes(), []byte(`"users":0`)) {
		t.Fatalf("create role: %d %s", rec.Code, rec.Body)
	}
	decode(t, rec, &dueno)
	if rec := call(h, "POST", rolesPath, adm, map[string]string{"name": "otro"}); rec.Code != http.StatusCreated {
		t.Fatalf("create role: %d %s", rec.Code, rec.Body)
	}
	rec = call(h, "POST", rolesPath, adm, map[string]string{"name": "Sobrante"})
	decode(t, rec, &spare)
	for name, want := range map[string]int{"dueño": http.StatusConflict, "Sobrante": http.StatusConflict, "sobrante": http.StatusConflict, "SOBRANTE": http.StatusConflict, "   ": http.StatusBadRequest, "": http.StatusBadRequest} {
		if rec := call(h, "POST", rolesPath, adm, map[string]string{"name": name}); rec.Code != want {
			t.Fatalf("create role %q: got %d, want %d", name, rec.Code, want)
		}
	}
	if rec := call(h, "POST", rolesPath, adm, map[string]string{"name": "x", "color": "rojo"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown field: %d", rec.Code)
	}
	if rec := call(h, "PUT", rolesPath+"/"+dueno.ID, adm, map[string]string{"description": "Dueño del negocio"}); rec.Code != http.StatusOK ||
		!bytes.Contains(rec.Body.Bytes(), []byte(`"name":"dueño"`)) || !bytes.Contains(rec.Body.Bytes(), []byte("Dueño del negocio")) {
		t.Fatalf("update description: %d %s", rec.Code, rec.Body)
	}
	if rec := call(h, "PUT", rolesPath+"/"+dueno.ID, adm, map[string]string{"name": "jefe"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("a role cannot be renamed: %d", rec.Code)
	}
	if rec := call(h, "GET", rolesPath, adm, nil); rec.Code != http.StatusOK || !bytes.Contains(rec.Body.Bytes(), []byte(`"name":"dueño"`)) || !bytes.Contains(rec.Body.Bytes(), []byte(`"name":"otro"`)) {
		t.Fatalf("list roles: %d %s", rec.Code, rec.Body)
	}
	if rec := call(h, "GET", "/v1/admin/systems/not-a-uuid/roles", adm, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad system id: %d", rec.Code)
	}
	if rec := call(h, "POST", "/v1/admin/access", adm, map[string]any{
		"user_id": usr.ID, "system_id": sys.ID, "tenant_id": ten.ID, "role": "inventado",
	}); rec.Code != http.StatusBadRequest || !bytes.Contains(rec.Body.Bytes(), []byte("unknown_role")) {
		t.Fatalf("a role outside the catalog must be refused: %d %s", rec.Code, rec.Body)
	}

	rec = call(h, "POST", "/v1/admin/access", adm, map[string]any{
		"user_id": usr.ID, "system_id": sys.ID, "tenant_id": ten.ID, "role": "dueño", "manage_users": true,
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("assign access: %d %s", rec.Code, rec.Body)
	}
	if rec := call(h, "GET", rolesPath, adm, nil); !bytes.Contains(rec.Body.Bytes(), []byte(`"name":"dueño"`)) || !bytes.Contains(rec.Body.Bytes(), []byte(`"users":1`)) {
		t.Fatalf("the role must count its people: %s", rec.Body)
	}
	if rec := call(h, "DELETE", rolesPath+"/"+dueno.ID, adm, nil); rec.Code != http.StatusConflict || !bytes.Contains(rec.Body.Bytes(), []byte("role_in_use")) {
		t.Fatalf("a role in use cannot be deleted: %d %s", rec.Code, rec.Body)
	}
	if rec := call(h, "DELETE", rolesPath+"/"+spare.ID, adm, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete an unused role: %d", rec.Code)
	}
	if rec := call(h, "DELETE", rolesPath+"/"+spare.ID, adm, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("delete twice: %d", rec.Code)
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
	if rec := call(h, "GET", "/v1/admin/systems/"+sys.ID+"/access", adm, nil); rec.Code != http.StatusOK ||
		!bytes.Contains(rec.Body.Bytes(), []byte(`"role":"dueño"`)) || !bytes.Contains(rec.Body.Bytes(), []byte(`"user_dni":"44444444"`)) {
		t.Fatalf("list system access: %d %s", rec.Code, rec.Body)
	}
	if rec := call(h, "GET", "/v1/admin/systems/not-a-uuid/access", adm, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad system id: %d", rec.Code)
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

func TestTenantOwnerAPI(t *testing.T) {
	ctx := context.Background()
	e := newE2EFull(t)
	h := e.handler

	olympus, _ := e.systems.Create(ctx, system.CreateInput{Code: "olympus", Name: "Olympus"})
	pulso, _ := e.systems.Create(ctx, system.CreateInput{Code: "pulso", Name: "Pulso"})
	gymA, _ := e.tenants.Create(ctx, tenant.CreateInput{RUC: "20111111111", LegalName: "Gym A"})
	gymB, _ := e.tenants.Create(ctx, tenant.CreateInput{RUC: "20222222222", LegalName: "Gym B"})
	for _, ts := range [][2]string{{gymA.ID, olympus.ID}, {gymB.ID, olympus.ID}, {gymB.ID, pulso.ID}} {
		if err := e.tenants.EnableSystem(ctx, ts[0], ts[1]); err != nil {
			t.Fatal(err)
		}
	}
	for _, sys := range []string{olympus.ID, pulso.ID} {
		for _, name := range []string{"dueño", "cajero", "supervisor", "hacked", "x"} {
			if _, err := e.roles.Create(ctx, role.CreateInput{SystemID: sys, Name: name}); err != nil {
				t.Fatal(err)
			}
		}
	}
	mkUser := func(dni, name string) user.User {
		u, err := e.users.Create(ctx, user.CreateInput{DNI: dni, FullName: name, Password: dni + "-secret"})
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	ownerA, ownerB := mkUser("11111111", "Owner A"), mkUser("22222222", "Owner B")
	plain := mkUser("33333333", "Plain Cashier")
	grant := func(u user.User, sys, ten, role string, manage bool) {
		if _, err := e.access.Assign(ctx, access.AssignInput{UserID: u.ID, SystemID: sys, TenantID: ten, Role: role, ManageUsers: manage}); err != nil {
			t.Fatal(err)
		}
	}
	grant(ownerA, olympus.ID, gymA.ID, "dueño", true)
	grant(ownerB, olympus.ID, gymB.ID, "dueño", true)
	grant(plain, olympus.ID, gymA.ID, "cajero", false)

	tokenFor := func(dni, system string) string {
		rec := call(h, "POST", "/v1/login", "", map[string]string{"dni": dni, "password": dni + "-secret", "system": system})
		if rec.Code != http.StatusOK {
			t.Fatalf("login %s: %d %s", dni, rec.Code, rec.Body)
		}
		var tok struct {
			AccessToken string `json:"access_token"`
		}
		decode(t, rec, &tok)
		return tok.AccessToken
	}
	tokA, tokB, tokPlain := tokenFor("11111111", "olympus"), tokenFor("22222222", "olympus"), tokenFor("33333333", "olympus")

	// Only an owner gets in.
	if rec := call(h, "GET", "/v1/tenant/members", "", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous: %d", rec.Code)
	}
	if rec := call(h, "GET", "/v1/tenant/members", tokPlain, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("regular member: %d", rec.Code)
	}
	adminTok := adminToken(t, h)
	if rec := call(h, "GET", "/v1/tenant/members", adminTok, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("the superadmin token is not a tenant owner token: %d", rec.Code)
	}
	if rec := call(h, "GET", "/v1/admin/users", tokA, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("an owner must not reach the superadmin API: %d", rec.Code)
	}

	// Owner A adds a brand new cashier: created with the DNI as password.
	// The owner sees the roles of their own system, chooses from them, and cannot invent one.
	if rec := call(h, "GET", "/v1/tenant/roles", tokA, nil); rec.Code != http.StatusOK ||
		!bytes.Contains(rec.Body.Bytes(), []byte(`"name":"cajero"`)) || !bytes.Contains(rec.Body.Bytes(), []byte(`"name":"supervisor"`)) {
		t.Fatalf("owner roles: %d %s", rec.Code, rec.Body)
	}
	if rec := call(h, "GET", "/v1/tenant/roles", tokPlain, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("a member who is not an owner must not list roles: %d", rec.Code)
	}
	if rec := call(h, "GET", "/v1/tenant/roles", "", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("roles without a token: %d", rec.Code)
	}
	if rec := call(h, "POST", "/v1/tenant/members", tokA, map[string]string{"dni": "77777777", "full_name": "Inventa Rol", "role": "inventado"}); rec.Code != http.StatusBadRequest ||
		!bytes.Contains(rec.Body.Bytes(), []byte("unknown_role")) {
		t.Fatalf("an owner cannot invent a role: %d %s", rec.Code, rec.Body)
	}
	rec := call(h, "POST", "/v1/tenant/members", tokA, map[string]string{"dni": "55555555", "full_name": "Nuevo Cajero", "role": "cajero"})
	if rec.Code != http.StatusCreated || !bytes.Contains(rec.Body.Bytes(), []byte(`"must_change_password":true`)) ||
		!bytes.Contains(rec.Body.Bytes(), []byte(`"manage_users":false`)) {
		t.Fatalf("add: %d %s", rec.Code, rec.Body)
	}
	var added struct {
		UserID string `json:"user_id"`
	}
	decode(t, rec, &added)

	// The new cashier must change the password before getting any token.
	rec = call(h, "POST", "/v1/login", "", map[string]string{"dni": "55555555", "password": "55555555", "system": "olympus"})
	if rec.Code != http.StatusForbidden || !bytes.Contains(rec.Body.Bytes(), []byte("password_change_required")) {
		t.Fatalf("first login: %d %s", rec.Code, rec.Body)
	}

	// Owner A cannot make a manager: the body has no such field.
	if rec := call(h, "POST", "/v1/tenant/members", tokA, map[string]any{"dni": "66666666", "full_name": "X", "role": "r", "manage_users": true}); rec.Code != http.StatusBadRequest {
		t.Fatalf("manage_users in body: %d", rec.Code)
	}

	// Owner B cannot see, change or remove Owner A's people.
	if rec := call(h, "GET", "/v1/tenant/members", tokB, nil); rec.Code != http.StatusOK || bytes.Contains(rec.Body.Bytes(), []byte(added.UserID)) ||
		bytes.Contains(rec.Body.Bytes(), []byte("Owner A")) {
		t.Fatalf("owner B sees A's data: %d %s", rec.Code, rec.Body)
	}
	for _, req := range [][3]string{
		{"PUT", "/v1/tenant/members/" + added.UserID, "role"},
		{"DELETE", "/v1/tenant/members/" + added.UserID, ""},
		{"POST", "/v1/tenant/members/" + added.UserID + "/reset-password", ""},
	} {
		var body any
		if req[2] != "" {
			body = map[string]string{"role": "hacked"}
		}
		if rec := call(h, req[0], req[1], tokB, body); rec.Code != http.StatusNotFound {
			t.Fatalf("%s %s from another tenant: %d", req[0], req[1], rec.Code)
		}
	}

	// Owner A manages their own people.
	if rec := call(h, "PUT", "/v1/tenant/members/"+added.UserID, tokA, map[string]string{"role": "supervisor"}); rec.Code != http.StatusNoContent {
		t.Fatalf("update role: %d %s", rec.Code, rec.Body)
	}
	rec = call(h, "GET", "/v1/tenant/members", tokA, nil)
	if !bytes.Contains(rec.Body.Bytes(), []byte(`"role":"supervisor"`)) || !bytes.Contains(rec.Body.Bytes(), []byte("Nuevo Cajero")) {
		t.Fatalf("list: %s", rec.Body)
	}

	// Owners are protected, including from themselves.
	if rec := call(h, "DELETE", "/v1/tenant/members/"+ownerA.ID, tokA, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("owner removing themselves: %d", rec.Code)
	}

	// Reset: allowed for someone who only exists in this tenant.
	if rec := call(h, "POST", "/v1/tenant/members/"+added.UserID+"/reset-password", tokA, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("reset exclusive member: %d %s", rec.Code, rec.Body)
	}

	// A person who also works for Gym B (in another system) cannot be reset by Owner A.
	if rec := call(h, "POST", "/v1/tenant/members", tokB, map[string]string{"dni": "33333333", "role": "x"}); rec.Code != http.StatusConflict {
		t.Fatalf("a person already in this system under another tenant: %d %s", rec.Code, rec.Body)
	}
	grant(plain, pulso.ID, gymB.ID, "cajero", false)
	if rec := call(h, "POST", "/v1/tenant/members/"+plain.ID+"/reset-password", tokA, nil); rec.Code != http.StatusForbidden ||
		!bytes.Contains(rec.Body.Bytes(), []byte("reset_not_allowed")) {
		t.Fatalf("reset of a shared account: %d %s", rec.Code, rec.Body)
	}
	if rec := call(h, "POST", "/v1/login", "", map[string]string{"dni": "33333333", "password": "33333333-secret", "system": "olympus"}); rec.Code != http.StatusOK {
		t.Fatalf("the shared account must be untouched: %d", rec.Code)
	}

	// Removing access ends the owner's own privileges on the next request, not after the token expires.
	if err := e.access.Remove(ctx, ownerA.ID, olympus.ID); err != nil {
		t.Fatal(err)
	}
	if rec := call(h, "GET", "/v1/tenant/members", tokA, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("revoked owner with a still-valid token: %d", rec.Code)
	}

	// Removing a member from the tenant.
	if rec := call(h, "DELETE", "/v1/tenant/members/"+plain.ID, tokB, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("remove from another tenant: %d", rec.Code)
	}
}

func adminToken(t *testing.T, h http.Handler) string {
	t.Helper()
	rec := call(h, "POST", "/v1/admin/login", "", map[string]string{"dni": "74455518", "password": "a-long-admin-password"})
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	decode(t, rec, &tok)
	return tok.AccessToken
}

// A person who owns two companies in the same system enters the one they used last, switches without a
// password, and manages the members of the company they are working for, never of the other.
func TestOwnerOfTwoCompanies(t *testing.T) {
	ctx := context.Background()
	e := newE2EFull(t)
	h := e.handler

	owner, _ := e.users.Create(ctx, user.CreateInput{DNI: "11111111", FullName: "Percy Dueño", Password: "owner-password"})
	acmeStaff, _ := e.users.Create(ctx, user.CreateInput{DNI: "22222222", FullName: "Staff Acme", Password: "staff-password"})
	globexStaff, _ := e.users.Create(ctx, user.CreateInput{DNI: "33333333", FullName: "Staff Globex", Password: "staff-password"})
	olympus, _ := e.systems.Create(ctx, system.CreateInput{Code: "olympus", Name: "Olympus"})
	if _, err := e.roles.Create(ctx, role.CreateInput{SystemID: olympus.ID, Name: "admin"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.roles.Create(ctx, role.CreateInput{SystemID: olympus.ID, Name: "cajero"}); err != nil {
		t.Fatal(err)
	}
	acme, _ := e.tenants.Create(ctx, tenant.CreateInput{RUC: "20123456789", LegalName: "Acme SAC", TradeName: "Acme"})
	globex, _ := e.tenants.Create(ctx, tenant.CreateInput{RUC: "20987654321", LegalName: "Globex SAC", TradeName: "Globex"})
	for _, tn := range []string{acme.ID, globex.ID} {
		if err := e.tenants.EnableSystem(ctx, tn, olympus.ID); err != nil {
			t.Fatal(err)
		}
	}
	assign := func(userID, tenantID, role string, manage bool) {
		t.Helper()
		if _, err := e.access.Assign(ctx, access.AssignInput{UserID: userID, SystemID: olympus.ID, TenantID: tenantID, Role: role, ManageUsers: manage}); err != nil {
			t.Fatal(err)
		}
	}
	assign(owner.ID, acme.ID, "admin", true)
	assign(owner.ID, globex.ID, "admin", true)
	assign(acmeStaff.ID, acme.ID, "cajero", false)
	assign(globexStaff.ID, globex.ID, "cajero", false)

	type tokens struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	login := func(body map[string]string) (*httptest.ResponseRecorder, tokens) {
		t.Helper()
		body["dni"], body["password"], body["system"] = "11111111", "owner-password", "olympus"
		rec := call(h, "POST", "/v1/login", "", body)
		var tok tokens
		_ = json.Unmarshal(rec.Body.Bytes(), &tok)
		return rec, tok
	}
	memberIDs := func(accessToken string) []string {
		t.Helper()
		rec := call(h, "GET", "/v1/tenant/members", accessToken, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("members: %d %s", rec.Code, rec.Body)
		}
		var body struct {
			Items []struct {
				UserID string `json:"user_id"`
			} `json:"items"`
		}
		decode(t, rec, &body)
		ids := make([]string, 0, len(body.Items))
		for _, m := range body.Items {
			ids = append(ids, m.UserID)
		}
		return ids
	}

	// Never used any company: the first one they were given.
	rec, tok := login(map[string]string{})
	if rec.Code != http.StatusOK || claimsOf(t, tok.AccessToken).Tenant != acme.ID {
		t.Fatalf("first login: %d %s", rec.Code, rec.Body)
	}

	// The selector lists both and marks the one the token is on.
	list := call(h, "GET", "/v1/session/tenants", tok.AccessToken, nil)
	var options struct {
		Items []struct {
			TenantID string `json:"tenant_id"`
			Name     string `json:"name"`
			Current  bool   `json:"current"`
		} `json:"items"`
	}
	decode(t, list, &options)
	if list.Code != http.StatusOK || len(options.Items) != 2 || options.Items[0].Name != "Acme" || !options.Items[0].Current ||
		options.Items[1].Name != "Globex" || options.Items[1].Current {
		t.Fatalf("tenants: %d %s", list.Code, list.Body)
	}
	if rec := call(h, "GET", "/v1/session/tenants", "", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", rec.Code)
	}

	// Members are those of the company of the token.
	if ids := memberIDs(tok.AccessToken); !contains(ids, acmeStaff.ID) || contains(ids, globexStaff.ID) {
		t.Fatalf("acme members: %v", ids)
	}

	// Switching: same session, new company, no password.
	rec = call(h, "POST", "/v1/refresh", "", map[string]string{"refresh_token": tok.RefreshToken, "tenant_id": globex.ID})
	_ = json.Unmarshal(rec.Body.Bytes(), &tok)
	if rec.Code != http.StatusOK || claimsOf(t, tok.AccessToken).Tenant != globex.ID {
		t.Fatalf("switch: %d %s", rec.Code, rec.Body)
	}
	if ids := memberIDs(tok.AccessToken); !contains(ids, globexStaff.ID) || contains(ids, acmeStaff.ID) {
		t.Fatalf("globex members: %v", ids)
	}

	// A plain refresh keeps the company.
	rec = call(h, "POST", "/v1/refresh", "", map[string]string{"refresh_token": tok.RefreshToken})
	_ = json.Unmarshal(rec.Body.Bytes(), &tok)
	if rec.Code != http.StatusOK || claimsOf(t, tok.AccessToken).Tenant != globex.ID {
		t.Fatalf("refresh: %d %s", rec.Code, rec.Body)
	}

	// A company the person does not work for is refused, and their session survives.
	stranger, _ := e.tenants.Create(ctx, tenant.CreateInput{RUC: "20555555555", LegalName: "Stranger SAC"})
	rec = call(h, "POST", "/v1/refresh", "", map[string]string{"refresh_token": tok.RefreshToken, "tenant_id": stranger.ID})
	if rec.Code != http.StatusForbidden || !bytes.Contains(rec.Body.Bytes(), []byte("no_access")) {
		t.Fatalf("switch to a stranger company: %d %s", rec.Code, rec.Body)
	}
	if rec = call(h, "POST", "/v1/refresh", "", map[string]string{"refresh_token": tok.RefreshToken}); rec.Code != http.StatusOK {
		t.Fatalf("the refused switch ended the session: %d", rec.Code)
	}

	// The next login enters the company they used last.
	if rec, next := login(map[string]string{}); rec.Code != http.StatusOK || claimsOf(t, next.AccessToken).Tenant != globex.ID {
		t.Fatalf("login after switching: %d %s", rec.Code, rec.Body)
	}
	// And a company can be asked for at login.
	if rec, next := login(map[string]string{"tenant_id": acme.ID}); rec.Code != http.StatusOK || claimsOf(t, next.AccessToken).Tenant != acme.ID {
		t.Fatalf("login with a company: %d %s", rec.Code, rec.Body)
	}

	// An owner cannot pull another company's staff into theirs.
	rec = call(h, "POST", "/v1/tenant/members", tok.AccessToken, map[string]string{"dni": "22222222", "full_name": "Staff Acme", "role": "cajero"})
	if rec.Code != http.StatusConflict {
		t.Fatalf("adding another company's staff: %d %s", rec.Code, rec.Body)
	}
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
