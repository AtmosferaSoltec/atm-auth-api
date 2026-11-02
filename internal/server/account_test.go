package server_test

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"testing"

	"github.com/AtmosferaSoltec/atm-auth-api/internal/access"
	"github.com/AtmosferaSoltec/atm-auth-api/internal/platform"
	"github.com/AtmosferaSoltec/atm-auth-api/internal/tenant"
)

// fakeHook plays the system that deletes its data of the person (Orbita).
type fakeHook struct {
	mu     sync.Mutex
	calls  []string
	status int
	auth   string
}

func (f *fakeHook) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var body struct {
		UserID string `json:"user_id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	f.calls = append(f.calls, body.UserID)
	f.auth = r.Header.Get("Authorization")
	if f.status != 0 {
		w.WriteHeader(f.status)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func registerAna(t *testing.T, e *e2e) tokenBody {
	t.Helper()
	rec := call(e.handler, "POST", "/v1/register", "", map[string]string{"system": "orbitatest", "email": "ana@example.com", "full_name": "Ana", "password": "ana-password-1"})
	var tok tokenBody
	_ = json.Unmarshal(rec.Body.Bytes(), &tok)
	return tok
}

func TestDeleteAccountWithPassword(t *testing.T) {
	e := newE2EFull(t)
	e.seedPersonal(t, "orbitatest")
	tok := registerAna(t, e)
	h := e.handler

	if rec := call(h, "DELETE", "/v1/account", tok.AccessToken, map[string]string{"password": "wrong-password"}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password: %d %s", rec.Code, rec.Body)
	}
	if rec := call(h, "DELETE", "/v1/account", "", map[string]string{"password": "ana-password-1"}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", rec.Code)
	}
	if len(e.hook.calls) != 0 {
		t.Fatal("nothing may be cleaned before the identity is confirmed")
	}
	if rec := call(h, "DELETE", "/v1/account", tok.AccessToken, map[string]string{"password": "ana-password-1"}); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body)
	}
	if len(e.hook.calls) != 1 || e.hook.auth == "" {
		t.Fatalf("the system must be asked once, with a token: %v", e.hook.calls)
	}
	if rec := call(h, "POST", "/v1/login", "", map[string]string{"system": "orbitatest", "email": "ana@example.com", "password": "ana-password-1"}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("login after delete: %d", rec.Code)
	}
	// The email is free again.
	if rec := call(h, "POST", "/v1/register", "", map[string]string{"system": "orbitatest", "email": "ana@example.com", "full_name": "Ana", "password": "ana-password-2"}); rec.Code != http.StatusCreated {
		t.Fatalf("re-register: %d %s", rec.Code, rec.Body)
	}
}

func TestDeleteAccountKeepsEverythingWhenTheSystemFails(t *testing.T) {
	e := newE2EFull(t)
	e.seedPersonal(t, "orbitatest")
	tok := registerAna(t, e)
	e.hook.status = http.StatusInternalServerError

	if rec := call(e.handler, "DELETE", "/v1/account", tok.AccessToken, map[string]string{"password": "ana-password-1"}); rec.Code != http.StatusBadGateway {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
	if rec := call(e.handler, "POST", "/v1/login", "", map[string]string{"system": "orbitatest", "email": "ana@example.com", "password": "ana-password-1"}); rec.Code != http.StatusOK {
		t.Fatalf("the account must still exist: %d", rec.Code)
	}
}

func TestDeleteAccountWithGoogle(t *testing.T) {
	e := newE2EFull(t)
	e.seedPersonal(t, "orbitatest")
	h := e.handler
	rec := call(h, "POST", "/v1/google", "", map[string]string{"system": "orbitatest", "credential": "ok:sub-g:gina@example.com", "nonce": e.nonce(t)})
	var tok tokenBody
	_ = json.Unmarshal(rec.Body.Bytes(), &tok)

	// Another Google identity cannot delete this account.
	if rec := call(h, "DELETE", "/v1/account", tok.AccessToken, map[string]string{"credential": "ok:other:gina@example.com", "nonce": e.nonce(t)}); rec.Code != http.StatusForbidden {
		t.Fatalf("other identity: %d %s", rec.Code, rec.Body)
	}
	if rec := call(h, "DELETE", "/v1/account", tok.AccessToken, map[string]string{"credential": "ok:sub-g:gina@example.com", "nonce": e.nonce(t)}); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body)
	}
}

func TestDeleteAccountRefusedForCompanyUsers(t *testing.T) {
	e := newE2EFull(t)
	e.seedPersonal(t, "orbitatest")
	tok := registerAna(t, e)
	// The same person also works in a company system: deleting the global account would remove that too.
	sys := e.seedSystem(t, "company", "Company")
	userID := claimsOf(t, tok.AccessToken).Subject
	ctx := context.Background()
	acme, err := e.tenants.Create(ctx, tenant.CreateInput{RUC: "20123456789", LegalName: "Acme SAC"})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.tenants.EnableSystem(ctx, acme.ID, sys.ID); err != nil {
		t.Fatal(err)
	}
	platform.SeedRoles(t, e.pool, sys.ID, "admin")
	if _, err := e.access.Assign(ctx, access.AssignInput{UserID: userID, SystemID: sys.ID, TenantID: acme.ID, Role: "admin"}); err != nil {
		t.Fatal(err)
	}
	if rec := call(e.handler, "DELETE", "/v1/account", tok.AccessToken, map[string]string{"password": "ana-password-1"}); rec.Code != http.StatusConflict {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
}
