package member

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AtmosferaSoltec/atm-auth-api/internal/auth"
	"github.com/AtmosferaSoltec/atm-auth-api/internal/httpx"
	"github.com/AtmosferaSoltec/atm-auth-api/internal/platform"
)

type tokens map[string]platform.Claims

func (t tokens) Verify(token string) (platform.Claims, error) {
	if c, ok := t[token]; ok {
		return c, nil
	}
	return platform.Claims{}, errors.New("invalid token")
}

func serviceMux(f *fixture) *http.ServeMux {
	verifier := tokens{
		"olympus-service": {Role: "service", System: "olympus"},
		"pulso-service":   {Role: "service", System: "pulso"},
		"a-user":          {Role: "user", System: "olympus", Tenant: tenantID, Subject: owner},
	}
	mux := http.NewServeMux()
	NewHandler(f.svc, slog.New(slog.NewTextHandler(io.Discard, nil)), verifier).
		RegisterService(mux, httpx.Middleware(auth.RequireRole(verifier, "service")))
	return mux
}

func call(mux *http.ServeMux, method, path, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestServiceRoutes(t *testing.T) {
	members := "/v1/service/members?tenant_id=" + tenantID

	tests := []struct {
		name   string
		method string
		path   string
		token  string
		body   string
		want   int
	}{
		{"a system lists the members of a company it serves", "GET", members, "olympus-service", "", http.StatusOK},
		{"a system adds a member", "POST", members, "olympus-service", `{"dni":"77777777","full_name":"Nueva","role":"cajero"}`, http.StatusCreated},
		{"a system changes a role", "PUT", "/v1/service/members/" + cashier + "?tenant_id=" + tenantID, "olympus-service", `{"role":"admin"}`, http.StatusNoContent},
		{"a system removes a member", "DELETE", "/v1/service/members/" + cashier + "?tenant_id=" + tenantID, "olympus-service", "", http.StatusNoContent},
		{"a system resets a password", "POST", "/v1/service/members/" + cashier + "/reset-password?tenant_id=" + tenantID, "olympus-service", "", http.StatusNoContent},
		{"a system reads its roles", "GET", "/v1/service/roles?tenant_id=" + tenantID, "olympus-service", "", http.StatusOK},
		{"another system cannot reach a company it does not serve", "GET", members, "pulso-service", "", http.StatusForbidden},
		{"the tenant is required", "GET", "/v1/service/members", "olympus-service", "", http.StatusBadRequest},
		{"a user token is not a service token", "GET", members, "a-user", "", http.StatusForbidden},
		{"no token", "GET", members, "", "", http.StatusUnauthorized},
		{"a forged token", "GET", members, "made-up", "", http.StatusUnauthorized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture()
			f.repo.roles = []RoleOption{{Name: "admin"}}
			f.access.grants["new-77777777"] = f.access.grants[cashier]
			delete(f.access.grants, "new-77777777") // the new person has no other company
			f.repo.members["new-77777777"] = Member{UserID: "new-77777777", Role: "cajero"}
			f.finder.users["new-77777777"] = f.finder.users[cashier]

			if got := call(serviceMux(f), tt.method, tt.path, tt.token, tt.body).Code; got != tt.want {
				t.Fatalf("got %d, want %d", got, tt.want)
			}
		})
	}
}

// The system never receives members of another company, even though it names the tenant itself.
func TestServiceScopeUsesTheTokenSystem(t *testing.T) {
	f := newFixture()
	rec := call(serviceMux(f), "GET", "/v1/service/members?tenant_id="+tenantID, "pulso-service", "")

	if rec.Code != http.StatusForbidden {
		t.Fatalf("got %d", rec.Code)
	}
	if _, err := f.svc.ScopeFor(context.Background(), "pulso", tenantID); !errors.Is(err, ErrTenantNotServed) {
		t.Fatalf("got %v", err)
	}
}
