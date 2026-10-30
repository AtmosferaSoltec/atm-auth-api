package tenant

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/AtmosferaSoltec/atm-auth-api/internal/auth"
	"github.com/AtmosferaSoltec/atm-auth-api/internal/httpx"
	"github.com/AtmosferaSoltec/atm-auth-api/internal/platform"
)

type tokenVerifier map[string]platform.Claims

func (v tokenVerifier) Verify(token string) (platform.Claims, error) {
	if c, ok := v[token]; ok {
		return c, nil
	}
	return platform.Claims{}, errors.New("invalid token")
}

type systemsRepo struct {
	*fakeRepo
	asked string
	items []Tenant
}

func (r *systemsRepo) ListForSystem(_ context.Context, code string) ([]Tenant, error) {
	r.asked = code
	return r.items, nil
}

func TestServiceTenantsRoute(t *testing.T) {
	repo := &systemsRepo{fakeRepo: newFakeRepo(), items: []Tenant{
		{ID: "t1", RUC: "10471983751", LegalName: "TASAYCO HERNANDEZ JESUS", TradeName: "La Vendimia", ClientID: "c1", ClientName: "Familia Tasayco", Status: StatusActive},
		{ID: "t2", RUC: "20612480070", LegalName: "LOGISTICA EXPRESS S.A.C.", Status: StatusActive},
	}}
	verifier := tokenVerifier{
		"service-token": {Role: "service", System: "lavendimia", Subject: "system:lavendimia"},
		"user-token":    {Role: "user", System: "lavendimia", Tenant: "t1"},
		"admin-token":   {Role: "superadmin"},
	}
	mux := http.NewServeMux()
	NewHandler(NewService(repo), slog.New(slog.NewTextHandler(io.Discard, nil))).
		RegisterService(mux, httpx.Middleware(auth.RequireRole(verifier, "service")))

	get := func(token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/v1/service/tenants", nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}

	t.Run("a system sees only its own customers, and only what it needs", func(t *testing.T) {
		rec := get("service-token")
		if rec.Code != http.StatusOK {
			t.Fatalf("got %d %s", rec.Code, rec.Body)
		}
		if repo.asked != "lavendimia" {
			t.Fatalf("the system must come from the token, got %q", repo.asked)
		}
		var body struct {
			Items []map[string]string `json:"items"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || len(body.Items) != 2 {
			t.Fatalf("got %s err %v", rec.Body, err)
		}
		first := body.Items[0]
		if first["ruc"] != "10471983751" || first["legal_name"] != "TASAYCO HERNANDEZ JESUS" || first["display_name"] != "La Vendimia" || first["id"] != "t1" ||
			first["client_id"] != "c1" || first["client_name"] != "Familia Tasayco" {
			t.Fatalf("got %+v", first)
		}
		if _, leaked := first["systems"]; leaked {
			t.Fatal("a system must not learn which other systems a customer has")
		}
	})

	t.Run("an empty list is [] and not null", func(t *testing.T) {
		repo.items = nil
		if body := get("service-token").Body.String(); body != "{\"items\":[]}\n" && body != "{\"items\":[]}" {
			t.Fatalf("got %q", body)
		}
	})

	for name, tc := range map[string]struct {
		token string
		want  int
	}{
		"no token":             {"", http.StatusUnauthorized},
		"an invalid token":     {"nope", http.StatusUnauthorized},
		"a user token":         {"user-token", http.StatusForbidden},
		"the superadmin token": {"admin-token", http.StatusForbidden},
	} {
		t.Run(name+" is refused", func(t *testing.T) {
			if rec := get(tc.token); rec.Code != tc.want {
				t.Fatalf("got %d", rec.Code)
			}
		})
	}
}
