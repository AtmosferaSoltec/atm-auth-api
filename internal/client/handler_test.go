package client

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AtmosferaSoltec/atm-auth-api/internal/httpx"
)

func newMux(repo Repository) *http.ServeMux {
	mux := http.NewServeMux()
	passThrough := httpx.Middleware(func(next http.Handler) http.Handler { return next })
	NewHandler(NewService(repo), slog.New(slog.NewTextHandler(io.Discard, nil))).Register(mux, passThrough)
	return mux
}

func do(mux *http.ServeMux, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestHandlerStatusCodes(t *testing.T) {
	tests := []struct {
		name   string
		repo   *fakeRepo
		method string
		path   string
		body   string
		want   int
	}{
		{"create", &fakeRepo{}, "POST", "/v1/admin/clients", `{"name":"Percy"}`, http.StatusCreated},
		{"create without a name", &fakeRepo{}, "POST", "/v1/admin/clients", `{"name":" "}`, http.StatusBadRequest},
		{"create with a broken body", &fakeRepo{}, "POST", "/v1/admin/clients", `{`, http.StatusBadRequest},
		{"rename", &fakeRepo{}, "PUT", "/v1/admin/clients/" + someID, `{"name":"Nuevo"}`, http.StatusOK},
		{"rename a missing client", &fakeRepo{err: ErrClientNotFound}, "PUT", "/v1/admin/clients/" + someID, `{"name":"Nuevo"}`, http.StatusNotFound},
		{"get with a bad id", &fakeRepo{}, "GET", "/v1/admin/clients/nope", "", http.StatusBadRequest},
		{"list", &fakeRepo{}, "GET", "/v1/admin/clients", "", http.StatusOK},
		{"delete", &fakeRepo{}, "DELETE", "/v1/admin/clients/" + someID, "", http.StatusNoContent},
		{"delete a client that still has companies", &fakeRepo{err: ErrClientHasTenants}, "DELETE", "/v1/admin/clients/" + someID, "", http.StatusConflict},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := do(newMux(tt.repo), tt.method, tt.path, tt.body).Code; got != tt.want {
				t.Fatalf("got %d, want %d", got, tt.want)
			}
		})
	}
}

func TestListNeverReturnsNullCompanies(t *testing.T) {
	rec := do(newMux(&fakeRepo{}), "GET", "/v1/admin/clients/"+someID, "")

	if !strings.Contains(rec.Body.String(), `"tenants":[]`) {
		t.Fatalf("a client without companies must list an empty array, got %s", rec.Body.String())
	}
}
