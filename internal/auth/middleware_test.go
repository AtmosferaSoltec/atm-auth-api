package auth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/AtmosferaSoltec/atm-auth-api/internal/platform"
)

type fakeVerifier map[string]platform.Claims

func (f fakeVerifier) Verify(token string) (platform.Claims, error) {
	if c, ok := f[token]; ok {
		return c, nil
	}
	return platform.Claims{}, errors.New("bad")
}

func TestRequireRole(t *testing.T) {
	v := fakeVerifier{"admin-token": {Role: "superadmin"}, "user-token": {Role: "user"}}
	h := RequireRole(v, "superadmin")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := ClaimsFromContext(r.Context()); !ok {
			t.Error("claims missing from context")
		}
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name, header string
		want         int
	}{
		{"no header", "", http.StatusUnauthorized},
		{"wrong scheme", "Basic abc", http.StatusUnauthorized},
		{"empty bearer", "Bearer ", http.StatusUnauthorized},
		{"invalid token", "Bearer nope", http.StatusUnauthorized},
		{"wrong role", "Bearer user-token", http.StatusForbidden},
		{"superadmin", "Bearer admin-token", http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tt.want {
				t.Fatalf("got %d, want %d", rec.Code, tt.want)
			}
		})
	}
}
