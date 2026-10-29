package auth

import (
	"context"
	"net/http"
	"strings"

	"github.com/AtmosferaSoltec/atm-auth-api/internal/httpx"
	"github.com/AtmosferaSoltec/atm-auth-api/internal/platform"
)

type Verifier interface {
	Verify(token string) (platform.Claims, error)
}

type ctxKey struct{}

// ClaimsFromContext returns the claims set by RequireRole.
func ClaimsFromContext(ctx context.Context) (platform.Claims, bool) {
	c, ok := ctx.Value(ctxKey{}).(platform.Claims)
	return c, ok
}

// RequireRole accepts only requests with a valid bearer token carrying the given role.
func RequireRole(v Verifier, role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			if !ok || token == "" {
				httpx.Error(w, http.StatusUnauthorized, "unauthorized", "Missing or invalid access token.")
				return
			}
			claims, err := v.Verify(token)
			if err != nil {
				httpx.Error(w, http.StatusUnauthorized, "unauthorized", "Missing or invalid access token.")
				return
			}
			if claims.Role != role {
				httpx.Error(w, http.StatusForbidden, "forbidden", "Insufficient permissions.")
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, claims)))
		})
	}
}
