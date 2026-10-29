package server

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/AtmosferaSoltec/atm-auth-api/internal/access"
	"github.com/AtmosferaSoltec/atm-auth-api/internal/auth"
	"github.com/AtmosferaSoltec/atm-auth-api/internal/credential"
	"github.com/AtmosferaSoltec/atm-auth-api/internal/httpx"
	"github.com/AtmosferaSoltec/atm-auth-api/internal/member"
	"github.com/AtmosferaSoltec/atm-auth-api/internal/role"
	"github.com/AtmosferaSoltec/atm-auth-api/internal/session"
	"github.com/AtmosferaSoltec/atm-auth-api/internal/system"
	"github.com/AtmosferaSoltec/atm-auth-api/internal/tenant"
	"github.com/AtmosferaSoltec/atm-auth-api/internal/user"
)

// Deps are the collaborators the router needs.
type Deps struct {
	DB       Pinger
	Verifier auth.Verifier
	JWKS     []byte
	Session  *session.Handler
	Systems  *system.Handler
	Tenants  *tenant.Handler
	Users    *user.Handler
	Access   *access.Handler
	Members  *member.Handler
	Secrets  *credential.Handler
	Roles    *role.Handler
}

// Pinger reports whether a dependency is reachable.
type Pinger interface {
	Ping(ctx context.Context) error
}

// New builds the HTTP handler with all routes and middlewares.
func New(log *slog.Logger, d Deps) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", health)
	mux.HandleFunc("GET /ready", ready(d.DB))
	mux.HandleFunc("GET /.well-known/jwks.json", jwks(d.JWKS))
	d.Session.Register(mux)
	d.Members.Register(mux)

	requireAdmin := httpx.Middleware(auth.RequireRole(d.Verifier, session.RoleSuperadmin))
	for _, h := range []interface {
		Register(*http.ServeMux, httpx.Middleware)
	}{d.Systems, d.Tenants, d.Users, d.Access, d.Secrets, d.Roles} {
		h.Register(mux, requireAdmin)
	}
	mux.Handle("GET /v1/admin/me", requireAdmin(http.HandlerFunc(adminMe)))

	var h http.Handler = mux
	h = httpx.Recover(log, h)
	h = httpx.Logger(log, h)
	h = httpx.RequestID(h)
	return h
}

func health(w http.ResponseWriter, r *http.Request) {
	httpx.JSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func ready(db Pinger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := db.Ping(ctx); err != nil {
			httpx.Error(w, http.StatusServiceUnavailable, "not_ready", "Service is not ready.")
			return
		}
		httpx.JSON(w, http.StatusOK, map[string]string{"status": "ready"})
	}
}

func jwks(body []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_, _ = w.Write(body)
	}
}

func adminMe(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.ClaimsFromContext(r.Context())
	httpx.JSON(w, http.StatusOK, map[string]string{"sub": claims.Subject, "role": claims.Role})
}
