package system

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/AtmosferaSoltec/atm-auth-api/internal/httpx"
)

type Handler struct {
	svc *Service
	log *slog.Logger
}

func NewHandler(svc *Service, log *slog.Logger) *Handler {
	return &Handler{svc: svc, log: log}
}

// Register mounts the superadmin routes. admin must reject anyone who is not the superadmin.
func (h *Handler) Register(mux *http.ServeMux, admin httpx.Middleware) {
	mux.Handle("GET /v1/admin/systems", admin(http.HandlerFunc(h.list)))
	mux.Handle("PUT /v1/admin/systems/{id}/session", admin(http.HandlerFunc(h.updateSession)))
}

var failures = map[error]httpx.Failure{
	ErrInvalidID:          {Status: http.StatusBadRequest, Message: "Invalid id."},
	ErrInvalidSessionMode: {Status: http.StatusBadRequest, Message: "The session mode must be 'persistent' or 'temporary'."},
	ErrSystemNotFound:     {Status: http.StatusNotFound, Message: "System not found."},
}

type systemJSON struct {
	ID     string `json:"id"`
	Code   string `json:"code"`
	Name   string `json:"name"`
	Status string `json:"status"`
	// SessionMode is "persistent" (remembers the user) or "temporary" (does not).
	SessionMode string `json:"session_mode"`
	// HasSecret says whether the system can ask for service tokens. The secret itself is never returned.
	HasSecret        bool       `json:"has_secret"`
	SecretCreatedAt  *time.Time `json:"secret_created_at,omitempty"`
	SecretLastUsedAt *time.Time `json:"secret_last_used_at,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
}

func toJSON(s System) systemJSON {
	return systemJSON{
		ID: s.ID, Code: s.Code, Name: s.Name, Status: s.Status,
		SessionMode: s.SessionMode,
		HasSecret:   s.HasSecret, SecretCreatedAt: s.SecretCreatedAt, SecretLastUsedAt: s.SecretLastUsedAt, CreatedAt: s.CreatedAt,
	}
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	systems, err := h.svc.List(r.Context())
	if err != nil {
		httpx.Fail(w, r, h.log, err, failures)
		return
	}
	out := make([]systemJSON, 0, len(systems))
	for _, s := range systems {
		out = append(out, toJSON(s))
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": out})
}

func (h *Handler) updateSession(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Mode string `json:"mode"`
	}
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid_request", "Invalid request body.")
		return
	}
	s, err := h.svc.UpdateSession(r.Context(), r.PathValue("id"), req.Mode)
	if err != nil {
		httpx.Fail(w, r, h.log, err, failures)
		return
	}
	httpx.JSON(w, http.StatusOK, toJSON(s))
}
