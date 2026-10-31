package role

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
	mux.Handle("GET /v1/admin/systems/{id}/roles", admin(http.HandlerFunc(h.list)))
}

var failures = map[error]httpx.Failure{
	ErrInvalidID: {Status: http.StatusBadRequest, Message: "Invalid id."},
}

type roleJSON struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Active      bool      `json:"active"`
	Users       int       `json:"users"`
	CreatedAt   time.Time `json:"created_at"`
}

func toJSON(r Role) roleJSON {
	return roleJSON{ID: r.ID, Name: r.Name, Description: r.Description, Active: r.Active, Users: r.Users, CreatedAt: r.CreatedAt}
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	roles, err := h.svc.List(r.Context(), r.PathValue("id"))
	if err != nil {
		httpx.Fail(w, r, h.log, err, failures)
		return
	}
	out := make([]roleJSON, 0, len(roles))
	for _, role := range roles {
		out = append(out, toJSON(role))
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": out})
}
