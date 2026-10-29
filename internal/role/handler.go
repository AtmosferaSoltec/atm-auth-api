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
	mux.Handle("POST /v1/admin/systems/{id}/roles", admin(http.HandlerFunc(h.create)))
	mux.Handle("PUT /v1/admin/systems/{id}/roles/{role_id}", admin(http.HandlerFunc(h.updateDescription)))
	mux.Handle("DELETE /v1/admin/systems/{id}/roles/{role_id}", admin(http.HandlerFunc(h.delete)))
}

var failures = map[error]httpx.Failure{
	ErrInvalidID:          {Status: http.StatusBadRequest, Message: "Invalid id."},
	ErrInvalidName:        {Status: http.StatusBadRequest, Message: "The role name is required and can have at most 64 characters."},
	ErrInvalidDescription: {Status: http.StatusBadRequest, Message: "The description can have at most 200 characters."},
	ErrSystemNotFound:     {Status: http.StatusNotFound, Message: "System not found."},
	ErrRoleNotFound:       {Status: http.StatusNotFound, Message: "Role not found."},
	ErrRoleExists:         {Status: http.StatusConflict, Message: "The system already has a role with that name."},
	ErrRoleInUse:          {Status: http.StatusConflict, Message: "Someone still has this role. Change their role or remove their access first."},
}

type roleJSON struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Users       int       `json:"users"`
	CreatedAt   time.Time `json:"created_at"`
}

func toJSON(r Role) roleJSON {
	return roleJSON{ID: r.ID, Name: r.Name, Description: r.Description, Users: r.Users, CreatedAt: r.CreatedAt}
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

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid_request", "Invalid request body.")
		return
	}
	created, err := h.svc.Create(r.Context(), CreateInput{SystemID: r.PathValue("id"), Name: req.Name, Description: req.Description})
	if err != nil {
		httpx.Fail(w, r, h.log, err, failures)
		return
	}
	httpx.JSON(w, http.StatusCreated, toJSON(created))
}

// updateDescription changes only the description: the name is what systems compare, so it never changes.
func (h *Handler) updateDescription(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Description string `json:"description"`
	}
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid_request", "Invalid request body.")
		return
	}
	updated, err := h.svc.UpdateDescription(r.Context(), r.PathValue("id"), r.PathValue("role_id"), req.Description)
	if err != nil {
		httpx.Fail(w, r, h.log, err, failures)
		return
	}
	httpx.JSON(w, http.StatusOK, toJSON(updated))
}

func (h *Handler) delete(w http.ResponseWriter, r *http.Request) {
	if err := h.svc.Delete(r.Context(), r.PathValue("id"), r.PathValue("role_id")); err != nil {
		httpx.Fail(w, r, h.log, err, failures)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
