package access

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
	mux.Handle("POST /v1/admin/access", admin(http.HandlerFunc(h.assign)))
	mux.Handle("DELETE /v1/admin/users/{id}/access/{system_id}", admin(http.HandlerFunc(h.remove)))
	mux.Handle("GET /v1/admin/users/{id}/access", admin(http.HandlerFunc(h.listByUser)))
}

var failures = map[error]httpx.Failure{
	ErrInvalidID:           {Status: http.StatusBadRequest, Message: "Invalid id."},
	ErrInvalidRole:         {Status: http.StatusBadRequest, Message: "The role is required and can have at most 64 characters."},
	ErrUserNotFound:        {Status: http.StatusNotFound, Message: "User not found."},
	ErrAccessNotFound:      {Status: http.StatusNotFound, Message: "The user has no access to that system."},
	ErrUserAlreadyInSystem: {Status: http.StatusConflict, Message: "The user already has access to this system. Remove it first to move them to another tenant."},
	ErrSystemNotEnabled:    {Status: http.StatusConflict, Message: "The tenant has not contracted this system."},
}

type accessJSON struct {
	ID          string    `json:"id"`
	UserID      string    `json:"user_id"`
	SystemID    string    `json:"system_id"`
	SystemCode  string    `json:"system_code,omitempty"`
	TenantID    string    `json:"tenant_id"`
	TenantName  string    `json:"tenant_name,omitempty"`
	Role        string    `json:"role"`
	ManageUsers bool      `json:"manage_users"`
	CreatedAt   time.Time `json:"created_at"`
}

func (h *Handler) assign(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID      string `json:"user_id"`
		SystemID    string `json:"system_id"`
		TenantID    string `json:"tenant_id"`
		Role        string `json:"role"`
		ManageUsers bool   `json:"manage_users"`
	}
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid_request", "Invalid request body.")
		return
	}
	a, err := h.svc.Assign(r.Context(), AssignInput{
		UserID: req.UserID, SystemID: req.SystemID, TenantID: req.TenantID, Role: req.Role, ManageUsers: req.ManageUsers,
	})
	if err != nil {
		httpx.Fail(w, r, h.log, err, failures)
		return
	}
	httpx.JSON(w, http.StatusCreated, accessJSON{
		ID: a.ID, UserID: a.UserID, SystemID: a.SystemID, TenantID: a.TenantID,
		Role: a.Role, ManageUsers: a.ManageUsers, CreatedAt: a.CreatedAt,
	})
}

func (h *Handler) remove(w http.ResponseWriter, r *http.Request) {
	if err := h.svc.Remove(r.Context(), r.PathValue("id"), r.PathValue("system_id")); err != nil {
		httpx.Fail(w, r, h.log, err, failures)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) listByUser(w http.ResponseWriter, r *http.Request) {
	details, err := h.svc.ListByUser(r.Context(), r.PathValue("id"))
	if err != nil {
		httpx.Fail(w, r, h.log, err, failures)
		return
	}
	out := make([]accessJSON, 0, len(details))
	for _, d := range details {
		out = append(out, accessJSON{
			ID: d.ID, UserID: d.UserID, SystemID: d.SystemID, SystemCode: d.SystemCode,
			TenantID: d.TenantID, TenantName: d.TenantName, Role: d.Role, ManageUsers: d.ManageUsers, CreatedAt: d.CreatedAt,
		})
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": out})
}
