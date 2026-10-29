package user

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
	mux.Handle("POST /v1/admin/users", admin(http.HandlerFunc(h.create)))
	mux.Handle("GET /v1/admin/users", admin(http.HandlerFunc(h.list)))
	mux.Handle("POST /v1/admin/users/{id}/reset-password", admin(http.HandlerFunc(h.resetPassword)))
	mux.Handle("PUT /v1/admin/users/{id}/status", admin(http.HandlerFunc(h.setStatus)))
}

var failures = map[error]httpx.Failure{
	ErrInvalidDNI:    {Status: http.StatusBadRequest, Message: "The DNI must have 8 digits."},
	ErrInvalidName:   {Status: http.StatusBadRequest, Message: "The full name is required."},
	ErrInvalidStatus: {Status: http.StatusBadRequest, Message: "The status must be 'active' or 'disabled'."},
	ErrInvalidID:     {Status: http.StatusBadRequest, Message: "Invalid id."},
	ErrWeakPassword:  {Status: http.StatusBadRequest, Message: "The password must have at least 8 characters."},
	ErrDNITaken:      {Status: http.StatusConflict, Message: "A user with that DNI already exists."},
	ErrUserNotFound:  {Status: http.StatusNotFound, Message: "User not found."},
}

// userJSON never includes the password hash.
type userJSON struct {
	ID                 string    `json:"id"`
	DNI                string    `json:"dni"`
	FullName           string    `json:"full_name"`
	Status             string    `json:"status"`
	MustChangePassword bool      `json:"must_change_password"`
	CreatedAt          time.Time `json:"created_at"`
}

func toJSON(u User) userJSON {
	return userJSON{
		ID: u.ID, DNI: u.DNI, FullName: u.FullName, Status: u.Status,
		MustChangePassword: u.MustChangePassword, CreatedAt: u.CreatedAt,
	}
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DNI      string `json:"dni"`
		FullName string `json:"full_name"`
		Password string `json:"password"`
	}
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid_request", "Invalid request body.")
		return
	}
	u, err := h.svc.Create(r.Context(), CreateInput{DNI: req.DNI, FullName: req.FullName, Password: req.Password})
	if err != nil {
		httpx.Fail(w, r, h.log, err, failures)
		return
	}
	httpx.JSON(w, http.StatusCreated, toJSON(u))
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	users, err := h.svc.List(r.Context())
	if err != nil {
		httpx.Fail(w, r, h.log, err, failures)
		return
	}
	out := make([]userJSON, 0, len(users))
	for _, u := range users {
		out = append(out, toJSON(u))
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": out})
}

func (h *Handler) resetPassword(w http.ResponseWriter, r *http.Request) {
	if err := h.svc.ResetPassword(r.Context(), r.PathValue("id")); err != nil {
		httpx.Fail(w, r, h.log, err, failures)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) setStatus(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Status string `json:"status"`
	}
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid_request", "Invalid request body.")
		return
	}
	if err := h.svc.SetStatus(r.Context(), r.PathValue("id"), req.Status); err != nil {
		httpx.Fail(w, r, h.log, err, failures)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
