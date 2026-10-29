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
	mux.Handle("POST /v1/admin/systems", admin(http.HandlerFunc(h.create)))
	mux.Handle("GET /v1/admin/systems", admin(http.HandlerFunc(h.list)))
}

var failures = map[error]httpx.Failure{
	ErrInvalidCode: {Status: http.StatusBadRequest, Message: "The code must be lowercase letters, digits, '-' or '_', starting with a letter."},
	ErrInvalidName: {Status: http.StatusBadRequest, Message: "The name is required."},
	ErrCodeTaken:   {Status: http.StatusConflict, Message: "A system with that code already exists."},
}

type systemJSON struct {
	ID        string    `json:"id"`
	Code      string    `json:"code"`
	Name      string    `json:"name"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

func toJSON(s System) systemJSON {
	return systemJSON{ID: s.ID, Code: s.Code, Name: s.Name, Status: s.Status, CreatedAt: s.CreatedAt}
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code string `json:"code"`
		Name string `json:"name"`
	}
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid_request", "Invalid request body.")
		return
	}
	s, err := h.svc.Create(r.Context(), CreateInput{Code: req.Code, Name: req.Name})
	if err != nil {
		httpx.Fail(w, r, h.log, err, failures)
		return
	}
	httpx.JSON(w, http.StatusCreated, toJSON(s))
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
