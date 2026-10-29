package credential

import (
	"log/slog"
	"net/http"

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
	mux.Handle("POST /v1/admin/systems/{id}/secret", admin(http.HandlerFunc(h.generate)))
	mux.Handle("DELETE /v1/admin/systems/{id}/secret", admin(http.HandlerFunc(h.revoke)))
}

var failures = map[error]httpx.Failure{
	ErrInvalidID:      {Status: http.StatusBadRequest, Message: "Invalid id."},
	ErrSystemNotFound: {Status: http.StatusNotFound, Message: "System not found."},
}

// generate answers with the new secret. It is the only time the secret is available.
func (h *Handler) generate(w http.ResponseWriter, r *http.Request) {
	issued, err := h.svc.Generate(r.Context(), r.PathValue("id"))
	if err != nil {
		httpx.Fail(w, r, h.log, err, failures)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	httpx.JSON(w, http.StatusOK, map[string]string{"client_id": issued.ClientID, "client_secret": issued.ClientSecret})
}

func (h *Handler) revoke(w http.ResponseWriter, r *http.Request) {
	if err := h.svc.Revoke(r.Context(), r.PathValue("id")); err != nil {
		httpx.Fail(w, r, h.log, err, failures)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
