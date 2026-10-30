package client

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
	mux.Handle("POST /v1/admin/clients", admin(http.HandlerFunc(h.create)))
	mux.Handle("GET /v1/admin/clients", admin(http.HandlerFunc(h.list)))
	mux.Handle("GET /v1/admin/clients/{id}", admin(http.HandlerFunc(h.get)))
	mux.Handle("PUT /v1/admin/clients/{id}", admin(http.HandlerFunc(h.rename)))
	mux.Handle("DELETE /v1/admin/clients/{id}", admin(http.HandlerFunc(h.delete)))
}

var failures = map[error]httpx.Failure{
	ErrInvalidID:        {Status: http.StatusBadRequest, Message: "Invalid id."},
	ErrInvalidName:      {Status: http.StatusBadRequest, Message: "The name is required."},
	ErrNameTooLong:      {Status: http.StatusBadRequest, Message: "The name is too long."},
	ErrClientNotFound:   {Status: http.StatusNotFound, Message: "Client not found."},
	ErrClientHasTenants: {Status: http.StatusConflict, Message: "The client still has companies. Move them to another client first."},
}

type tenantRefJSON struct {
	ID          string `json:"id"`
	RUC         string `json:"ruc"`
	DisplayName string `json:"display_name"`
}

type clientJSON struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	// Tenants is never null: a client without companies has an empty list.
	Tenants []tenantRefJSON `json:"tenants"`
}

func toJSON(c Client) clientJSON {
	tenants := make([]tenantRefJSON, 0, len(c.Tenants))
	for _, t := range c.Tenants {
		tenants = append(tenants, tenantRefJSON{ID: t.ID, RUC: t.RUC, DisplayName: t.DisplayName})
	}
	return clientJSON{ID: c.ID, Name: c.Name, CreatedAt: c.CreatedAt, Tenants: tenants}
}

type nameRequest struct {
	Name string `json:"name"`
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	var req nameRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid_request", "Invalid request body.")
		return
	}
	c, err := h.svc.Create(r.Context(), req.Name)
	if err != nil {
		httpx.Fail(w, r, h.log, err, failures)
		return
	}
	httpx.JSON(w, http.StatusCreated, toJSON(c))
}

func (h *Handler) rename(w http.ResponseWriter, r *http.Request) {
	var req nameRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid_request", "Invalid request body.")
		return
	}
	c, err := h.svc.Rename(r.Context(), r.PathValue("id"), req.Name)
	if err != nil {
		httpx.Fail(w, r, h.log, err, failures)
		return
	}
	httpx.JSON(w, http.StatusOK, toJSON(c))
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	c, err := h.svc.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		httpx.Fail(w, r, h.log, err, failures)
		return
	}
	httpx.JSON(w, http.StatusOK, toJSON(c))
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	cs, err := h.svc.List(r.Context())
	if err != nil {
		httpx.Fail(w, r, h.log, err, failures)
		return
	}
	out := make([]clientJSON, 0, len(cs))
	for _, c := range cs {
		out = append(out, toJSON(c))
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": out})
}

func (h *Handler) delete(w http.ResponseWriter, r *http.Request) {
	if err := h.svc.Delete(r.Context(), r.PathValue("id")); err != nil {
		httpx.Fail(w, r, h.log, err, failures)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
