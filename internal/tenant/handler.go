package tenant

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
	mux.Handle("POST /v1/admin/tenants", admin(http.HandlerFunc(h.create)))
	mux.Handle("GET /v1/admin/tenants", admin(http.HandlerFunc(h.list)))
	mux.Handle("GET /v1/admin/tenants/{id}", admin(http.HandlerFunc(h.get)))
	mux.Handle("POST /v1/admin/tenants/{id}/systems", admin(http.HandlerFunc(h.enableSystem)))
	mux.Handle("DELETE /v1/admin/tenants/{id}/systems/{system_id}", admin(http.HandlerFunc(h.disableSystem)))
}

var failures = map[error]httpx.Failure{
	ErrInvalidRUC:           {Status: http.StatusBadRequest, Message: "The RUC must have 11 digits."},
	ErrInvalidLegalName:     {Status: http.StatusBadRequest, Message: "The legal name is required."},
	ErrInvalidID:            {Status: http.StatusBadRequest, Message: "Invalid id."},
	ErrRUCTaken:             {Status: http.StatusConflict, Message: "A tenant with that RUC already exists."},
	ErrTenantNotFound:       {Status: http.StatusNotFound, Message: "Tenant not found."},
	ErrSystemNotFound:       {Status: http.StatusNotFound, Message: "System not found."},
	ErrSystemAlreadyEnabled: {Status: http.StatusConflict, Message: "The system is already enabled for this tenant."},
	ErrSystemNotEnabled:     {Status: http.StatusNotFound, Message: "The system is not enabled for this tenant."},
}

type systemRefJSON struct {
	ID   string `json:"id"`
	Code string `json:"code"`
	Name string `json:"name"`
}

type tenantJSON struct {
	ID          string    `json:"id"`
	RUC         string    `json:"ruc"`
	LegalName   string    `json:"legal_name"`
	TradeName   string    `json:"trade_name"`
	DisplayName string    `json:"display_name"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
	// Systems is never null: a tenant without systems has an empty list.
	Systems []systemRefJSON `json:"systems"`
}

func toJSON(t Tenant) tenantJSON {
	systems := make([]systemRefJSON, 0, len(t.Systems))
	for _, s := range t.Systems {
		systems = append(systems, systemRefJSON{ID: s.ID, Code: s.Code, Name: s.Name})
	}
	return tenantJSON{
		ID: t.ID, RUC: t.RUC, LegalName: t.LegalName, TradeName: t.TradeName,
		DisplayName: t.DisplayName(), Status: t.Status, CreatedAt: t.CreatedAt, Systems: systems,
	}
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RUC       string `json:"ruc"`
		LegalName string `json:"legal_name"`
		TradeName string `json:"trade_name"`
	}
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid_request", "Invalid request body.")
		return
	}
	t, err := h.svc.Create(r.Context(), CreateInput{RUC: req.RUC, LegalName: req.LegalName, TradeName: req.TradeName})
	if err != nil {
		httpx.Fail(w, r, h.log, err, failures)
		return
	}
	httpx.JSON(w, http.StatusCreated, toJSON(t))
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	t, err := h.svc.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		httpx.Fail(w, r, h.log, err, failures)
		return
	}
	httpx.JSON(w, http.StatusOK, toJSON(t))
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	ts, err := h.svc.List(r.Context())
	if err != nil {
		httpx.Fail(w, r, h.log, err, failures)
		return
	}
	out := make([]tenantJSON, 0, len(ts))
	for _, t := range ts {
		out = append(out, toJSON(t))
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": out})
}

func (h *Handler) enableSystem(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SystemID string `json:"system_id"`
	}
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid_request", "Invalid request body.")
		return
	}
	if err := h.svc.EnableSystem(r.Context(), r.PathValue("id"), req.SystemID); err != nil {
		httpx.Fail(w, r, h.log, err, failures)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) disableSystem(w http.ResponseWriter, r *http.Request) {
	if err := h.svc.DisableSystem(r.Context(), r.PathValue("id"), r.PathValue("system_id")); err != nil {
		httpx.Fail(w, r, h.log, err, failures)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
