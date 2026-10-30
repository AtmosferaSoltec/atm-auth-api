package tenant

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/AtmosferaSoltec/atm-auth-api/internal/auth"
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
	mux.Handle("PUT /v1/admin/tenants/{id}", admin(http.HandlerFunc(h.update)))
	mux.Handle("PUT /v1/admin/tenants/{id}/client", admin(http.HandlerFunc(h.setClient)))
	mux.Handle("POST /v1/admin/tenants/{id}/systems", admin(http.HandlerFunc(h.enableSystem)))
	mux.Handle("DELETE /v1/admin/tenants/{id}/systems/{system_id}", admin(http.HandlerFunc(h.disableSystem)))
}

// RegisterService mounts the routes a system's backend calls with its service token. The system is the one the
// token was issued to: it comes from the token, never from the request.
func (h *Handler) RegisterService(mux *http.ServeMux, service httpx.Middleware) {
	mux.Handle("GET /v1/service/tenants", service(http.HandlerFunc(h.listForSystem)))
}

var failures = map[error]httpx.Failure{
	ErrInvalidRUC:           {Status: http.StatusBadRequest, Message: "The RUC, when given, must have 11 digits."},
	ErrInvalidLegalName:     {Status: http.StatusBadRequest, Message: "The name is required."},
	ErrInvalidID:            {Status: http.StatusBadRequest, Message: "Invalid id."},
	ErrInvalidUbigeo:        {Status: http.StatusBadRequest, Message: "The ubigeo must have 6 digits."},
	ErrInvalidEmail:         {Status: http.StatusBadRequest, Message: "The email is not valid."},
	ErrInvalidPhone:         {Status: http.StatusBadRequest, Message: "The phone is not valid."},
	ErrInvalidLogo:          {Status: http.StatusBadRequest, Message: "The logo must be a file id."},
	ErrFieldTooLong:         {Status: http.StatusBadRequest, Message: "A field is too long."},
	ErrRUCTaken:             {Status: http.StatusConflict, Message: "A tenant with that RUC already exists."},
	ErrRUCImmutable:         {Status: http.StatusConflict, Message: "The RUC of a company that already has one cannot change."},
	ErrRUCRequired:          {Status: http.StatusConflict, Message: "This system needs the company to have a RUC."},
	ErrClientNotFound:       {Status: http.StatusNotFound, Message: "Client not found."},
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
	ID          string `json:"id"`
	RUC         string `json:"ruc"`
	LegalName   string `json:"legal_name"`
	TradeName   string `json:"trade_name"`
	DisplayName string `json:"display_name"`
	Address     string `json:"address"`
	Department  string `json:"department"`
	Province    string `json:"province"`
	District    string `json:"district"`
	Ubigeo      string `json:"ubigeo"`
	Phone       string `json:"phone"`
	Email       string `json:"email"`
	// LogoFileID is null while the company has no logo.
	LogoFileID *string `json:"logo_file_id"`
	// ClientID is the owner of the company; companies of one client can share data inside a system.
	ClientID   string    `json:"client_id"`
	ClientName string    `json:"client_name"`
	Status     string    `json:"status"`
	CreatedAt  time.Time `json:"created_at"`
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
		DisplayName: t.DisplayName(), Address: t.Address, Department: t.Department, Province: t.Province, District: t.District,
		Ubigeo: t.Ubigeo, Phone: t.Phone, Email: t.Email, LogoFileID: logoPointer(t.LogoFileID),
		ClientID: t.ClientID, ClientName: t.ClientName, Status: t.Status, CreatedAt: t.CreatedAt, Systems: systems,
	}
}

func logoPointer(id string) *string {
	if id == "" {
		return nil
	}
	return &id
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RUC       string `json:"ruc"`
		LegalName string `json:"legal_name"`
		TradeName string `json:"trade_name"`
		ClientID  string `json:"client_id"`
	}
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid_request", "Invalid request body.")
		return
	}
	t, err := h.svc.Create(r.Context(), CreateInput{RUC: req.RUC, LegalName: req.LegalName, TradeName: req.TradeName, ClientID: req.ClientID})
	if err != nil {
		httpx.Fail(w, r, h.log, err, failures)
		return
	}
	httpx.JSON(w, http.StatusCreated, toJSON(t))
}

func (h *Handler) update(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RUC        string `json:"ruc"`
		LegalName  string `json:"legal_name"`
		TradeName  string `json:"trade_name"`
		Address    string `json:"address"`
		Department string `json:"department"`
		Province   string `json:"province"`
		District   string `json:"district"`
		Ubigeo     string `json:"ubigeo"`
		Phone      string `json:"phone"`
		Email      string `json:"email"`
		LogoFileID string `json:"logo_file_id"`
	}
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid_request", "Invalid request body.")
		return
	}
	t, err := h.svc.Update(r.Context(), r.PathValue("id"), UpdateInput{
		RUC: req.RUC, LegalName: req.LegalName, TradeName: req.TradeName, Address: req.Address, Department: req.Department, Province: req.Province,
		District: req.District, Ubigeo: req.Ubigeo, Phone: req.Phone, Email: req.Email, LogoFileID: req.LogoFileID,
	})
	if err != nil {
		httpx.Fail(w, r, h.log, err, failures)
		return
	}
	httpx.JSON(w, http.StatusOK, toJSON(t))
}

func (h *Handler) setClient(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ClientID string `json:"client_id"`
	}
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid_request", "Invalid request body.")
		return
	}
	t, err := h.svc.SetClient(r.Context(), r.PathValue("id"), req.ClientID)
	if err != nil {
		httpx.Fail(w, r, h.log, err, failures)
		return
	}
	httpx.JSON(w, http.StatusOK, toJSON(t))
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

// serviceTenantJSON is what a system needs to know about its customers: who they are, not what else they use.
type serviceTenantJSON struct {
	ID          string `json:"id"`
	RUC         string `json:"ruc"`
	LegalName   string `json:"legal_name"`
	TradeName   string `json:"trade_name"`
	DisplayName string `json:"display_name"`
	Address     string `json:"address"`
	Department  string `json:"department"`
	Province    string `json:"province"`
	District    string `json:"district"`
	Ubigeo      string `json:"ubigeo"`
	Phone       string `json:"phone"`
	Email       string `json:"email"`
	// LogoFileID is null while the company has no logo.
	LogoFileID *string `json:"logo_file_id"`
	// ClientID is the owner of the company. A system shares data between the companies that have the same one.
	ClientID   string `json:"client_id"`
	ClientName string `json:"client_name"`
}

func (h *Handler) listForSystem(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok || claims.System == "" {
		httpx.Error(w, http.StatusForbidden, "forbidden", "Insufficient permissions.")
		return
	}
	ts, err := h.svc.ListForSystem(r.Context(), claims.System)
	if err != nil {
		httpx.Fail(w, r, h.log, err, failures)
		return
	}
	out := make([]serviceTenantJSON, 0, len(ts))
	for _, t := range ts {
		out = append(out, serviceTenantJSON{
			ID: t.ID, RUC: t.RUC, LegalName: t.LegalName, TradeName: t.TradeName, DisplayName: t.DisplayName(),
			Address: t.Address, Department: t.Department, Province: t.Province, District: t.District,
			Ubigeo: t.Ubigeo, Phone: t.Phone, Email: t.Email, LogoFileID: logoPointer(t.LogoFileID), ClientID: t.ClientID, ClientName: t.ClientName,
		})
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": out})
}
