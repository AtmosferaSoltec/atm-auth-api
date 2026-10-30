package member

import (
	"log/slog"
	"net/http"

	"github.com/AtmosferaSoltec/atm-auth-api/internal/access"
	"github.com/AtmosferaSoltec/atm-auth-api/internal/auth"
	"github.com/AtmosferaSoltec/atm-auth-api/internal/httpx"
	"github.com/AtmosferaSoltec/atm-auth-api/internal/session"
	"github.com/AtmosferaSoltec/atm-auth-api/internal/user"
)

type Handler struct {
	svc      *Service
	log      *slog.Logger
	verifier auth.Verifier
}

func NewHandler(svc *Service, log *slog.Logger, verifier auth.Verifier) *Handler {
	return &Handler{svc: svc, log: log, verifier: verifier}
}

func (h *Handler) Register(mux *http.ServeMux) {
	mux.Handle("GET /v1/tenant/roles", h.guard(h.roles))
	mux.Handle("GET /v1/tenant/members", h.guard(h.list))
	mux.Handle("POST /v1/tenant/members", h.guard(h.add))
	mux.Handle("PUT /v1/tenant/members/{user_id}", h.guard(h.updateRole))
	mux.Handle("DELETE /v1/tenant/members/{user_id}", h.guard(h.remove))
	mux.Handle("POST /v1/tenant/members/{user_id}/reset-password", h.guard(h.resetPassword))
}

// RegisterService mounts the routes a system's backend calls with its service token to manage the members of one
// of its tenants (`tenant_id` in the query). Who may call them is decided by that system, not here.
func (h *Handler) RegisterService(mux *http.ServeMux, service httpx.Middleware) {
	mux.Handle("GET /v1/service/roles", service(h.serviceScope(h.roles)))
	mux.Handle("GET /v1/service/members", service(h.serviceScope(h.list)))
	mux.Handle("POST /v1/service/members", service(h.serviceScope(h.add)))
	mux.Handle("PUT /v1/service/members/{user_id}", service(h.serviceScope(h.updateRole)))
	mux.Handle("DELETE /v1/service/members/{user_id}", service(h.serviceScope(h.remove)))
	mux.Handle("POST /v1/service/members/{user_id}/reset-password", service(h.serviceScope(h.resetPassword)))
}

var failures = map[error]httpx.Failure{
	ErrNotManager:      {Status: http.StatusForbidden, Message: "You are not allowed to manage users."},
	ErrInvalidID:       {Status: http.StatusBadRequest, Message: "Invalid id."},
	ErrTenantNotServed: {Status: http.StatusForbidden, Message: "This system does not serve that company."},
	ErrMemberNotFound:  {Status: http.StatusNotFound, Message: "Member not found."},
	ErrProtectedMember: {Status: http.StatusForbidden, Message: "Only the platform administrator can change this member."},
	ErrResetNotAllowed: {Status: http.StatusForbidden, Message: "This person also belongs to other organizations. Ask the platform administrator to reset the password."},

	user.ErrInvalidDNI:  {Status: http.StatusBadRequest, Message: "The DNI must have 8 digits."},
	user.ErrInvalidName: {Status: http.StatusBadRequest, Message: "The full name is required for a new person."},

	access.ErrInvalidRole:         {Status: http.StatusBadRequest, Message: "The role is required and can have at most 64 characters."},
	access.ErrUnknownRole:         {Status: http.StatusBadRequest, Message: "The system has no such role. Choose one from GET /v1/tenant/roles."},
	access.ErrUserAlreadyInSystem: {Status: http.StatusConflict, Message: "This person already belongs to an organization in this system."},
}

// guard runs next only for a valid user token whose owner may manage users, and gives it the scope.
func (h *Handler) guard(next func(http.ResponseWriter, *http.Request, Scope)) http.Handler {
	return auth.RequireRole(h.verifier, session.RoleUser)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, _ := auth.ClaimsFromContext(r.Context())
		sc, err := h.svc.Authorize(r.Context(), claims.Subject, claims.System, claims.Tenant)
		if err != nil {
			httpx.Fail(w, r, h.log, err, failures)
			return
		}
		next(w, r, sc)
	}))
}

// serviceScope runs next for a service token, scoped to the token's system and the `tenant_id` of the query.
func (h *Handler) serviceScope(next func(http.ResponseWriter, *http.Request, Scope)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := auth.ClaimsFromContext(r.Context())
		if !ok {
			httpx.Error(w, http.StatusForbidden, "forbidden", "Insufficient permissions.")
			return
		}
		sc, err := h.svc.ScopeFor(r.Context(), claims.System, r.URL.Query().Get("tenant_id"))
		if err != nil {
			httpx.Fail(w, r, h.log, err, failures)
			return
		}
		next(w, r, sc)
	})
}

type memberJSON struct {
	UserID             string `json:"user_id"`
	DNI                string `json:"dni"`
	FullName           string `json:"full_name"`
	Role               string `json:"role"`
	ManageUsers        bool   `json:"manage_users"`
	Status             string `json:"status"`
	MustChangePassword bool   `json:"must_change_password"`
}

func toJSON(m Member) memberJSON {
	return memberJSON{
		UserID: m.UserID, DNI: m.DNI, FullName: m.FullName, Role: m.Role, ManageUsers: m.ManageUsers,
		Status: m.Status, MustChangePassword: m.MustChangePassword,
	}
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request, sc Scope) {
	members, err := h.svc.List(r.Context(), sc)
	if err != nil {
		httpx.Fail(w, r, h.log, err, failures)
		return
	}
	out := make([]memberJSON, 0, len(members))
	for _, m := range members {
		out = append(out, toJSON(m))
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": out})
}

func (h *Handler) add(w http.ResponseWriter, r *http.Request, sc Scope) {
	var req struct {
		DNI      string `json:"dni"`
		FullName string `json:"full_name"`
		Role     string `json:"role"`
	}
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid_request", "Invalid request body.")
		return
	}
	m, err := h.svc.Add(r.Context(), sc, AddInput{DNI: req.DNI, FullName: req.FullName, Role: req.Role})
	if err != nil {
		httpx.Fail(w, r, h.log, err, failures)
		return
	}
	httpx.JSON(w, http.StatusCreated, toJSON(m))
}

func (h *Handler) updateRole(w http.ResponseWriter, r *http.Request, sc Scope) {
	var req struct {
		Role string `json:"role"`
	}
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid_request", "Invalid request body.")
		return
	}
	h.noContent(w, r, h.svc.UpdateRole(r.Context(), sc, r.PathValue("user_id"), req.Role))
}

func (h *Handler) remove(w http.ResponseWriter, r *http.Request, sc Scope) {
	h.noContent(w, r, h.svc.Remove(r.Context(), sc, r.PathValue("user_id")))
}

func (h *Handler) resetPassword(w http.ResponseWriter, r *http.Request, sc Scope) {
	h.noContent(w, r, h.svc.ResetPassword(r.Context(), sc, r.PathValue("user_id")))
}

func (h *Handler) noContent(w http.ResponseWriter, r *http.Request, err error) {
	if err != nil {
		httpx.Fail(w, r, h.log, err, failures)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// roles lists the roles of the owner's system. Members can only be given one of them.
func (h *Handler) roles(w http.ResponseWriter, r *http.Request, sc Scope) {
	roles, err := h.svc.Roles(r.Context(), sc)
	if err != nil {
		httpx.Fail(w, r, h.log, err, failures)
		return
	}
	out := make([]map[string]string, 0, len(roles))
	for _, role := range roles {
		out = append(out, map[string]string{"name": role.Name, "description": role.Description})
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": out})
}
