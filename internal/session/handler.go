package session

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/AtmosferaSoltec/atm-auth-api/internal/access"
	"github.com/AtmosferaSoltec/atm-auth-api/internal/httpx"
	"github.com/AtmosferaSoltec/atm-auth-api/internal/user"
)

type Handler struct {
	svc            *Service
	log            *slog.Logger
	clientIPHeader string
}

func NewHandler(svc *Service, log *slog.Logger, clientIPHeader string) *Handler {
	return &Handler{svc: svc, log: log, clientIPHeader: clientIPHeader}
}

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/login", h.login)
	mux.HandleFunc("POST /v1/admin/login", h.adminLogin)
	mux.HandleFunc("POST /v1/token", h.clientToken)
	mux.HandleFunc("POST /v1/password/change", h.changePassword)
	mux.HandleFunc("POST /v1/refresh", h.refresh)
	mux.HandleFunc("POST /v1/logout", h.logout)
}

type loginRequest struct {
	DNI      string `json:"dni"`
	Password string `json:"password"`
}

type userLoginRequest struct {
	DNI      string `json:"dni"`
	Password string `json:"password"`
	System   string `json:"system"`
}

type changePasswordRequest struct {
	DNI             string `json:"dni"`
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type tokensResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	// RefreshExpiresIn is how many seconds the refresh token lasts without being used.
	RefreshExpiresIn int `json:"refresh_expires_in"`
	// SessionMode tells clients whether they may remember the session ("persistent") or must not ("temporary").
	SessionMode string `json:"session_mode"`
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	var req userLoginRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil || req.DNI == "" || req.Password == "" ||
		req.System == "" || len(req.DNI) > 64 || len(req.System) > 64 {
		invalidRequest(w)
		return
	}
	tokens, err := h.svc.UserLogin(r.Context(), req.DNI, req.Password, req.System, httpx.ClientIP(r, h.clientIPHeader))
	h.respondTokens(w, r, tokens, err)
}

func (h *Handler) adminLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil || req.DNI == "" || req.Password == "" || len(req.DNI) > 64 {
		invalidRequest(w)
		return
	}
	tokens, err := h.svc.AdminLogin(r.Context(), req.DNI, req.Password, httpx.ClientIP(r, h.clientIPHeader))
	h.respondTokens(w, r, tokens, err)
}

func (h *Handler) changePassword(w http.ResponseWriter, r *http.Request) {
	var req changePasswordRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil || req.DNI == "" || req.CurrentPassword == "" ||
		req.NewPassword == "" || len(req.DNI) > 64 {
		invalidRequest(w)
		return
	}
	err := h.svc.ChangePassword(r.Context(), req.DNI, req.CurrentPassword, req.NewPassword, httpx.ClientIP(r, h.clientIPHeader))
	if err == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if errors.Is(err, user.ErrWeakPassword) {
		httpx.Error(w, http.StatusBadRequest, "weak_password", "The new password must have at least 8 characters, differ from the current one and not be the DNI.")
		return
	}
	h.respondTokens(w, r, Tokens{}, err)
}

func (h *Handler) refresh(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil || req.RefreshToken == "" {
		invalidRequest(w)
		return
	}
	tokens, err := h.svc.Refresh(r.Context(), req.RefreshToken)
	h.respondTokens(w, r, tokens, err)
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil || req.RefreshToken == "" {
		invalidRequest(w)
		return
	}
	if err := h.svc.Logout(r.Context(), req.RefreshToken); err != nil {
		h.internalError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) respondTokens(w http.ResponseWriter, r *http.Request, tokens Tokens, err error) {
	var tooMany *TooManyAttemptsError
	switch {
	case err == nil:
		w.Header().Set("Cache-Control", "no-store")
		httpx.JSON(w, http.StatusOK, tokensResponse{
			AccessToken: tokens.AccessToken, RefreshToken: tokens.RefreshToken,
			TokenType: "Bearer", ExpiresIn: tokens.ExpiresIn,
			RefreshExpiresIn: tokens.RefreshExpiresIn, SessionMode: tokens.SessionMode,
		})
	case errors.Is(err, ErrInvalidCredentials):
		httpx.Error(w, http.StatusUnauthorized, "invalid_credentials", "Invalid DNI or password.")
	case errors.Is(err, ErrPasswordChangeRequired):
		httpx.Error(w, http.StatusForbidden, "password_change_required", "You must set a new password before continuing.")
	case errors.Is(err, access.ErrNoAccess):
		httpx.Error(w, http.StatusForbidden, "no_access", "You do not have access to this system.")
	case errors.Is(err, ErrInvalidRefreshToken):
		httpx.Error(w, http.StatusUnauthorized, "invalid_refresh_token", "Invalid or expired refresh token.")
	case errors.As(err, &tooMany):
		secs := int(tooMany.RetryAfter.Seconds()) + 1
		w.Header().Set("Retry-After", strconv.Itoa(secs))
		httpx.Error(w, http.StatusTooManyRequests, "too_many_attempts", "Too many failed attempts. Try again later.")
	default:
		h.internalError(w, r, err)
	}
}

func invalidRequest(w http.ResponseWriter) {
	httpx.Error(w, http.StatusBadRequest, "invalid_request", "Invalid request body.")
}

func (h *Handler) internalError(w http.ResponseWriter, r *http.Request, err error) {
	h.log.Error("session request failed", "request_id", httpx.RequestIDFromContext(r.Context()), "error", err)
	httpx.Error(w, http.StatusInternalServerError, "internal_error", "Internal server error.")
}

type clientTokenRequest struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// clientToken gives a system's backend a service token. The same token works on every microservice.
func (h *Handler) clientToken(w http.ResponseWriter, r *http.Request) {
	var req clientTokenRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil || req.ClientID == "" || req.ClientSecret == "" ||
		len(req.ClientID) > 64 || len(req.ClientSecret) > 256 {
		invalidRequest(w)
		return
	}
	tokens, err := h.svc.ClientToken(r.Context(), req.ClientID, req.ClientSecret, httpx.ClientIP(r, h.clientIPHeader))

	var tooMany *TooManyAttemptsError
	switch {
	case err == nil:
		w.Header().Set("Cache-Control", "no-store")
		httpx.JSON(w, http.StatusOK, map[string]any{
			"access_token": tokens.AccessToken, "token_type": "Bearer", "expires_in": tokens.ExpiresIn,
		})
	case errors.Is(err, ErrInvalidClient):
		httpx.Error(w, http.StatusUnauthorized, "invalid_client", "Invalid client credentials.")
	case errors.As(err, &tooMany):
		w.Header().Set("Retry-After", strconv.Itoa(int(tooMany.RetryAfter.Seconds())+1))
		httpx.Error(w, http.StatusTooManyRequests, "too_many_attempts", "Too many failed attempts. Try again later.")
	default:
		h.internalError(w, r, err)
	}
}
