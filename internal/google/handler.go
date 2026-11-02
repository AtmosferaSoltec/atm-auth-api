package google

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
	mux.HandleFunc("POST /v1/google/challenge", h.challenge)
	mux.HandleFunc("POST /v1/google", h.signIn)
}

func (h *Handler) challenge(w http.ResponseWriter, r *http.Request) {
	nonce, err := h.svc.NewChallenge(r.Context())
	if err != nil {
		h.fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	httpx.JSON(w, http.StatusOK, map[string]any{"nonce": nonce, "expires_in": int(ChallengeTTL.Seconds())})
}

type signInRequest struct {
	System     string `json:"system"`
	Credential string `json:"credential"`
	Nonce      string `json:"nonce"`
	Password   string `json:"password"`
	TenantID   string `json:"tenant_id"`
}

func (h *Handler) signIn(w http.ResponseWriter, r *http.Request) {
	var req signInRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid_request", "Invalid request body.")
		return
	}
	tokens, err := h.svc.SignIn(r.Context(), SignInInput(req), httpx.ClientIP(r, h.clientIPHeader))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	httpx.JSON(w, http.StatusOK, map[string]any{
		"access_token": tokens.AccessToken, "refresh_token": tokens.RefreshToken, "token_type": "Bearer",
		"expires_in": tokens.ExpiresIn, "refresh_expires_in": tokens.RefreshExpiresIn, "session_mode": tokens.SessionMode,
	})
}

func (h *Handler) fail(w http.ResponseWriter, r *http.Request, err error) {
	var tooMany *TooManyAttemptsError
	switch {
	case errors.Is(err, ErrUnavailable):
		httpx.Error(w, http.StatusServiceUnavailable, "google_unavailable", "Google sign-in is not available.")
	case errors.Is(err, ErrInvalidInput):
		httpx.Error(w, http.StatusBadRequest, "invalid_request", "Invalid request body.")
	case errors.Is(err, ErrInvalidCredentia):
		httpx.Error(w, http.StatusUnauthorized, "invalid_google_credential", "The Google credential is not valid.")
	case errors.Is(err, ErrChallenge):
		httpx.Error(w, http.StatusUnauthorized, "google_challenge_expired", "The sign-in attempt expired. Start again.")
	case errors.Is(err, ErrLinkRequired):
		httpx.Error(w, http.StatusConflict, "password_required_to_link", "An account with this email exists: confirm its password to link Google.")
	case errors.Is(err, ErrBadCredentials):
		httpx.Error(w, http.StatusUnauthorized, "invalid_credentials", "Invalid credentials.")
	case errors.Is(err, ErrIdentityConflict):
		httpx.Error(w, http.StatusConflict, "google_identity_conflict", "That account already has another Google identity linked.")
	case errors.Is(err, access.ErrSignupClosed):
		httpx.Error(w, http.StatusForbidden, "signup_closed", "This system does not accept new accounts.")
	case errors.Is(err, access.ErrNoAccess):
		httpx.Error(w, http.StatusForbidden, "no_access", "You do not have access to this system or company.")
	case errors.Is(err, user.ErrEmailTaken):
		httpx.Error(w, http.StatusConflict, "email_taken", "An account with that email already exists.")
	case errors.As(err, &tooMany):
		w.Header().Set("Retry-After", strconv.Itoa(int(tooMany.RetryAfter.Seconds())+1))
		httpx.Error(w, http.StatusTooManyRequests, "too_many_attempts", "Too many failed attempts. Try again later.")
	default:
		h.log.Error("google sign-in failed", "request_id", httpx.RequestIDFromContext(r.Context()), "error", err)
		httpx.Error(w, http.StatusInternalServerError, "internal_error", "Internal server error.")
	}
}
