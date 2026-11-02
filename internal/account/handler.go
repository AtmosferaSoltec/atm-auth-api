package account

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/AtmosferaSoltec/atm-auth-api/internal/auth"
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

// RegisterAuthenticated mounts the routes of a signed-in user. userAuth must reject any other token.
func (h *Handler) RegisterAuthenticated(mux *http.ServeMux, userAuth httpx.Middleware) {
	mux.Handle("DELETE /v1/account", userAuth(http.HandlerFunc(h.delete)))
}

func (h *Handler) delete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password   string `json:"password"`
		Credential string `json:"credential"`
		Nonce      string `json:"nonce"`
	}
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid_request", "Invalid request body.")
		return
	}
	claims, _ := auth.ClaimsFromContext(r.Context())
	err := h.svc.Delete(r.Context(), claims.Subject, Input(req), httpx.ClientIP(r, h.clientIPHeader))
	var tooMany *TooManyAttemptsError
	switch {
	case err == nil:
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, ErrInvalidInput):
		httpx.Error(w, http.StatusBadRequest, "invalid_request", "Send the password, or a Google credential with its nonce.")
	case errors.Is(err, ErrBadCredentials):
		httpx.Error(w, http.StatusUnauthorized, "invalid_credentials", "Invalid credentials.")
	case errors.Is(err, ErrNotLinked):
		httpx.Error(w, http.StatusForbidden, "google_not_linked", "That Google account is not linked to this account.")
	case errors.Is(err, ErrChallenge):
		httpx.Error(w, http.StatusUnauthorized, "google_challenge_expired", "The attempt expired. Start again.")
	case errors.Is(err, ErrGoogleUnavailble):
		httpx.Error(w, http.StatusServiceUnavailable, "google_unavailable", "Google sign-in is not available.")
	case errors.Is(err, ErrShared):
		httpx.Error(w, http.StatusConflict, "account_shared", "This account also works in company systems and cannot be deleted from here.")
	case errors.Is(err, ErrHookFailed):
		h.log.Error("account cleanup failed", "request_id", httpx.RequestIDFromContext(r.Context()), "error", err)
		httpx.Error(w, http.StatusBadGateway, "account_cleanup_failed", "Your data could not be removed yet. Nothing was deleted: try again.")
	case errors.Is(err, user.ErrUserNotFound):
		httpx.Error(w, http.StatusUnauthorized, "unauthorized", "Unauthorized.")
	case errors.As(err, &tooMany):
		w.Header().Set("Retry-After", strconv.Itoa(int(tooMany.RetryAfter.Seconds())+1))
		httpx.Error(w, http.StatusTooManyRequests, "too_many_attempts", "Too many failed attempts. Try again later.")
	default:
		h.log.Error("delete account failed", "request_id", httpx.RequestIDFromContext(r.Context()), "error", err)
		httpx.Error(w, http.StatusInternalServerError, "internal_error", "Internal server error.")
	}
}
