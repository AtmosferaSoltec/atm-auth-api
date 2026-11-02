package recovery

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/AtmosferaSoltec/atm-auth-api/internal/httpx"
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
	mux.HandleFunc("POST /v1/password/forgot", h.forgot)
	mux.HandleFunc("POST /v1/password/verify", h.verify)
	mux.HandleFunc("POST /v1/password/reset", h.reset)
}

type request struct {
	Email       string `json:"email"`
	System      string `json:"system"`
	Code        string `json:"code"`
	NewPassword string `json:"new_password"`
}

func (h *Handler) decode(w http.ResponseWriter, r *http.Request) (request, bool) {
	var req request
	if err := httpx.DecodeJSON(w, r, &req); err != nil || len(req.Email) > 254 || len(req.System) > 64 ||
		len(req.Code) > 16 || len(req.NewPassword) > 512 {
		httpx.Error(w, http.StatusBadRequest, "invalid_request", "Invalid request body.")
		return request{}, false
	}
	return req, true
}

// forgot always answers 204 for a well-formed request, whether or not the email has an account.
func (h *Handler) forgot(w http.ResponseWriter, r *http.Request) {
	req, ok := h.decode(w, r)
	if !ok {
		return
	}
	h.done(w, r, h.svc.Forgot(r.Context(), req.Email, req.System, httpx.ClientIP(r, h.clientIPHeader)))
}

func (h *Handler) verify(w http.ResponseWriter, r *http.Request) {
	req, ok := h.decode(w, r)
	if !ok {
		return
	}
	h.done(w, r, h.svc.Verify(r.Context(), req.Email, req.Code, httpx.ClientIP(r, h.clientIPHeader)))
}

func (h *Handler) reset(w http.ResponseWriter, r *http.Request) {
	req, ok := h.decode(w, r)
	if !ok {
		return
	}
	h.done(w, r, h.svc.Reset(r.Context(), req.Email, req.Code, req.NewPassword, req.System, httpx.ClientIP(r, h.clientIPHeader)))
}

func (h *Handler) done(w http.ResponseWriter, r *http.Request, err error) {
	var tooMany *TooManyAttemptsError
	switch {
	case err == nil:
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, ErrInvalidEmail):
		httpx.Error(w, http.StatusBadRequest, "invalid_email", "The email is not valid.")
	case errors.Is(err, ErrInvalidCode):
		httpx.Error(w, http.StatusBadRequest, "invalid_code_format", "The code has 6 digits.")
	case errors.Is(err, ErrUnknownSystem):
		httpx.Error(w, http.StatusBadRequest, "unknown_system", "Unknown system.")
	case errors.Is(err, ErrWeakPassword):
		httpx.Error(w, http.StatusBadRequest, "weak_password", "The password must have between 8 and 128 characters.")
	case errors.Is(err, ErrResetCodeWrong):
		httpx.Error(w, http.StatusUnprocessableEntity, "reset_code_invalid", "The code is wrong or has expired.")
	case errors.As(err, &tooMany):
		w.Header().Set("Retry-After", strconv.Itoa(int(tooMany.RetryAfter.Seconds())+1))
		httpx.Error(w, http.StatusTooManyRequests, "too_many_attempts", "Too many attempts. Try again later.")
	default:
		h.log.Error("password recovery failed", "request_id", httpx.RequestIDFromContext(r.Context()), "error", err)
		httpx.Error(w, http.StatusInternalServerError, "internal_error", "Internal server error.")
	}
}
