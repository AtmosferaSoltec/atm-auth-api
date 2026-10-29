package httpx

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
)

type errorBody struct {
	Error errorDetail `json:"error"`
}

type errorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// JSON writes v as a JSON response with the given status.
func JSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// Error writes the standard error body.
func Error(w http.ResponseWriter, status int, code, message string) {
	JSON(w, status, errorBody{Error: errorDetail{Code: code, Message: message}})
}

// Middleware wraps a handler.
type Middleware func(http.Handler) http.Handler

// Failure is the HTTP status and public message for a known domain error.
type Failure struct {
	Status  int
	Message string
}

// Fail answers with the failure registered for err. The error text is the stable error code.
// Unknown errors are logged and answered as a generic 500.
func Fail(w http.ResponseWriter, r *http.Request, log *slog.Logger, err error, known map[error]Failure) {
	for target, f := range known {
		if errors.Is(err, target) {
			Error(w, f.Status, target.Error(), f.Message)
			return
		}
	}
	log.Error("request failed", "request_id", RequestIDFromContext(r.Context()), "error", err)
	Error(w, http.StatusInternalServerError, "internal_error", "Internal server error.")
}
