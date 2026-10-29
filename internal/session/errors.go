package session

import (
	"errors"
	"time"
)

var (
	ErrInvalidCredentials     = errors.New("invalid_credentials")
	ErrInvalidRefreshToken    = errors.New("invalid_refresh_token")
	ErrPasswordChangeRequired = errors.New("password_change_required")
)

// TooManyAttemptsError is returned when a login is throttled.
type TooManyAttemptsError struct {
	RetryAfter time.Duration
}

func (e *TooManyAttemptsError) Error() string { return "too_many_attempts" }
