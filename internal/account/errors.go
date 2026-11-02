package account

import (
	"errors"
	"time"
)

var (
	ErrInvalidInput     = errors.New("invalid_request")
	ErrBadCredentials   = errors.New("invalid_credentials")
	ErrNotLinked        = errors.New("google_not_linked")
	ErrChallenge        = errors.New("google_challenge_expired")
	ErrShared           = errors.New("account_shared")
	ErrHookFailed       = errors.New("account_cleanup_failed")
	ErrGoogleUnavailble = errors.New("google_unavailable")
)

// TooManyAttemptsError is returned when confirmations are throttled.
type TooManyAttemptsError struct{ RetryAfter time.Duration }

func (e *TooManyAttemptsError) Error() string { return "too_many_attempts" }
