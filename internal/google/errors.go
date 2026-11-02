package google

import (
	"errors"
	"time"
)

var (
	ErrUnavailable      = errors.New("google_unavailable")
	ErrInvalidInput     = errors.New("invalid_request")
	ErrInvalidCredentia = errors.New("invalid_google_credential")
	ErrLinkRequired     = errors.New("password_required_to_link")
	ErrBadCredentials   = errors.New("invalid_credentials")
	ErrChallenge        = errors.New("google_challenge_expired")
	ErrIdentityConflict = errors.New("google_identity_conflict")
	ErrNotLinked        = errors.New("google_not_linked")
)

// TooManyAttemptsError is returned when password confirmations are throttled.
type TooManyAttemptsError struct{ RetryAfter time.Duration }

func (e *TooManyAttemptsError) Error() string { return "too_many_attempts" }
