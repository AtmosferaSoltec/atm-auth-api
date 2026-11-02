package recovery

import (
	"errors"
	"time"
)

var (
	ErrInvalidEmail   = errors.New("invalid_email")
	ErrInvalidCode    = errors.New("invalid_code_format")
	ErrWeakPassword   = errors.New("weak_password")
	ErrUnknownSystem  = errors.New("unknown_system")
	ErrResetCodeWrong = errors.New("reset_code_invalid")
)

// TooManyAttemptsError is returned when requests are throttled.
type TooManyAttemptsError struct{ RetryAfter time.Duration }

func (e *TooManyAttemptsError) Error() string { return "too_many_attempts" }
