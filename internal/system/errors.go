package system

import "errors"

var (
	ErrInvalidCode    = errors.New("invalid_system_code")
	ErrInvalidName    = errors.New("invalid_system_name")
	ErrCodeTaken      = errors.New("system_code_taken")
	ErrSystemNotFound = errors.New("system_not_found")
	ErrInvalidID      = errors.New("invalid_id")
	ErrCodeMismatch   = errors.New("code_mismatch")

	ErrInvalidSessionMode    = errors.New("invalid_session_mode")
	ErrInvalidSessionMinutes = errors.New("invalid_session_minutes")
)
