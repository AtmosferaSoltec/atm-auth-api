package system

import "errors"

var (
	ErrSystemNotFound = errors.New("system_not_found")
	ErrInvalidID      = errors.New("invalid_id")

	ErrInvalidSessionMode = errors.New("invalid_session_mode")
)
