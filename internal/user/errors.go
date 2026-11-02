package user

import "errors"

var (
	ErrInvalidDNI    = errors.New("invalid_dni")
	ErrInvalidName   = errors.New("invalid_full_name")
	ErrInvalidStatus = errors.New("invalid_status")
	ErrInvalidID     = errors.New("invalid_id")
	ErrWeakPassword  = errors.New("weak_password")
	ErrDNITaken      = errors.New("dni_taken")
	ErrNoDNI         = errors.New("no_dni")
	ErrInvalidEmail  = errors.New("invalid_email")
	ErrEmailTaken    = errors.New("email_taken")
	ErrUserNotFound  = errors.New("user_not_found")
)
