package client

import "errors"

var (
	ErrInvalidID        = errors.New("invalid_id")
	ErrInvalidName      = errors.New("invalid_name")
	ErrNameTooLong      = errors.New("name_too_long")
	ErrClientNotFound   = errors.New("client_not_found")
	ErrClientHasTenants = errors.New("client_has_tenants")
)
