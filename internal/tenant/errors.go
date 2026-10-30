package tenant

import "errors"

var (
	ErrInvalidRUC           = errors.New("invalid_ruc")
	ErrInvalidLegalName     = errors.New("invalid_legal_name")
	ErrInvalidID            = errors.New("invalid_id")
	ErrInvalidUbigeo        = errors.New("invalid_ubigeo")
	ErrInvalidEmail         = errors.New("invalid_email")
	ErrInvalidPhone         = errors.New("invalid_phone")
	ErrInvalidLogo          = errors.New("invalid_logo")
	ErrFieldTooLong         = errors.New("field_too_long")
	ErrRUCTaken             = errors.New("ruc_taken")
	ErrClientNotFound       = errors.New("client_not_found")
	ErrTenantNotFound       = errors.New("tenant_not_found")
	ErrSystemNotFound       = errors.New("system_not_found")
	ErrSystemAlreadyEnabled = errors.New("system_already_enabled")
	ErrSystemNotEnabled     = errors.New("system_not_enabled")
)
