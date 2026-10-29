package tenant

import "errors"

var (
	ErrInvalidRUC           = errors.New("invalid_ruc")
	ErrInvalidLegalName     = errors.New("invalid_legal_name")
	ErrInvalidID            = errors.New("invalid_id")
	ErrRUCTaken             = errors.New("ruc_taken")
	ErrTenantNotFound       = errors.New("tenant_not_found")
	ErrSystemNotFound       = errors.New("system_not_found")
	ErrSystemAlreadyEnabled = errors.New("system_already_enabled")
)
