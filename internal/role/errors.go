package role

import "errors"

var (
	ErrInvalidID          = errors.New("invalid_id")
	ErrInvalidName        = errors.New("invalid_role_name")
	ErrInvalidDescription = errors.New("invalid_role_description")
	ErrSystemNotFound     = errors.New("system_not_found")
	ErrRoleNotFound       = errors.New("role_not_found")
	// ErrRoleExists also covers a name that differs only in upper or lower case.
	ErrRoleExists = errors.New("role_exists")
	ErrRoleInUse  = errors.New("role_in_use")
)
