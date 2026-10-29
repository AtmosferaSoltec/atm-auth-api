package access

import "errors"

var (
	ErrInvalidID           = errors.New("invalid_id")
	ErrInvalidRole         = errors.New("invalid_role")
	ErrNoAccess            = errors.New("no_access")
	ErrUserAlreadyInSystem = errors.New("user_already_in_system")
	ErrUserNotFound        = errors.New("user_not_found")
	ErrSystemNotEnabled    = errors.New("system_not_enabled_for_tenant")
	ErrAccessNotFound      = errors.New("access_not_found")
)
