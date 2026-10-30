package member

import "errors"

var (
	ErrNotManager      = errors.New("not_a_manager")
	ErrTenantNotServed = errors.New("tenant_not_served")
	ErrInvalidID       = errors.New("invalid_id")
	ErrMemberNotFound  = errors.New("member_not_found")
	ErrProtectedMember = errors.New("protected_member")
	ErrResetNotAllowed = errors.New("reset_not_allowed")
)
