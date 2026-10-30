package system

import "time"

const (
	StatusActive   = "active"
	StatusDisabled = "disabled"
)

const (
	// SessionPersistent remembers the user: the refresh token lasts REFRESH_TOKEN_TTL without use.
	SessionPersistent = "persistent"
	// SessionTemporary does not remember the user: clients do not keep the session after the tab closes.
	// The server only bounds it with a fixed ceiling (TEMPORARY_REFRESH_TTL).
	SessionTemporary = "temporary"
)

type System struct {
	ID     string
	Code   string
	Name   string
	Status string
	// SessionMode is SessionPersistent or SessionTemporary.
	SessionMode string
	// RequiresRUC says whether the system can only be enabled for companies that have a RUC.
	RequiresRUC bool
	// HasSecret says whether the system has a secret to ask for service tokens. The secret itself is never exposed.
	HasSecret        bool
	SecretCreatedAt  *time.Time
	SecretLastUsedAt *time.Time
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// normalizeSession validates a session mode. An empty one means persistent.
func normalizeSession(mode string) (string, error) {
	switch mode {
	case "", SessionPersistent:
		return SessionPersistent, nil
	case SessionTemporary:
		return SessionTemporary, nil
	default:
		return "", ErrInvalidSessionMode
	}
}
