package credential

import "errors"

var (
	ErrInvalidID      = errors.New("invalid_id")
	ErrSystemNotFound = errors.New("system_not_found")
	// ErrInvalidClient covers an unknown system, a wrong secret, a system without a secret and a disabled system,
	// so a caller cannot tell them apart.
	ErrInvalidClient = errors.New("invalid_client")
)
