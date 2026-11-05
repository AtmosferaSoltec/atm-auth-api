package user

import "errors"

var (
	ErrInvalidDocument = errors.New("invalid_document")
	ErrInvalidName     = errors.New("invalid_full_name")
	ErrInvalidStatus   = errors.New("invalid_status")
	ErrInvalidID       = errors.New("invalid_id")
	ErrWeakPassword    = errors.New("weak_password")
	ErrDocumentTaken   = errors.New("document_taken")
	ErrNoDocument      = errors.New("no_document")
	ErrInvalidEmail    = errors.New("invalid_email")
	ErrEmailTaken      = errors.New("email_taken")
	ErrUserNotFound    = errors.New("user_not_found")
)
