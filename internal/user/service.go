package user

import (
	"context"
	"fmt"
	"strings"

	"github.com/AtmosferaSoltec/atm-auth-api/internal/platform"
)

type PasswordHasher interface {
	Hash(password string) (string, error)
}

// SessionRevoker ends every session of a user.
type SessionRevoker interface {
	RevokeUserSessions(ctx context.Context, userID string) error
}

type Service struct {
	repo    Repository
	hasher  PasswordHasher
	revoker SessionRevoker
}

func NewService(repo Repository, hasher PasswordHasher, revoker SessionRevoker) *Service {
	return &Service{repo: repo, hasher: hasher, revoker: revoker}
}

type CreateInput struct {
	DNI      string
	FullName string
	// Password is optional and only for internal callers (the HTTP API never sets it): when empty, the initial
	// password is the DNI and the user must change it at first login.
	Password string
}

func (s *Service) Create(ctx context.Context, in CreateInput) (User, error) {
	if !validDNI(in.DNI) {
		return User{}, ErrInvalidDNI
	}
	name := normalizeName(in.FullName)
	if name == "" {
		return User{}, ErrInvalidName
	}
	password, mustChange := in.Password, false
	if password == "" {
		password, mustChange = in.DNI, true
	} else if len(password) < MinPasswordLength {
		return User{}, ErrWeakPassword
	}
	hash, err := s.hasher.Hash(password)
	if err != nil {
		return User{}, fmt.Errorf("create user: %w", err)
	}
	created, err := s.repo.Create(ctx, User{
		DNI:                in.DNI,
		FullName:           name,
		PasswordHash:       hash,
		Status:             StatusActive,
		MustChangePassword: mustChange,
	})
	if err != nil {
		return User{}, fmt.Errorf("create user: %w", err)
	}
	return created, nil
}

// RegisterInput is a person who creates their own account with an email and a password.
type RegisterInput struct {
	Email    string
	FullName string
	Password string
}

// Register creates an account identified by email. The person chose the password, so no change is forced.
func (s *Service) Register(ctx context.Context, in RegisterInput) (User, error) {
	email, ok := NormalizeEmail(in.Email)
	if !ok {
		return User{}, ErrInvalidEmail
	}
	name := normalizeName(in.FullName)
	if name == "" || len([]rune(name)) > 120 {
		return User{}, ErrInvalidName
	}
	if len(in.Password) < MinPasswordLength || len(in.Password) > 128 {
		return User{}, ErrWeakPassword
	}
	hash, err := s.hasher.Hash(in.Password)
	if err != nil {
		return User{}, fmt.Errorf("register user: %w", err)
	}
	created, err := s.repo.Create(ctx, User{Email: email, FullName: name, PasswordHash: hash, Status: StatusActive})
	if err != nil {
		return User{}, fmt.Errorf("register user: %w", err)
	}
	return created, nil
}

// RegisterExternal creates an account for a person whose email an identity provider (Google) already verified.
// It has no password: the person can set one later with the email recovery flow.
func (s *Service) RegisterExternal(ctx context.Context, email, fullName string) (User, error) {
	email, ok := NormalizeEmail(email)
	if !ok {
		return User{}, ErrInvalidEmail
	}
	name := normalizeName(fullName)
	if r := []rune(name); len(r) > 120 {
		name = string(r[:120])
	}
	if name == "" {
		// Providers may omit the name; the part of the email before the @ is better than refusing.
		name = strings.SplitN(email, "@", 2)[0]
	}
	created, err := s.repo.Create(ctx, User{Email: email, EmailVerified: true, FullName: name, Status: StatusActive})
	if err != nil {
		return User{}, fmt.Errorf("register external user: %w", err)
	}
	return created, nil
}

func (s *Service) List(ctx context.Context) ([]User, error) {
	users, err := s.repo.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	return users, nil
}

// ResetPassword puts the DNI back as the password, forces a change at next login and ends all sessions.
func (s *Service) ResetPassword(ctx context.Context, id string) error {
	if !platform.IsUUID(id) {
		return ErrInvalidID
	}
	u, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("reset password: %w", err)
	}
	if u.DNI == "" {
		// People without a DNI recover their password themselves; there is no initial password to go back to.
		return ErrNoDNI
	}
	hash, err := s.hasher.Hash(u.DNI)
	if err != nil {
		return fmt.Errorf("reset password: %w", err)
	}
	if err := s.repo.SetPassword(ctx, id, hash, true); err != nil {
		return fmt.Errorf("reset password: %w", err)
	}
	if err := s.revoker.RevokeUserSessions(ctx, id); err != nil {
		return fmt.Errorf("reset password: %w", err)
	}
	return nil
}

// SetStatus enables or disables an account. Disabling also ends all its sessions.
func (s *Service) SetStatus(ctx context.Context, id, status string) error {
	if !platform.IsUUID(id) {
		return ErrInvalidID
	}
	if !ValidStatus(status) {
		return ErrInvalidStatus
	}
	if err := s.repo.SetStatus(ctx, id, status); err != nil {
		return fmt.Errorf("set user status: %w", err)
	}
	if status == StatusDisabled {
		if err := s.revoker.RevokeUserSessions(ctx, id); err != nil {
			return fmt.Errorf("set user status: %w", err)
		}
	}
	return nil
}
