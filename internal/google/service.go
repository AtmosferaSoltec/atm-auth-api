// Package google signs people in with a Google account for every system, so no backend has to implement it.
// The apps (web, Android, iOS) obtain the Google ID token with their own SDK and send it here.
package google

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/AtmosferaSoltec/atm-auth-api/internal/access"
	"github.com/AtmosferaSoltec/atm-auth-api/internal/session"
	"github.com/AtmosferaSoltec/atm-auth-api/internal/user"
)

// ChallengeTTL is how long the nonce of one sign-in attempt lives.
const ChallengeTTL = 5 * time.Minute

type Store interface {
	UserBySubject(ctx context.Context, subject string) (userID string, found bool, err error)
	Link(ctx context.Context, subject, userID string) error
	CreateChallenge(ctx context.Context, hash []byte, expiresAt, now time.Time) error
	ConsumeChallenge(ctx context.Context, hash []byte, now time.Time) (bool, error)
}

type Users interface {
	GetByEmail(ctx context.Context, email string) (user.User, error)
	GetByID(ctx context.Context, id string) (user.User, error)
}

type Registrar interface {
	RegisterExternal(ctx context.Context, email, fullName string) (user.User, error)
}

type Hasher interface {
	Verify(password, encodedHash string) (bool, error)
}

type Signer interface {
	SignIn(ctx context.Context, u user.User, systemCode, tenantID string) (session.Tokens, error)
}

type Access interface {
	SelfSignupRole(ctx context.Context, systemCode string) (string, error)
	GrantPersonal(ctx context.Context, userID, systemCode, role string) error
}

type AttemptStore interface {
	Failures(ctx context.Context, key string, since time.Time) (count int, oldest time.Time, err error)
	Record(ctx context.Context, key string, at, cutoff time.Time) error
	Clear(ctx context.Context, key string) error
}

type Limits struct {
	MaxPerEmail int
	MaxPerIP    int
	Window      time.Duration
}

type Deps struct {
	// Verifier is nil when no Google client ID is configured: Google sign-in is then unavailable.
	Verifier  Verifier
	Store     Store
	Users     Users
	Registrar Registrar
	Hasher    Hasher
	Signer    Signer
	Access    Access
	Attempts  AttemptStore
	// DummyHash is verified when there is no hash, so the time does not tell.
	DummyHash string
	Limits    Limits
}

type Service struct {
	deps Deps
	now  func() time.Time
}

func NewService(deps Deps, now func() time.Time) *Service { return &Service{deps: deps, now: now} }

// NewChallenge creates the single-use nonce that the app must put in its Google request.
func (s *Service) NewChallenge(ctx context.Context) (string, error) {
	if s.deps.Verifier == nil {
		return "", ErrUnavailable
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	nonce := base64.RawURLEncoding.EncodeToString(raw)
	now := s.now()
	if err := s.deps.Store.CreateChallenge(ctx, hashNonce(nonce), now.Add(ChallengeTTL), now); err != nil {
		return "", err
	}
	return nonce, nil
}

type SignInInput struct {
	System     string
	Credential string
	Nonce      string
	// Password is only needed the first time, to link Google to an account that already exists with that email.
	Password string
	TenantID string
}

// SignIn opens a session for the Google account: it uses the linked account, links one that exists with the
// same email (after confirming its password), or creates a new one in systems that accept sign-up.
// The nonce is consumed only right before something changes, so asking for the password does not burn it.
func (s *Service) SignIn(ctx context.Context, in SignInInput, ip string) (session.Tokens, error) {
	if s.deps.Verifier == nil {
		return session.Tokens{}, ErrUnavailable
	}
	if in.System == "" || len(in.System) > 64 || in.Nonce == "" || len(in.Nonce) > 128 ||
		in.Credential == "" || len(in.Credential) > 16384 || len(in.Password) > 512 {
		return session.Tokens{}, ErrInvalidInput
	}
	account, err := s.deps.Verifier.Verify(ctx, in.Credential, in.Nonce)
	if err != nil {
		return session.Tokens{}, err
	}
	email, ok := user.NormalizeEmail(account.Email)
	if !ok || account.Subject == "" || len(account.Subject) > 255 {
		return session.Tokens{}, ErrInvalidCredentia
	}

	userID, linked, err := s.deps.Store.UserBySubject(ctx, account.Subject)
	if err != nil {
		return session.Tokens{}, err
	}
	var u user.User
	create := false
	switch {
	case linked:
		if u, err = s.deps.Users.GetByID(ctx, userID); err != nil {
			return session.Tokens{}, fmt.Errorf("google sign in: %w", err)
		}
	default:
		u, err = s.deps.Users.GetByEmail(ctx, email)
		switch {
		case err == nil:
			if err := s.confirmPassword(ctx, u, in.Password, ip); err != nil {
				return session.Tokens{}, err
			}
		case errors.Is(err, user.ErrUserNotFound):
			// A new account needs a system that accepts them; checked before anything is consumed.
			if _, err := s.deps.Access.SelfSignupRole(ctx, in.System); err != nil {
				return session.Tokens{}, err
			}
			create = true
		default:
			return session.Tokens{}, fmt.Errorf("google sign in: %w", err)
		}
	}

	consumed, err := s.deps.Store.ConsumeChallenge(ctx, hashNonce(in.Nonce), s.now())
	if err != nil {
		return session.Tokens{}, err
	}
	if !consumed {
		return session.Tokens{}, ErrChallenge
	}

	if create {
		if u, err = s.deps.Registrar.RegisterExternal(ctx, email, account.Name); err != nil {
			return session.Tokens{}, err
		}
	}
	if !linked {
		if err := s.deps.Store.Link(ctx, account.Subject, u.ID); err != nil {
			return session.Tokens{}, err
		}
	}
	return s.enter(ctx, u, in)
}

// enter signs the person in; if they have no access yet to a system that accepts sign-up, it gives them
// the self-signup role first (someone of Pulso who opens Orbita with Google, for instance).
func (s *Service) enter(ctx context.Context, u user.User, in SignInInput) (session.Tokens, error) {
	tokens, err := s.deps.Signer.SignIn(ctx, u, in.System, in.TenantID)
	if !errors.Is(err, access.ErrNoAccess) || in.TenantID != "" {
		return tokens, err
	}
	role, rerr := s.deps.Access.SelfSignupRole(ctx, in.System)
	if rerr != nil {
		return session.Tokens{}, err
	}
	if err := s.deps.Access.GrantPersonal(ctx, u.ID, in.System, role); err != nil {
		return session.Tokens{}, err
	}
	return s.deps.Signer.SignIn(ctx, u, in.System, "")
}

// confirmPassword is the proof of ownership of an existing account before Google is linked to it. Only wrong
// passwords count against the throttle.
func (s *Service) confirmPassword(ctx context.Context, u user.User, password, ip string) error {
	if password == "" {
		if u.PasswordHash == "" {
			// Nothing to confirm with: the person must set a password first (forgot-password) or use another way in.
			return ErrBadCredentials
		}
		return ErrLinkRequired
	}
	emailKey, ipKey := "google-link:"+u.Email, "google-link-ip:"+ip
	now := s.now()
	for _, c := range []struct {
		key string
		max int
	}{{emailKey, s.deps.Limits.MaxPerEmail}, {ipKey, s.deps.Limits.MaxPerIP}} {
		count, oldest, err := s.deps.Attempts.Failures(ctx, c.key, now.Add(-s.deps.Limits.Window))
		if err != nil {
			return fmt.Errorf("check attempts: %w", err)
		}
		if count >= c.max {
			return &TooManyAttemptsError{RetryAfter: oldest.Add(s.deps.Limits.Window).Sub(now)}
		}
	}
	hash := s.deps.DummyHash
	if u.PasswordHash != "" {
		hash = u.PasswordHash
	}
	ok, err := s.deps.Hasher.Verify(password, hash)
	if err != nil {
		return fmt.Errorf("verify password: %w", err)
	}
	if !ok || u.PasswordHash == "" || u.Status != user.StatusActive {
		for _, key := range []string{emailKey, ipKey} {
			if err := s.deps.Attempts.Record(ctx, key, now, now.Add(-s.deps.Limits.Window)); err != nil {
				return fmt.Errorf("record attempt: %w", err)
			}
		}
		return ErrBadCredentials
	}
	return s.deps.Attempts.Clear(ctx, emailKey)
}

func hashNonce(nonce string) []byte {
	sum := sha256.Sum256([]byte(nonce))
	return sum[:]
}
