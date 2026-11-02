package recovery

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/AtmosferaSoltec/atm-auth-api/internal/user"
)

type PasswordHasher interface {
	Hash(password string) (string, error)
}

// Mailer sends the emails of the flow on behalf of a system.
type Mailer interface {
	SendResetCode(ctx context.Context, system, to, name, code string, validFor time.Duration) error
	SendPasswordChanged(ctx context.Context, system, to, name string) error
}

// AttemptStore is the same throttling store the logins use.
type AttemptStore interface {
	Failures(ctx context.Context, key string, since time.Time) (count int, oldest time.Time, err error)
	Record(ctx context.Context, key string, at, cutoff time.Time) error
	Clear(ctx context.Context, key string) error
}

// Limits throttles requests: per email and per IP inside a window.
type Limits struct {
	MaxPerEmail int
	MaxPerIP    int
	Window      time.Duration
}

type Service struct {
	repo    Repository
	hasher  PasswordHasher
	mailer  Mailer
	attempt AttemptStore
	key     []byte
	limits  Limits
	// systems are the codes that may be named in a request: the email is sent on behalf of one of them.
	systems map[string]bool
	log     *slog.Logger
	now     func() time.Time
	// background runs the work that must not delay the answer. Tests replace it to run inline.
	background func(func())
}

func NewService(repo Repository, hasher PasswordHasher, mailer Mailer, attempts AttemptStore, key []byte, limits Limits,
	systems []string, log *slog.Logger, now func() time.Time) *Service {
	known := make(map[string]bool, len(systems))
	for _, code := range systems {
		known[code] = true
	}
	return &Service{
		repo: repo, hasher: hasher, mailer: mailer, attempt: attempts, key: key, limits: limits,
		systems: known, log: log, now: now, background: func(f func()) { go f() },
	}
}

// RunInline makes the background work run before the call returns (for tests).
func (s *Service) RunInline() { s.background = func(f func()) { f() } }

// Forgot sends a code to the email if it has an account. It answers the same, and at the same speed, whether
// it does or not: the work happens in the background.
func (s *Service) Forgot(ctx context.Context, email, system, ip string) error {
	email, ok := user.NormalizeEmail(email)
	if !ok {
		return ErrInvalidEmail
	}
	if !s.systems[system] {
		return ErrUnknownSystem
	}
	// Every request counts, not only failures: this route is the one that sends mail.
	ipKey, emailKey := "forgot-ip:"+ip, "forgot:"+email
	if err := s.check(ctx, s.limits.MaxPerIP, ipKey); err != nil {
		return err
	}
	if err := s.check(ctx, s.limits.MaxPerEmail, emailKey); err != nil {
		return err
	}
	if err := s.record(ctx, ipKey, emailKey); err != nil {
		return err
	}
	bg := context.WithoutCancel(ctx)
	s.background(func() {
		bg, cancel := context.WithTimeout(bg, 20*time.Second)
		defer cancel()
		if err := s.issue(bg, email, system); err != nil {
			s.log.Error("password reset code", "error", err)
		}
	})
	return nil
}

func (s *Service) issue(ctx context.Context, email, system string) error {
	acc, found, err := s.repo.Find(ctx, email)
	if err != nil || !found {
		return err
	}
	now := s.now()
	sent, err := s.repo.CountSince(ctx, acc.ID, now.Add(-SendWindow))
	if err != nil || sent >= MaxSends {
		return err
	}
	code, err := newCode()
	if err != nil {
		return err
	}
	if err := s.repo.Replace(ctx, acc.ID, hashCode(s.key, acc.ID, code), now.Add(CodeTTL), now); err != nil {
		return err
	}
	return s.mailer.SendResetCode(ctx, system, acc.Email, acc.Name, code, CodeTTL)
}

// Verify says whether the code works, so the client can ask for the new password. It does not consume the
// code, but a wrong guess counts as an attempt.
func (s *Service) Verify(ctx context.Context, email, code, ip string) error {
	email, err := s.validate(email, code)
	if err != nil {
		return err
	}
	_, err = s.guard(ctx, email, ip, func() (Account, error) {
		return s.repo.Check(ctx, email, s.codeHasher(code), s.now(), "")
	})
	return err
}

// Reset changes the password with the code, ends every session and tells the owner. It does not sign in:
// the client goes to the login. A new password that is not acceptable does not consume the code.
func (s *Service) Reset(ctx context.Context, email, code, newPassword, system, ip string) error {
	email, err := s.validate(email, code)
	if err != nil {
		return err
	}
	if len(newPassword) < MinPasswordLength || len(newPassword) > MaxPasswordLength {
		return ErrWeakPassword
	}
	if system != "" && !s.systems[system] {
		return ErrUnknownSystem
	}
	hash, err := s.hashPassword(newPassword)
	if err != nil {
		return err
	}
	acc, err := s.guard(ctx, email, ip, func() (Account, error) {
		return s.repo.Check(ctx, email, s.codeHasher(code), s.now(), hash)
	})
	if err != nil {
		return err
	}
	if system != "" {
		bg := context.WithoutCancel(ctx)
		s.background(func() {
			bg, cancel := context.WithTimeout(bg, 20*time.Second)
			defer cancel()
			// So the owner finds out if it was not them.
			if err := s.mailer.SendPasswordChanged(bg, system, acc.Email, acc.Name); err != nil {
				s.log.Error("password changed email", "error", err)
			}
		})
	}
	return nil
}

func (s *Service) hashPassword(p string) (string, error) {
	h, err := s.hasher.Hash(p)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return h, nil
}

// codeHasher returns the function that turns a guess into its stored form for a user.
func (s *Service) codeHasher(code string) func(string) []byte {
	return func(userID string) []byte { return hashCode(s.key, userID, code) }
}

func (s *Service) validate(email, code string) (string, error) {
	normalized, ok := user.NormalizeEmail(email)
	if !ok {
		return "", ErrInvalidEmail
	}
	if !codePattern.MatchString(code) {
		return "", ErrInvalidCode
	}
	return normalized, nil
}

// guard throttles checks of a code per email and per IP. Only wrong guesses count, so the owner of the
// account is slowed down for a while but never locked out for good.
func (s *Service) guard(ctx context.Context, email, ip string, run func() (Account, error)) (Account, error) {
	emailKey, ipKey := "reset:"+email, "reset-ip:"+ip
	if err := s.check(ctx, s.limits.MaxPerEmail, emailKey); err != nil {
		return Account{}, err
	}
	if err := s.check(ctx, s.limits.MaxPerIP, ipKey); err != nil {
		return Account{}, err
	}
	acc, err := run()
	if errors.Is(err, ErrResetCodeWrong) {
		if rerr := s.record(ctx, emailKey, ipKey); rerr != nil {
			return Account{}, rerr
		}
		return Account{}, err
	}
	if err != nil {
		return Account{}, err
	}
	if err := s.attempt.Clear(ctx, emailKey); err != nil {
		return Account{}, fmt.Errorf("clear attempts: %w", err)
	}
	return acc, nil
}

func (s *Service) check(ctx context.Context, max int, key string) error {
	count, oldest, err := s.attempt.Failures(ctx, key, s.now().Add(-s.limits.Window))
	if err != nil {
		return fmt.Errorf("check attempts: %w", err)
	}
	if count >= max {
		return &TooManyAttemptsError{RetryAfter: oldest.Add(s.limits.Window).Sub(s.now())}
	}
	return nil
}

func (s *Service) record(ctx context.Context, keys ...string) error {
	now := s.now()
	for _, k := range keys {
		if err := s.attempt.Record(ctx, k, now, now.Add(-s.limits.Window)); err != nil {
			return fmt.Errorf("record attempt: %w", err)
		}
	}
	return nil
}
