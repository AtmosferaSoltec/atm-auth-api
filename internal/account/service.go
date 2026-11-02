// Package account lets a person delete their own account. It only serves people whose every access is to a
// personal system (Orbita): a global account that also works in company systems is deleted by the superadmin.
package account

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/AtmosferaSoltec/atm-auth-api/internal/access"
	"github.com/AtmosferaSoltec/atm-auth-api/internal/google"
	"github.com/AtmosferaSoltec/atm-auth-api/internal/platform"
	"github.com/AtmosferaSoltec/atm-auth-api/internal/user"
)

type Users interface {
	GetByID(ctx context.Context, id string) (user.User, error)
}

type Hasher interface {
	Verify(password, encodedHash string) (bool, error)
}

type Accesses interface {
	ListByUser(ctx context.Context, userID string) ([]access.Detail, error)
}

type Repository interface {
	// IsPersonal reports whether the system has no companies.
	IsPersonal(ctx context.Context, systemCode string) (bool, error)
	// Delete removes the user; sessions, access and linked identities go with it.
	Delete(ctx context.Context, userID string) error
	// GoogleLinkedTo reports whether the Google subject is linked to the user.
	GoogleLinkedTo(ctx context.Context, subject, userID string) (bool, error)
	ConsumeChallenge(ctx context.Context, hash []byte, now time.Time) (bool, error)
}

type AttemptStore interface {
	Failures(ctx context.Context, key string, since time.Time) (count int, oldest time.Time, err error)
	Record(ctx context.Context, key string, at, cutoff time.Time) error
	Clear(ctx context.Context, key string) error
}

type TokenSigner interface {
	Sign(c platform.Claims) (string, error)
}

type Limits struct {
	MaxPerUser int
	MaxPerIP   int
	Window     time.Duration
}

type Deps struct {
	Users    Users
	Hasher   Hasher
	Accesses Accesses
	Repo     Repository
	Attempts AttemptStore
	// Verifier is nil when Google sign-in is off.
	Verifier  google.Verifier
	Signer    TokenSigner
	DummyHash string
	Limits    Limits
	// Hooks maps a system code to the URL that cleans up that system's data of a user (POST, idempotent).
	Hooks map[string]string
}

type Service struct {
	deps Deps
	http *http.Client
	now  func() time.Time
}

func NewService(deps Deps, now func() time.Time) *Service {
	return &Service{deps: deps, http: &http.Client{Timeout: 30 * time.Second}, now: now}
}

// Input proves who is asking: the password, or for accounts without one a fresh Google credential.
type Input struct {
	Password   string
	Credential string
	Nonce      string
}

// Delete removes the account of userID. Each system holding data of the person is asked to remove it first; if
// any refuses, nothing is deleted and the person can retry, so no data is left behind with nobody to claim it.
func (s *Service) Delete(ctx context.Context, userID string, in Input, ip string) error {
	if (in.Password == "") == (in.Credential == "") || len(in.Password) > 512 || len(in.Credential) > 16384 || len(in.Nonce) > 128 {
		return ErrInvalidInput
	}
	u, err := s.deps.Users.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("delete account: %w", err)
	}
	details, err := s.deps.Accesses.ListByUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("delete account: %w", err)
	}
	var systems []string
	for _, d := range details {
		personal, err := s.deps.Repo.IsPersonal(ctx, d.SystemCode)
		if err != nil {
			return fmt.Errorf("delete account: %w", err)
		}
		if !personal {
			return ErrShared
		}
		systems = append(systems, d.SystemCode)
	}

	if in.Password != "" {
		err = s.confirmPassword(ctx, u, in.Password, ip)
	} else {
		err = s.confirmGoogle(ctx, u, in)
	}
	if err != nil {
		return err
	}

	for _, code := range systems {
		if url := s.deps.Hooks[code]; url != "" {
			if err := s.notify(ctx, code, url, userID); err != nil {
				return fmt.Errorf("%w: %s: %v", ErrHookFailed, code, err)
			}
		}
	}
	if err := s.deps.Repo.Delete(ctx, userID); err != nil {
		return fmt.Errorf("delete account: %w", err)
	}
	return nil
}

func (s *Service) confirmPassword(ctx context.Context, u user.User, password, ip string) error {
	userKey, ipKey := "delete:"+u.ID, "delete-ip:"+ip
	now := s.now()
	for _, c := range []struct {
		key string
		max int
	}{{userKey, s.deps.Limits.MaxPerUser}, {ipKey, s.deps.Limits.MaxPerIP}} {
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
	if !ok || u.PasswordHash == "" {
		for _, key := range []string{userKey, ipKey} {
			if err := s.deps.Attempts.Record(ctx, key, now, now.Add(-s.deps.Limits.Window)); err != nil {
				return fmt.Errorf("record attempt: %w", err)
			}
		}
		return ErrBadCredentials
	}
	return s.deps.Attempts.Clear(ctx, userKey)
}

// confirmGoogle accepts a fresh credential (single-use nonce) of the Google identity linked to this very account.
func (s *Service) confirmGoogle(ctx context.Context, u user.User, in Input) error {
	if s.deps.Verifier == nil {
		return ErrGoogleUnavailble
	}
	if in.Nonce == "" {
		return ErrInvalidInput
	}
	acc, err := s.deps.Verifier.Verify(ctx, in.Credential, in.Nonce)
	if err != nil {
		return ErrBadCredentials
	}
	linked, err := s.deps.Repo.GoogleLinkedTo(ctx, acc.Subject, u.ID)
	if err != nil {
		return err
	}
	if !linked {
		return ErrNotLinked
	}
	ok, err := s.deps.Repo.ConsumeChallenge(ctx, google.HashNonce(in.Nonce), s.now())
	if err != nil {
		return err
	}
	if !ok {
		return ErrChallenge
	}
	return nil
}

// notify asks a system to delete the data it holds of the user, with a short-lived service token of this service.
func (s *Service) notify(ctx context.Context, system, url, userID string) error {
	now := s.now()
	token, err := s.deps.Signer.Sign(platform.Claims{
		Subject: "system:auth", Role: "service", System: "auth",
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(),
	})
	if err != nil {
		return fmt.Errorf("sign service token: %w", err)
	}
	body, err := json.Marshal(map[string]string{"user_id": userID, "system": system})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// 404 means the system holds nothing of this person: the same as done.
	if resp.StatusCode/100 != 2 && resp.StatusCode != http.StatusNotFound {
		return errors.New("system answered " + resp.Status)
	}
	return nil
}
