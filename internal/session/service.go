package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/AtmosferaSoltec/atm-auth-api/internal/access"
	"github.com/AtmosferaSoltec/atm-auth-api/internal/platform"
	"github.com/AtmosferaSoltec/atm-auth-api/internal/user"
)

type PasswordHasher interface {
	Hash(password string) (string, error)
	Verify(password, encodedHash string) (bool, error)
}

type TokenSigner interface {
	Sign(c platform.Claims) (string, error)
}

type UserFinder interface {
	GetByDNI(ctx context.Context, dni string) (user.User, error)
	GetByID(ctx context.Context, id string) (user.User, error)
	SetPassword(ctx context.Context, id, passwordHash string, mustChange bool) error
}

type AccessResolver interface {
	// Resolve returns access.ErrNoAccess when the user cannot enter the system.
	Resolve(ctx context.Context, userID, systemCode string) (access.Grant, error)
}

type Service struct {
	deps       Deps
	admin      AdminCredentials
	dummyHash  string
	limits     Limits
	accessTTL  time.Duration
	refreshTTL time.Duration
	now        func() time.Time
}

type Deps struct {
	Tokens   RefreshStore
	Attempts AttemptStore
	Users    UserFinder
	Access   AccessResolver
	Hasher   PasswordHasher
	Signer   TokenSigner
}

type Config struct {
	Admin AdminCredentials
	// DummyHash is a valid password hash verified when a DNI does not exist,
	// so the response time does not reveal whether the account exists.
	DummyHash  string
	Limits     Limits
	AccessTTL  time.Duration
	RefreshTTL time.Duration
}

func NewService(deps Deps, cfg Config, now func() time.Time) *Service {
	return &Service{
		deps: deps, admin: cfg.Admin, dummyHash: cfg.DummyHash, limits: cfg.Limits,
		accessTTL: cfg.AccessTTL, refreshTTL: cfg.RefreshTTL, now: now,
	}
}

// AdminLogin authenticates the superadmin. ip is the client address used for throttling.
func (s *Service) AdminLogin(ctx context.Context, dni, password, ip string) (Tokens, error) {
	subjectKey, ipKey := "admin:"+dni, "ip:"+ip
	if err := s.checkLimits(ctx, subjectKey, ipKey); err != nil {
		return Tokens{}, err
	}

	// The password is always verified so the response time does not reveal whether the DNI matched.
	ok, err := s.deps.Hasher.Verify(password, s.admin.PasswordHash)
	if err != nil {
		return Tokens{}, fmt.Errorf("admin login: %w", err)
	}
	dniMatch := subtle.ConstantTimeCompare([]byte(dni), []byte(s.admin.DNI)) == 1
	if !ok || !dniMatch {
		if err := s.recordFailure(ctx, subjectKey, ipKey); err != nil {
			return Tokens{}, err
		}
		return Tokens{}, ErrInvalidCredentials
	}

	if err := s.deps.Attempts.Clear(ctx, subjectKey); err != nil {
		return Tokens{}, fmt.Errorf("admin login: clear attempts: %w", err)
	}
	tokens, err := s.issue(ctx, RefreshToken{Role: RoleSuperadmin}, nil)
	if err != nil {
		return Tokens{}, fmt.Errorf("admin login: %w", err)
	}
	return tokens, nil
}

// UserLogin authenticates a user for one system and resolves the tenant and role they have there.
// Failed password checks are throttled; a correct password without access is not.
func (s *Service) UserLogin(ctx context.Context, dni, password, systemCode, ip string) (Tokens, error) {
	subjectKey, ipKey := "dni:"+dni, "ip:"+ip
	if err := s.checkLimits(ctx, subjectKey, ipKey); err != nil {
		return Tokens{}, err
	}

	u, err := s.deps.Users.GetByDNI(ctx, dni)
	found := err == nil
	if err != nil && !errors.Is(err, user.ErrUserNotFound) {
		return Tokens{}, fmt.Errorf("user login: %w", err)
	}
	hash := s.dummyHash
	if found {
		hash = u.PasswordHash
	}
	ok, err := s.deps.Hasher.Verify(password, hash)
	if err != nil {
		return Tokens{}, fmt.Errorf("user login: %w", err)
	}
	if !found || !ok || u.Status != user.StatusActive {
		if err := s.recordFailure(ctx, subjectKey, ipKey); err != nil {
			return Tokens{}, err
		}
		return Tokens{}, ErrInvalidCredentials
	}
	if err := s.deps.Attempts.Clear(ctx, subjectKey); err != nil {
		return Tokens{}, fmt.Errorf("user login: clear attempts: %w", err)
	}

	if u.MustChangePassword {
		return Tokens{}, ErrPasswordChangeRequired
	}

	grant, err := s.deps.Access.Resolve(ctx, u.ID, systemCode)
	if err != nil {
		return Tokens{}, err
	}
	tokens, err := s.issue(ctx, userTemplate(u.ID, "", grant), &grant)
	if err != nil {
		return Tokens{}, fmt.Errorf("user login: %w", err)
	}
	return tokens, nil
}

// ChangePassword sets a new password after verifying the current one, then ends all of the user's sessions.
// It does not issue tokens: the user must log in again.
func (s *Service) ChangePassword(ctx context.Context, dni, current, next, ip string) error {
	subjectKey, ipKey := "dni:"+dni, "ip:"+ip
	if err := s.checkLimits(ctx, subjectKey, ipKey); err != nil {
		return err
	}

	u, err := s.deps.Users.GetByDNI(ctx, dni)
	found := err == nil
	if err != nil && !errors.Is(err, user.ErrUserNotFound) {
		return fmt.Errorf("change password: %w", err)
	}
	hash := s.dummyHash
	if found {
		hash = u.PasswordHash
	}
	ok, err := s.deps.Hasher.Verify(current, hash)
	if err != nil {
		return fmt.Errorf("change password: %w", err)
	}
	if !found || !ok || u.Status != user.StatusActive {
		if err := s.recordFailure(ctx, subjectKey, ipKey); err != nil {
			return err
		}
		return ErrInvalidCredentials
	}
	if !user.ValidNewPassword(next, dni) || next == current {
		return user.ErrWeakPassword
	}

	newHash, err := s.deps.Hasher.Hash(next)
	if err != nil {
		return fmt.Errorf("change password: %w", err)
	}
	if err := s.deps.Users.SetPassword(ctx, u.ID, newHash, false); err != nil {
		return fmt.Errorf("change password: %w", err)
	}
	if err := s.deps.Attempts.Clear(ctx, subjectKey); err != nil {
		return fmt.Errorf("change password: clear attempts: %w", err)
	}
	return s.RevokeUserSessions(ctx, u.ID)
}

// RevokeUserSessions ends every session of a user.
func (s *Service) RevokeUserSessions(ctx context.Context, userID string) error {
	if err := s.deps.Tokens.RevokeUser(ctx, userID, s.now()); err != nil {
		return fmt.Errorf("revoke user sessions: %w", err)
	}
	return nil
}

// Refresh rotates a refresh token. Presenting an already used token revokes its whole family.
// For users the account and access are checked again, so removing access ends the session.
func (s *Service) Refresh(ctx context.Context, raw string) (Tokens, error) {
	old, err := s.deps.Tokens.FindByHash(ctx, hashToken(raw))
	if err != nil {
		return Tokens{}, err
	}
	now := s.now()
	if old.RevokedAt != nil || !old.ExpiresAt.After(now) {
		return Tokens{}, ErrInvalidRefreshToken
	}
	if old.UsedAt != nil {
		if err := s.deps.Tokens.RevokeFamily(ctx, old.FamilyID, now); err != nil {
			return Tokens{}, fmt.Errorf("refresh: revoke family: %w", err)
		}
		return Tokens{}, ErrInvalidRefreshToken
	}

	tmpl := RefreshToken{FamilyID: old.FamilyID, Role: old.Role}
	var grant *access.Grant
	if old.Role == RoleUser {
		g, err := s.currentGrant(ctx, old)
		if err != nil {
			return Tokens{}, err
		}
		grant = &g
		tmpl = userTemplate(old.UserID, old.FamilyID, g)
	}

	won, err := s.deps.Tokens.MarkUsed(ctx, old.ID, now)
	if err != nil {
		return Tokens{}, fmt.Errorf("refresh: %w", err)
	}
	if !won {
		return Tokens{}, ErrInvalidRefreshToken
	}
	tokens, err := s.issue(ctx, tmpl, grant)
	if err != nil {
		return Tokens{}, fmt.Errorf("refresh: %w", err)
	}
	return tokens, nil
}

// currentGrant re-checks a user's account and access. If either is gone the whole session is revoked.
func (s *Service) currentGrant(ctx context.Context, old RefreshToken) (access.Grant, error) {
	deny := func() (access.Grant, error) {
		if err := s.deps.Tokens.RevokeFamily(ctx, old.FamilyID, s.now()); err != nil {
			return access.Grant{}, fmt.Errorf("refresh: revoke family: %w", err)
		}
		return access.Grant{}, ErrInvalidRefreshToken
	}
	u, err := s.deps.Users.GetByID(ctx, old.UserID)
	if errors.Is(err, user.ErrUserNotFound) {
		return deny()
	}
	if err != nil {
		return access.Grant{}, fmt.Errorf("refresh: %w", err)
	}
	if u.Status != user.StatusActive || u.MustChangePassword {
		return deny()
	}
	g, err := s.deps.Access.Resolve(ctx, old.UserID, old.SystemCode)
	if errors.Is(err, access.ErrNoAccess) {
		return deny()
	}
	if err != nil {
		return access.Grant{}, fmt.Errorf("refresh: %w", err)
	}
	return g, nil
}

func userTemplate(userID, familyID string, g access.Grant) RefreshToken {
	return RefreshToken{
		FamilyID: familyID, Role: RoleUser,
		UserID: userID, SystemID: g.SystemID, SystemCode: g.SystemCode,
	}
}

// Logout revokes the whole session family of a refresh token. Unknown tokens are ignored.
func (s *Service) Logout(ctx context.Context, raw string) error {
	t, err := s.deps.Tokens.FindByHash(ctx, hashToken(raw))
	if err == ErrInvalidRefreshToken {
		return nil
	}
	if err != nil {
		return fmt.Errorf("logout: %w", err)
	}
	if err := s.deps.Tokens.RevokeFamily(ctx, t.FamilyID, s.now()); err != nil {
		return fmt.Errorf("logout: %w", err)
	}
	return nil
}

func (s *Service) checkLimits(ctx context.Context, subjectKey, ipKey string) error {
	since := s.now().Add(-s.limits.Window)
	for _, c := range []struct {
		key string
		max int
	}{{subjectKey, s.limits.MaxPerSubject}, {ipKey, s.limits.MaxPerIP}} {
		count, oldest, err := s.deps.Attempts.Failures(ctx, c.key, since)
		if err != nil {
			return fmt.Errorf("check login attempts: %w", err)
		}
		if count >= c.max {
			return &TooManyAttemptsError{RetryAfter: oldest.Add(s.limits.Window).Sub(s.now())}
		}
	}
	return nil
}

func (s *Service) recordFailure(ctx context.Context, keys ...string) error {
	now := s.now()
	for _, k := range keys {
		if err := s.deps.Attempts.Record(ctx, k, now, now.Add(-s.limits.Window)); err != nil {
			return fmt.Errorf("record login failure: %w", err)
		}
	}
	return nil
}

// issue stores a new refresh token built from tmpl and signs a matching access token.
// grant is nil for the superadmin.
func (s *Service) issue(ctx context.Context, tmpl RefreshToken, grant *access.Grant) (Tokens, error) {
	raw, err := newRefreshToken()
	if err != nil {
		return Tokens{}, err
	}
	now := s.now()
	tmpl.TokenHash = hashToken(raw)
	tmpl.ExpiresAt = now.Add(s.refreshTTL)
	if _, err := s.deps.Tokens.Create(ctx, tmpl); err != nil {
		return Tokens{}, fmt.Errorf("store refresh token: %w", err)
	}

	claims := platform.Claims{
		Subject:   tmpl.UserID,
		Role:      tmpl.Role,
		System:    tmpl.SystemCode,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(s.accessTTL).Unix(),
	}
	if tmpl.Role == RoleSuperadmin {
		claims.Subject = AdminSubject
	}
	if grant != nil {
		claims.Tenant = grant.TenantID
		claims.AppRole = grant.Role
		claims.ManageUsers = grant.ManageUsers
	}
	access, err := s.deps.Signer.Sign(claims)
	if err != nil {
		return Tokens{}, err
	}
	return Tokens{AccessToken: access, RefreshToken: raw, ExpiresIn: int(s.accessTTL.Seconds())}, nil
}

func newRefreshToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate refresh token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// hashToken hashes a high-entropy refresh token. A fast hash is enough because the input is random.
func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
