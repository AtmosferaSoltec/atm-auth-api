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
	"github.com/AtmosferaSoltec/atm-auth-api/internal/credential"
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
	// Resolve returns access.ErrNoAccess when the user cannot enter the system (or the company asked for).
	// An empty tenantID picks the company used last, or else the first one the user was given.
	Resolve(ctx context.Context, userID, systemCode, tenantID string) (access.Grant, error)
	// Options lists the companies the user can work for in the system.
	Options(ctx context.Context, userID, systemCode string) ([]access.Option, error)
	// MarkUsed records the company the user works for, so the next login enters it.
	MarkUsed(ctx context.Context, userID, systemID, tenantID string) error
}

// ClientVerifier checks the secret a system's backend presents.
type ClientVerifier interface {
	// Verify returns credential.ErrInvalidClient unless the code and secret match an active system.
	Verify(ctx context.Context, clientID, secret string) (credential.Credential, error)
}

type Service struct {
	deps       Deps
	admin      AdminCredentials
	dummyHash  string
	limits     Limits
	accessTTL  time.Duration
	refreshTTL time.Duration
	// temporaryTTL bounds the refresh token of a "temporary" system. Zero means no extra bound.
	temporaryTTL time.Duration
	now          func() time.Time
}

type Deps struct {
	Tokens   RefreshStore
	Attempts AttemptStore
	Users    UserFinder
	Access   AccessResolver
	Hasher   PasswordHasher
	Signer   TokenSigner
	Clients  ClientVerifier
}

type Config struct {
	Admin AdminCredentials
	// DummyHash is a valid password hash verified when a DNI does not exist,
	// so the response time does not reveal whether the account exists.
	DummyHash  string
	Limits     Limits
	AccessTTL  time.Duration
	RefreshTTL time.Duration
	// TemporaryRefreshTTL is how long a "temporary" system's session lasts without being used. It is a ceiling
	// for sessions left behind, not a timer the user feels: clients drop the session when the tab closes.
	TemporaryRefreshTTL time.Duration
}

func NewService(deps Deps, cfg Config, now func() time.Time) *Service {
	return &Service{
		deps: deps, admin: cfg.Admin, dummyHash: cfg.DummyHash, limits: cfg.Limits,
		accessTTL: cfg.AccessTTL, refreshTTL: cfg.RefreshTTL, temporaryTTL: cfg.TemporaryRefreshTTL, now: now,
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
// tenantID is optional: without it the user enters the company they used last (or else the first one they
// were given) and can switch afterwards with Refresh.
// Failed password checks are throttled; a correct password without access is not.
func (s *Service) UserLogin(ctx context.Context, dni, password, systemCode, tenantID, ip string) (Tokens, error) {
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

	grant, err := s.deps.Access.Resolve(ctx, u.ID, systemCode, tenantID)
	if err != nil {
		return Tokens{}, err
	}
	tokens, err := s.issue(ctx, userTemplate(u.ID, "", grant), &grant)
	if err != nil {
		return Tokens{}, fmt.Errorf("user login: %w", err)
	}
	if err := s.deps.Access.MarkUsed(ctx, u.ID, grant.SystemID, grant.TenantID); err != nil {
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
//
// tenantID is optional. Empty keeps the session in its company. A different one switches the session to
// that company, if the user works for it in the system: the old token is spent and the new one carries
// the new company. A company the user cannot enter is refused (access.ErrNoAccess) without ending the
// session they have.
func (s *Service) Refresh(ctx context.Context, raw, tenantID string) (Tokens, error) {
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
	switching := false
	if old.Role == RoleUser {
		want := old.TenantID
		if tenantID != "" && tenantID != old.TenantID {
			want, switching = tenantID, true
		}
		g, err := s.currentGrant(ctx, old, want, switching)
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
	if switching {
		// The company the user chose becomes the one login enters next time.
		if err := s.deps.Access.MarkUsed(ctx, old.UserID, grant.SystemID, grant.TenantID); err != nil {
			return Tokens{}, fmt.Errorf("refresh: %w", err)
		}
	}
	return tokens, nil
}

// Tenants lists the companies a user can work for in a system, and which one the token is on.
func (s *Service) Tenants(ctx context.Context, userID, systemCode string) ([]access.Option, error) {
	options, err := s.deps.Access.Options(ctx, userID, systemCode)
	if err != nil {
		return nil, fmt.Errorf("list tenants: %w", err)
	}
	return options, nil
}

// currentGrant re-checks a user's account and access for the company the session works for (want). If the
// account or that access is gone the whole session is revoked, unless the user is only trying to switch to
// a company they cannot enter: then the switch is refused and the session they have stays as it is.
func (s *Service) currentGrant(ctx context.Context, old RefreshToken, want string, switching bool) (access.Grant, error) {
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
	g, err := s.deps.Access.Resolve(ctx, old.UserID, old.SystemCode, want)
	if errors.Is(err, access.ErrNoAccess) {
		if switching {
			return access.Grant{}, access.ErrNoAccess
		}
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
		UserID: userID, SystemID: g.SystemID, SystemCode: g.SystemCode, TenantID: g.TenantID,
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
	refreshTTL, mode := s.refreshTTL, "persistent"
	if grant != nil {
		if grant.SessionMode != "" {
			mode = grant.SessionMode
		}
		// A temporary session is bounded by its own, shorter ceiling.
		if mode == "temporary" && s.temporaryTTL > 0 && s.temporaryTTL < refreshTTL {
			refreshTTL = s.temporaryTTL
		}
	}
	tmpl.TokenHash = hashToken(raw)
	tmpl.ExpiresAt = now.Add(refreshTTL)
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
		claims.Name = grant.UserName
		claims.DNI = grant.UserDNI
		claims.TenantRUC = grant.TenantRUC
	}
	access, err := s.deps.Signer.Sign(claims)
	if err != nil {
		return Tokens{}, err
	}
	return Tokens{
		AccessToken: access, RefreshToken: raw, ExpiresIn: int(s.accessTTL.Seconds()),
		RefreshExpiresIn: int(refreshTTL.Seconds()), SessionMode: mode,
	}, nil
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

// ClientToken exchanges a system's secret for a short-lived service token. It issues no refresh token:
// the backend asks again when the token expires. Failures are throttled per system and per IP, like logins.
func (s *Service) ClientToken(ctx context.Context, clientID, secret, ip string) (Tokens, error) {
	subjectKey, ipKey := "client:"+clientID, "ip:"+ip
	if err := s.checkLimits(ctx, subjectKey, ipKey); err != nil {
		return Tokens{}, err
	}
	c, err := s.deps.Clients.Verify(ctx, clientID, secret)
	if errors.Is(err, credential.ErrInvalidClient) {
		if err := s.recordFailure(ctx, subjectKey, ipKey); err != nil {
			return Tokens{}, err
		}
		return Tokens{}, ErrInvalidClient
	}
	if err != nil {
		return Tokens{}, fmt.Errorf("client token: %w", err)
	}
	if err := s.deps.Attempts.Clear(ctx, subjectKey); err != nil {
		return Tokens{}, fmt.Errorf("client token: clear attempts: %w", err)
	}

	now := s.now()
	access, err := s.deps.Signer.Sign(platform.Claims{
		Subject:   "system:" + c.Code,
		Role:      RoleService,
		System:    c.Code,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(s.accessTTL).Unix(),
	})
	if err != nil {
		return Tokens{}, fmt.Errorf("client token: %w", err)
	}
	return Tokens{AccessToken: access, ExpiresIn: int(s.accessTTL.Seconds())}, nil
}
