package google

import (
	"context"
	"crypto/subtle"
	"time"

	"google.golang.org/api/idtoken"
)

// Account holds only claims the verifier checked.
type Account struct {
	Subject string
	Email   string
	Name    string
}

type Verifier interface {
	Verify(ctx context.Context, credential, nonce string) (Account, error)
}

// IDTokenVerifier validates Google ID tokens with Google's maintained library (it caches the signing keys).
// The accepted audiences are the OAuth client IDs of our own web, Android and iOS apps; the caller never
// chooses one.
type IDTokenVerifier struct {
	clientIDs []string
	validate  func(ctx context.Context, token, audience string) (*idtoken.Payload, error)
	now       func() time.Time
}

func NewIDTokenVerifier(clientIDs []string) *IDTokenVerifier {
	return &IDTokenVerifier{clientIDs: clientIDs, validate: idtoken.Validate, now: time.Now}
}

func (v *IDTokenVerifier) Verify(ctx context.Context, credential, nonce string) (Account, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for _, aud := range v.clientIDs {
		payload, err := v.validate(ctx, credential, aud)
		if err != nil {
			continue
		}
		return accountFrom(payload, nonce, v.now())
	}
	return Account{}, ErrInvalidCredentia
}

func accountFrom(p *idtoken.Payload, nonce string, now time.Time) (Account, error) {
	if p.Issuer != "https://accounts.google.com" && p.Issuer != "accounts.google.com" {
		return Account{}, ErrInvalidCredentia
	}
	gotNonce, _ := p.Claims["nonce"].(string)
	verified, _ := p.Claims["email_verified"].(bool)
	email, _ := p.Claims["email"].(string)
	name, _ := p.Claims["name"].(string)
	if nonce == "" || subtle.ConstantTimeCompare([]byte(nonce), []byte(gotNonce)) != 1 || !verified ||
		p.Subject == "" || email == "" || p.Expires <= now.Unix() || p.IssuedAt > now.Add(time.Minute).Unix() {
		return Account{}, ErrInvalidCredentia
	}
	return Account{Subject: p.Subject, Email: email, Name: name}, nil
}
