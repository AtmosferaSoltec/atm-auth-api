package platform

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

const minRSABits = 2048

var ErrInvalidToken = errors.New("invalid token")

// Claims are the JWT claims issued by this service.
//
// Role is the platform-level role ("superadmin" or "user") and is the only one this service trusts for
// authorization. AppRole is the free-text role the user has inside System and Tenant; it is only
// informational for the consuming system.
type Claims struct {
	Subject     string `json:"sub"`
	Role        string `json:"role"`
	System      string `json:"system,omitempty"`
	Tenant      string `json:"tenant,omitempty"`
	AppRole     string `json:"app_role,omitempty"`
	ManageUsers bool   `json:"manage_users,omitempty"`
	Issuer      string `json:"iss"`
	IssuedAt    int64  `json:"iat"`
	ExpiresAt   int64  `json:"exp"`
	ID          string `json:"jti"`
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// TokenSigner signs and verifies RS256 JWTs. It accepts no other algorithm.
type TokenSigner struct {
	key    *rsa.PrivateKey
	kid    string
	issuer string
	now    func() time.Time
}

// NewTokenSigner parses a base64-encoded PEM RSA private key (PKCS#8 or PKCS#1).
func NewTokenSigner(privateKeyBase64, issuer string, now func() time.Time) (*TokenSigner, error) {
	pemBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(privateKeyBase64))
	if err != nil {
		return nil, fmt.Errorf("parse jwt key: base64: %w", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("parse jwt key: no PEM block")
	}
	key, err := parseRSAKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	if key.N.BitLen() < minRSABits {
		return nil, fmt.Errorf("parse jwt key: key must have at least %d bits", minRSABits)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("parse jwt key: marshal public key: %w", err)
	}
	sum := sha256.Sum256(der)
	return &TokenSigner{key: key, kid: hex.EncodeToString(sum[:8]), issuer: issuer, now: now}, nil
}

func parseRSAKey(der []byte) (*rsa.PrivateKey, error) {
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("parse jwt key: not an RSA key")
		}
		return rk, nil
	}
	rk, err := x509.ParsePKCS1PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse jwt key: %w", err)
	}
	return rk, nil
}

// Sign sets the issuer and a random jti, then signs c.
func (s *TokenSigner) Sign(c Claims) (string, error) {
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", fmt.Errorf("sign token: jti: %w", err)
	}
	c.Issuer = s.issuer
	c.ID = hex.EncodeToString(jti)

	header, err := json.Marshal(jwtHeader{Alg: "RS256", Typ: "JWT", Kid: s.kid})
	if err != nil {
		return "", fmt.Errorf("sign token: header: %w", err)
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("sign token: payload: %w", err)
	}
	input := b64(header) + "." + b64(payload)
	digest := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}
	return input + "." + b64(sig), nil
}

// Verify checks the algorithm, signature, issuer and expiry, and returns the claims.
func (s *TokenSigner) Verify(token string) (Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, ErrInvalidToken
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Claims{}, ErrInvalidToken
	}
	var h jwtHeader
	if err := json.Unmarshal(headerBytes, &h); err != nil || h.Alg != "RS256" {
		return Claims{}, ErrInvalidToken
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Claims{}, ErrInvalidToken
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&s.key.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
		return Claims{}, ErrInvalidToken
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Claims{}, ErrInvalidToken
	}
	var c Claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return Claims{}, ErrInvalidToken
	}
	if c.Issuer != s.issuer || c.ExpiresAt <= s.now().Unix() {
		return Claims{}, ErrInvalidToken
	}
	return c, nil
}

// JWKS returns the public key as a JSON Web Key Set.
func (s *TokenSigner) JWKS() ([]byte, error) {
	e := big.NewInt(int64(s.key.E))
	return json.Marshal(map[string]any{"keys": []map[string]string{{
		"kty": "RSA", "use": "sig", "alg": "RS256", "kid": s.kid,
		"n": b64(s.key.N.Bytes()), "e": b64(e.Bytes()),
	}}})
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
