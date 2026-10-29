package platform

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"
)

func testKeyBase64(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	return base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func newTestSigner(t *testing.T, now time.Time) *TokenSigner {
	t.Helper()
	s, err := NewTokenSigner(testKeyBase64(t), "test-issuer", func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestTokenSignVerify(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s := newTestSigner(t, now)
	good := Claims{Subject: "u1", Role: "user", System: "olympus", IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix()}

	tok, err := s.Sign(good)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Verify(tok)
	if err != nil {
		t.Fatal(err)
	}
	if got.Subject != "u1" || got.Role != "user" || got.System != "olympus" || got.Issuer != "test-issuer" || got.ID == "" {
		t.Fatalf("unexpected claims: %+v", got)
	}

	t.Run("expired", func(t *testing.T) {
		expired := good
		expired.ExpiresAt = now.Add(-time.Second).Unix()
		tok, _ := s.Sign(expired)
		if _, err := s.Verify(tok); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("tampered payload", func(t *testing.T) {
		parts := strings.Split(tok, ".")
		forged, _ := json.Marshal(Claims{Subject: "admin", Role: "superadmin", Issuer: "test-issuer", ExpiresAt: now.Add(time.Hour).Unix()})
		if _, err := s.Verify(parts[0] + "." + b64(forged) + "." + parts[2]); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("alg none", func(t *testing.T) {
		parts := strings.Split(tok, ".")
		none := b64([]byte(`{"alg":"none","typ":"JWT"}`))
		if _, err := s.Verify(none + "." + parts[1] + "."); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("signed by another key", func(t *testing.T) {
		other := newTestSigner(t, now)
		tok, _ := other.Sign(good)
		if _, err := s.Verify(tok); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("garbage", func(t *testing.T) {
		for _, bad := range []string{"", "a.b", "a.b.c", "...."} {
			if _, err := s.Verify(bad); err == nil {
				t.Fatalf("expected error for %q", bad)
			}
		}
	})
}

func TestTokenSignerRejectsBadKeys(t *testing.T) {
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	der, _ := x509.MarshalPKCS8PrivateKey(small)
	smallB64 := base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	for name, in := range map[string]string{"not base64": "%%%", "not pem": base64.StdEncoding.EncodeToString([]byte("x")), "too small": smallB64} {
		if _, err := NewTokenSigner(in, "i", time.Now); err == nil {
			t.Fatalf("%s: expected error", name)
		}
	}
}

func TestJWKS(t *testing.T) {
	s := newTestSigner(t, time.Now())
	raw, err := s.JWKS()
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Keys []map[string]string `json:"keys"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || len(out.Keys) != 1 {
		t.Fatalf("bad jwks: %s", raw)
	}
	k := out.Keys[0]
	if k["kty"] != "RSA" || k["alg"] != "RS256" || k["kid"] != s.kid || k["n"] == "" || k["e"] != "AQAB" {
		t.Fatalf("unexpected key: %v", k)
	}
	if strings.Contains(string(raw), `"d"`) {
		t.Fatal("private exponent leaked")
	}
}
