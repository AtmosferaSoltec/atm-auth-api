package server_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/AtmosferaSoltec/atm-auth-api/internal/google"
)

// fakeGoogleVerifier accepts credentials of the form "ok:<subject>:<email>" and checks nothing else:
// the real verification of Google's signature is the library's job.
type fakeGoogleVerifier struct{}

func (fakeGoogleVerifier) Verify(_ context.Context, credential, _ string) (google.Account, error) {
	var subject, email string
	for i, part := range splitColon(credential) {
		switch i {
		case 1:
			subject = part
		case 2:
			email = part
		}
	}
	if len(credential) < 3 || credential[:3] != "ok:" {
		return google.Account{}, google.ErrInvalidCredentia
	}
	return google.Account{Subject: subject, Email: email, Name: "Gina Google"}, nil
}

func splitColon(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

func (e *e2e) nonce(t *testing.T) string {
	t.Helper()
	rec := call(e.handler, "POST", "/v1/google/challenge", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("challenge: %d %s", rec.Code, rec.Body)
	}
	var out struct {
		Nonce string `json:"nonce"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return out.Nonce
}

func TestGoogleCreatesAccountAndSignsInAgain(t *testing.T) {
	e := newE2EFull(t)
	e.seedPersonal(t, "orbitatest")
	h := e.handler

	nonce := e.nonce(t)
	body := map[string]string{"system": "orbitatest", "credential": "ok:sub-1:gina@example.com", "nonce": nonce}
	rec := call(h, "POST", "/v1/google", "", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("first sign-in: %d %s", rec.Code, rec.Body)
	}
	var tok tokenBody
	_ = json.Unmarshal(rec.Body.Bytes(), &tok)
	c := claimsOf(t, tok.AccessToken)
	if c.Email != "gina@example.com" || c.AppRole != "admin" || c.Tenant != "" {
		t.Fatalf("claims: %+v", c)
	}

	// The nonce is single use.
	if rec := call(h, "POST", "/v1/google", "", body); rec.Code != http.StatusUnauthorized {
		t.Fatalf("replayed nonce: %d %s", rec.Code, rec.Body)
	}
	// A second visit with the same Google account signs into the same person.
	body["nonce"] = e.nonce(t)
	rec = call(h, "POST", "/v1/google", "", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("second sign-in: %d %s", rec.Code, rec.Body)
	}
	var tok2 tokenBody
	_ = json.Unmarshal(rec.Body.Bytes(), &tok2)
	if claimsOf(t, tok2.AccessToken).Subject != c.Subject {
		t.Fatal("a returning Google account must be the same user")
	}
	// An account created with Google has no password: it cannot sign in with one.
	if rec := call(h, "POST", "/v1/login", "", map[string]string{"system": "orbitatest", "email": "gina@example.com", "password": "anything-long"}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("password login of a Google-only account: %d", rec.Code)
	}
}

func TestGoogleLinksExistingAccountOnlyWithItsPassword(t *testing.T) {
	e := newE2EFull(t)
	e.seedPersonal(t, "orbitatest")
	h := e.handler
	call(h, "POST", "/v1/register", "", map[string]string{"system": "orbitatest", "email": "ana@example.com", "full_name": "Ana", "password": "ana-password-1"})

	nonce := e.nonce(t)
	body := map[string]string{"system": "orbitatest", "credential": "ok:sub-ana:ana@example.com", "nonce": nonce}
	if rec := call(h, "POST", "/v1/google", "", body); rec.Code != http.StatusConflict {
		t.Fatalf("without password: %d %s", rec.Code, rec.Body)
	}
	body["password"] = "wrong-password"
	if rec := call(h, "POST", "/v1/google", "", body); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password: %d %s", rec.Code, rec.Body)
	}
	// Asking for the password did not burn the nonce.
	body["password"] = "ana-password-1"
	if rec := call(h, "POST", "/v1/google", "", body); rec.Code != http.StatusOK {
		t.Fatalf("with password: %d %s", rec.Code, rec.Body)
	}
	// Linked: from now on no password is needed.
	body2 := map[string]string{"system": "orbitatest", "credential": "ok:sub-ana:ana@example.com", "nonce": e.nonce(t)}
	if rec := call(h, "POST", "/v1/google", "", body2); rec.Code != http.StatusOK {
		t.Fatalf("linked: %d %s", rec.Code, rec.Body)
	}
}

func TestGoogleRejections(t *testing.T) {
	e := newE2EFull(t)
	e.seedPersonal(t, "orbitatest")
	e.seedSystem(t, "closed", "Closed")
	h := e.handler

	if rec := call(h, "POST", "/v1/google", "", map[string]string{"system": "orbitatest", "credential": "bad", "nonce": e.nonce(t)}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad credential: %d", rec.Code)
	}
	if rec := call(h, "POST", "/v1/google", "", map[string]string{"system": "closed", "credential": "ok:s:new@example.com", "nonce": e.nonce(t)}); rec.Code != http.StatusForbidden {
		t.Fatalf("system without sign-up: %d %s", rec.Code, rec.Body)
	}
	if rec := call(h, "POST", "/v1/google", "", map[string]string{"system": "orbitatest", "credential": "ok:s:new@example.com", "nonce": "never-issued"}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unknown nonce: %d", rec.Code)
	}
}
