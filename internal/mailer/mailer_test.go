package mailer

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/AtmosferaSoltec/atm-auth-api/internal/platform"
)

type fakeSigner struct{ last platform.Claims }

func (f *fakeSigner) Sign(c platform.Claims) (string, error) { f.last = c; return "signed-token", nil }

func TestSendResetCode(t *testing.T) {
	var got emailRequest
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		if r.URL.Path != "/v1/email" || r.Method != http.MethodPost {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	signer := &fakeSigner{}
	c := New(srv.URL+"/", signer, time.Now)
	if err := c.SendResetCode(context.Background(), "orbita", "a@b.co", "Ana", "123456", 15*time.Minute); err != nil {
		t.Fatal(err)
	}
	if auth != "Bearer signed-token" || signer.last.System != "orbita" || signer.last.Role != "service" || signer.last.Subject != "system:orbita" {
		t.Fatalf("token claims: %+v auth=%q", signer.last, auth)
	}
	if got.To != "a@b.co" || got.Template != "password_reset_code" || got.Data["code"] != "123456" || got.Data["expires_minutes"] != float64(15) {
		t.Fatalf("body: %+v", got)
	}
}

func TestUnavailableAndFailure(t *testing.T) {
	if err := New("", &fakeSigner{}, time.Now).SendPasswordChanged(context.Background(), "orbita", "a@b.co", ""); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("got %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }))
	defer srv.Close()
	if err := New(srv.URL, &fakeSigner{}, time.Now).SendPasswordChanged(context.Background(), "orbita", "a@b.co", ""); err == nil {
		t.Fatal("a 503 must be an error")
	}
}
