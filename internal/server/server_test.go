package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/AtmosferaSoltec/atm-auth-api/internal/platform"
	"github.com/AtmosferaSoltec/atm-auth-api/internal/session"
)

type fakePinger struct{ err error }

func (f fakePinger) Ping(context.Context) error { return f.err }

func newHandler(db Pinger) http.Handler {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return New(log, Deps{DB: db, Verifier: noVerifier{}, Session: session.NewHandler(nil, log, "")})
}

type noVerifier struct{}

func (noVerifier) Verify(string) (platform.Claims, error) { return platform.Claims{}, errors.New("no") }

func TestHealth(t *testing.T) {
	rec := httptest.NewRecorder()
	newHandler(fakePinger{}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d", rec.Code)
	}
	if rec.Header().Get("X-Request-ID") == "" {
		t.Fatal("missing X-Request-ID")
	}
}

func TestReady(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"database up", nil, http.StatusOK},
		{"database down", errors.New("down"), http.StatusServiceUnavailable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			newHandler(fakePinger{err: tt.err}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ready", nil))
			if rec.Code != tt.want {
				t.Fatalf("got %d, want %d", rec.Code, tt.want)
			}
		})
	}
}
