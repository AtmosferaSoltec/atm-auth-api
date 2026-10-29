package httpx

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestRequestID(t *testing.T) {
	h := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	t.Run("propagates incoming id", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set(RequestIDHeader, "abc")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if got := rec.Header().Get(RequestIDHeader); got != "abc" {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("generates id", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		if rec.Header().Get(RequestIDHeader) == "" {
			t.Fatal("expected generated id")
		}
	})
}

func TestRecover(t *testing.T) {
	h := Recover(discardLogger(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("boom")
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("got status %d", rec.Code)
	}
}

func TestCORS(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTeapot) })
	h := CORS([]string{"https://app.example.com"}, next)

	do := func(method, origin string, preflight bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "/v1/login", nil)
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		if preflight {
			req.Header.Set("Access-Control-Request-Method", "POST")
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	t.Run("allowed origin gets the header", func(t *testing.T) {
		rec := do(http.MethodPost, "https://app.example.com", false)
		if rec.Code != http.StatusTeapot || rec.Header().Get("Access-Control-Allow-Origin") != "https://app.example.com" {
			t.Fatalf("got %d %v", rec.Code, rec.Header())
		}
		if rec.Header().Get("Access-Control-Allow-Credentials") != "" {
			t.Fatal("credentials must never be allowed")
		}
	})
	t.Run("preflight is answered without reaching the handler", func(t *testing.T) {
		rec := do(http.MethodOptions, "https://app.example.com", true)
		if rec.Code != http.StatusNoContent || rec.Header().Get("Access-Control-Allow-Headers") == "" {
			t.Fatalf("got %d %v", rec.Code, rec.Header())
		}
	})
	t.Run("other origins get nothing", func(t *testing.T) {
		rec := do(http.MethodPost, "https://evil.example.com", false)
		if rec.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Fatalf("got %v", rec.Header())
		}
		if rec := do(http.MethodOptions, "https://evil.example.com", true); rec.Code == http.StatusNoContent {
			t.Fatal("preflight from a stranger must not succeed")
		}
	})
	t.Run("no origin, no change", func(t *testing.T) {
		if rec := do(http.MethodGet, "", false); rec.Code != http.StatusTeapot || rec.Header().Get("Vary") != "" {
			t.Fatalf("got %d %v", rec.Code, rec.Header())
		}
	})
}
