package server_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/AtmosferaSoltec/atm-auth-api/internal/platform"
)

type tokenBody struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// seedPersonal registers a personal system that accepts self sign-up.
func (e *e2e) seedPersonal(t *testing.T, code string) {
	t.Helper()
	id := platform.SeedSystem(t, e.pool, code, code)
	platform.SeedRoles(t, e.pool, id, "admin")
	if _, err := e.pool.Exec(context.Background(),
		`UPDATE systems SET personal = true, self_signup = true, self_signup_role = 'admin' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
}

func TestPersonalSignupLoginRefresh(t *testing.T) {
	e := newE2EFull(t)
	e.seedPersonal(t, "orbitatest")
	h := e.handler

	body := map[string]string{"system": "orbitatest", "email": "  Ana@Example.COM ", "full_name": "Ana Pérez", "password": "correct-horse"}
	rec := call(h, "POST", "/v1/register", "", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register: got %d %s", rec.Code, rec.Body)
	}
	var tok tokenBody
	_ = json.Unmarshal(rec.Body.Bytes(), &tok)
	c := claimsOf(t, tok.AccessToken)
	if c.Email != "ana@example.com" || c.System != "orbitatest" || c.AppRole != "admin" || c.Role != "user" {
		t.Fatalf("claims: %+v", c)
	}
	if c.Tenant != "" {
		t.Fatalf("personal token must carry no tenant: %+v", c)
	}

	if rec := call(h, "POST", "/v1/register", "", body); rec.Code != http.StatusConflict {
		t.Fatalf("duplicate email: got %d %s", rec.Code, rec.Body)
	}

	login := map[string]string{"system": "orbitatest", "email": "ANA@example.com", "password": "correct-horse"}
	rec = call(h, "POST", "/v1/login", "", login)
	if rec.Code != http.StatusOK {
		t.Fatalf("login: got %d %s", rec.Code, rec.Body)
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &tok)
	if rec := call(h, "POST", "/v1/refresh", "", map[string]string{"refresh_token": tok.RefreshToken}); rec.Code != http.StatusOK {
		t.Fatalf("refresh: got %d %s", rec.Code, rec.Body)
	}

	login["password"] = "wrong-password"
	if rec := call(h, "POST", "/v1/login", "", login); rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad password: got %d", rec.Code)
	}
}

func TestSignupRejections(t *testing.T) {
	e := newE2EFull(t)
	e.seedPersonal(t, "orbitatest")
	e.seedSystem(t, "closed", "Closed")
	h := e.handler

	cases := []struct {
		name string
		body map[string]string
		want int
	}{
		{"system without self signup", map[string]string{"system": "closed", "email": "a@b.co", "full_name": "A", "password": "correct-horse"}, http.StatusForbidden},
		{"unknown system", map[string]string{"system": "nope", "email": "a@b.co", "full_name": "A", "password": "correct-horse"}, http.StatusForbidden},
		{"bad email", map[string]string{"system": "orbitatest", "email": "not-an-email", "full_name": "A", "password": "correct-horse"}, http.StatusBadRequest},
		{"short password", map[string]string{"system": "orbitatest", "email": "a@b.co", "full_name": "A", "password": "short"}, http.StatusBadRequest},
		{"no name", map[string]string{"system": "orbitatest", "email": "a@b.co", "full_name": " ", "password": "correct-horse"}, http.StatusBadRequest},
	}
	for _, c := range cases {
		if rec := call(h, "POST", "/v1/register", "", c.body); rec.Code != c.want {
			t.Errorf("%s: got %d %s, want %d", c.name, rec.Code, rec.Body, c.want)
		}
	}
}

func TestEmailAccountCannotEnterOtherSystems(t *testing.T) {
	e := newE2EFull(t)
	e.seedPersonal(t, "orbitatest")
	e.seedSystem(t, "other", "Other")
	h := e.handler
	call(h, "POST", "/v1/register", "", map[string]string{"system": "orbitatest", "email": "a@b.co", "full_name": "Ana", "password": "correct-horse"})
	rec := call(h, "POST", "/v1/login", "", map[string]string{"system": "other", "email": "a@b.co", "password": "correct-horse"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("got %d %s, want 403 no_access", rec.Code, rec.Body)
	}
}
