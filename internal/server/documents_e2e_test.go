package server_test

import (
	"bytes"
	"context"
	"net/http"
	"testing"

	"github.com/AtmosferaSoltec/atm-auth-api/internal/access"
	"github.com/AtmosferaSoltec/atm-auth-api/internal/platform"
	"github.com/AtmosferaSoltec/atm-auth-api/internal/tenant"
	"github.com/AtmosferaSoltec/atm-auth-api/internal/user"
)

// A person without a Peruvian DNI (a passport or a foreign resident card) is created, signs in with the number
// alone, and reaches the systems with the document in the token. Clients that still send `dni` keep working.
func TestForeignDocuments(t *testing.T) {
	ctx := context.Background()
	e := newE2EFull(t)
	h := e.handler
	adm := adminToken(t, h)

	pulso := e.seedSystem(t, "pulso", "Pulso")
	gym, err := e.tenants.Create(ctx, tenant.CreateInput{RUC: "20333333333", LegalName: "Gym La Paz"})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.tenants.EnableSystem(ctx, gym.ID, pulso.ID); err != nil {
		t.Fatal(err)
	}
	platform.SeedRoles(t, e.pool, pulso.ID, "owner", "receptionist")

	// The superadmin creates the account with a passport. Spaces, dashes and lower case are cleaned.
	rec := call(h, "POST", "/v1/admin/users", adm, map[string]string{
		"document_type": "passport", "document_number": " ab-123456 ", "full_name": "Dueño Boliviano",
	})
	var created struct {
		ID                 string `json:"id"`
		DocumentType       string `json:"document_type"`
		DocumentNumber     string `json:"document_number"`
		DNI                string `json:"dni"`
		MustChangePassword bool   `json:"must_change_password"`
	}
	decode(t, rec, &created)
	if rec.Code != http.StatusCreated || created.DocumentType != "passport" || created.DocumentNumber != "AB123456" ||
		created.DNI != "AB123456" || !created.MustChangePassword {
		t.Fatalf("create with passport: %d %s", rec.Code, rec.Body)
	}

	for name, body := range map[string]map[string]string{
		"ce too short":      {"document_type": "ce", "document_number": "12345678", "full_name": "X"},
		"ce with letters":   {"document_type": "ce", "document_number": "A123456789", "full_name": "X"},
		"passport too long": {"document_type": "passport", "document_number": "ABCDEFGHIJ123", "full_name": "X"},
		"unknown type":      {"document_type": "rut", "document_number": "123456789", "full_name": "X"},
		"legacy short dni":  {"dni": "1234567", "full_name": "X"},
	} {
		if rec := call(h, "POST", "/v1/admin/users", adm, body); rec.Code != http.StatusBadRequest ||
			!bytes.Contains(rec.Body.Bytes(), []byte("invalid_document")) {
			t.Fatalf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
	if rec := call(h, "POST", "/v1/admin/users", adm, map[string]string{"dni": "44444444", "document_number": "44444444", "full_name": "X"}); rec.Code != http.StatusBadRequest ||
		!bytes.Contains(rec.Body.Bytes(), []byte("invalid_request")) {
		t.Fatalf("dni and document_number at once: %d %s", rec.Code, rec.Body)
	}
	// The number is unique whatever its type: it is all a person types to sign in.
	if rec := call(h, "POST", "/v1/admin/users", adm, map[string]string{"document_type": "passport", "document_number": "AB123456", "full_name": "Dup"}); rec.Code != http.StatusConflict ||
		!bytes.Contains(rec.Body.Bytes(), []byte("document_taken")) {
		t.Fatalf("duplicate document: %d %s", rec.Code, rec.Body)
	}
	// Older clients still send `dni`, and get a DNI.
	if rec := call(h, "POST", "/v1/admin/users", adm, map[string]string{"dni": "44444444", "full_name": "Con DNI"}); rec.Code != http.StatusCreated ||
		!bytes.Contains(rec.Body.Bytes(), []byte(`"document_type":"dni"`)) || !bytes.Contains(rec.Body.Bytes(), []byte(`"dni":"44444444"`)) {
		t.Fatalf("legacy dni create: %d %s", rec.Code, rec.Body)
	}

	if _, err := e.access.Assign(ctx, access.AssignInput{UserID: created.ID, SystemID: pulso.ID, TenantID: gym.ID, Role: "owner", ManageUsers: true}); err != nil {
		t.Fatal(err)
	}

	// First login: the initial password is the number, and it must be changed.
	if rec := call(h, "POST", "/v1/login", "", map[string]string{"document": "ab123456", "password": "AB123456", "system": "pulso"}); rec.Code != http.StatusForbidden ||
		!bytes.Contains(rec.Body.Bytes(), []byte("password_change_required")) {
		t.Fatalf("first login: %d %s", rec.Code, rec.Body)
	}
	change := func(next string) int {
		return call(h, "POST", "/v1/password/change", "", map[string]string{"document": "AB123456", "current_password": "AB123456", "new_password": next}).Code
	}
	if code := change("AB123456"); code != http.StatusBadRequest {
		t.Fatalf("the document as new password: %d", code)
	}
	if code := change("clave-del-dueno"); code != http.StatusNoContent {
		t.Fatalf("change password: %d", code)
	}

	if rec := call(h, "POST", "/v1/login", "", map[string]string{"document": "AB123456", "dni": "AB123456", "password": "clave-del-dueno", "system": "pulso"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("document and dni at once: %d", rec.Code)
	}
	rec = call(h, "POST", "/v1/login", "", map[string]string{"document": "ab 123456", "password": "clave-del-dueno", "system": "pulso"})
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	decode(t, rec, &tok)
	if c := claimsOf(t, tok.AccessToken); rec.Code != http.StatusOK || c.DocumentType != "passport" || c.DocumentNumber != "AB123456" ||
		c.DNI != "AB123456" || c.Tenant != gym.ID || c.AppRole != "owner" {
		t.Fatalf("login with passport: %d %+v", rec.Code, c)
	}
	// The older `dni` field takes any document number too.
	if rec := call(h, "POST", "/v1/login", "", map[string]string{"dni": "AB123456", "password": "clave-del-dueno", "system": "pulso"}); rec.Code != http.StatusOK {
		t.Fatalf("legacy dni field with a passport: %d %s", rec.Code, rec.Body)
	}

	// The owner adds a receptionist with a foreign resident card.
	rec = call(h, "POST", "/v1/tenant/members", tok.AccessToken, map[string]string{
		"document_type": "ce", "document_number": "001234567", "full_name": "Recepcionista Venezolana", "role": "receptionist",
	})
	if rec.Code != http.StatusCreated || !bytes.Contains(rec.Body.Bytes(), []byte(`"document_type":"ce"`)) ||
		!bytes.Contains(rec.Body.Bytes(), []byte(`"document_number":"001234567"`)) {
		t.Fatalf("add member with ce: %d %s", rec.Code, rec.Body)
	}
	if rec := call(h, "POST", "/v1/tenant/members", tok.AccessToken, map[string]string{
		"document_type": "ce", "document_number": "1234", "full_name": "X", "role": "receptionist",
	}); rec.Code != http.StatusBadRequest || !bytes.Contains(rec.Body.Bytes(), []byte("invalid_document")) {
		t.Fatalf("add member with a bad ce: %d %s", rec.Code, rec.Body)
	}
	if rec := call(h, "POST", "/v1/login", "", map[string]string{"document": "001234567", "password": "001234567", "system": "pulso"}); rec.Code != http.StatusForbidden ||
		!bytes.Contains(rec.Body.Bytes(), []byte("password_change_required")) {
		t.Fatalf("first login with ce: %d %s", rec.Code, rec.Body)
	}

	// The console sees each person's document.
	rec = call(h, "GET", "/v1/admin/systems/"+pulso.ID+"/access", adm, nil)
	if rec.Code != http.StatusOK || !bytes.Contains(rec.Body.Bytes(), []byte(`"user_document_type":"passport"`)) ||
		!bytes.Contains(rec.Body.Bytes(), []byte(`"user_document_number":"AB123456"`)) {
		t.Fatalf("system access: %d %s", rec.Code, rec.Body)
	}

	// The superadmin's reset goes back to the document number, whatever its type.
	if rec := call(h, "POST", "/v1/admin/users/"+created.ID+"/reset-password", adm, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("reset: %d %s", rec.Code, rec.Body)
	}
	if rec := call(h, "POST", "/v1/login", "", map[string]string{"document": "AB123456", "password": "AB123456", "system": "pulso"}); rec.Code != http.StatusForbidden {
		t.Fatalf("after reset: %d %s", rec.Code, rec.Body)
	}
}

// A row written by the version that knows nothing of document types is a DNI, and the database still refuses
// numbers that do not fit their type.
func TestDocumentConstraints(t *testing.T) {
	ctx := context.Background()
	e := newE2EFull(t)

	if _, err := e.pool.Exec(ctx, `INSERT INTO users (dni, full_name, password_hash) VALUES ('12345678', 'Old Version', 'h')`); err != nil {
		t.Fatalf("an insert without type must still work: %v", err)
	}
	u, err := user.NewPostgresRepository(e.pool).GetByDocument(ctx, "12345678")
	if err != nil || u.DocumentType != "dni" {
		t.Fatalf("an untyped row is a DNI: %+v %v", u, err)
	}
	for name, row := range map[string][2]string{
		"untyped 9 digits":    {"", "123456789"},
		"dni with letters":    {"dni", "1234567A"},
		"ce of 8 digits":      {"ce", "12345678"},
		"lower-case passport": {"passport", "ab123456"},
		"unknown type":        {"rut", "123456789"},
	} {
		if _, err := e.pool.Exec(ctx, `INSERT INTO users (document_type, dni, full_name, password_hash) VALUES (NULLIF($1, ''), $2, 'X', 'h')`,
			row[0], row[1]); err == nil {
			t.Fatalf("%s must be refused", name)
		}
	}
	if _, err := e.pool.Exec(ctx, `INSERT INTO users (document_type, email, full_name) VALUES ('ce', 'x@example.com', 'X')`); err == nil {
		t.Fatal("a type without a number must be refused")
	}
}
