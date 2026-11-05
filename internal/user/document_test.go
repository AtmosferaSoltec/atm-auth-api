package user

import "testing"

func TestNormalizeDocument(t *testing.T) {
	for _, tc := range []struct {
		documentType, number string
		wantType, wantNumber string
		ok                   bool
	}{
		{"", "74455518", "dni", "74455518", true},
		{"DNI", " 74455518 ", "dni", "74455518", true},
		{"dni", "7445551", "", "", false},
		{"dni", "7445551A", "", "", false},
		{"ce", "001234567", "ce", "001234567", true},
		{"ce", "123456789012", "ce", "123456789012", true},
		{"ce", "12345678", "", "", false},
		{"ce", "1234567890123", "", "", false},
		{"ce", "A01234567", "", "", false},
		{"passport", "ab-123 456", "passport", "AB123456", true},
		{"passport", "123456", "passport", "123456", true},
		{"passport", "12345", "", "", false},
		{"passport", "ABCDEFGHIJKLM", "", "", false},
		{"passport", "AB12345Ñ", "", "", false},
		{"rut", "123456789", "", "", false},
	} {
		gotType, gotNumber, ok := NormalizeDocument(tc.documentType, tc.number)
		if gotType != tc.wantType || gotNumber != tc.wantNumber || ok != tc.ok {
			t.Errorf("NormalizeDocument(%q, %q) = %q, %q, %v", tc.documentType, tc.number, gotType, gotNumber, ok)
		}
	}
}

func TestValidNewPasswordRefusesTheDocument(t *testing.T) {
	if ValidNewPassword("AB123456", "AB123456") || !ValidNewPassword("otra-clave", "AB123456") {
		t.Fatal("the initial password (the document number) must not be accepted as the new one")
	}
}
