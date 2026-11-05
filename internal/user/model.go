package user

import (
	"regexp"
	"strings"
	"time"
)

const (
	StatusActive   = "active"
	StatusDisabled = "disabled"

	MinPasswordLength = 8
)

// ValidStatus reports whether s is a known account status.
func ValidStatus(s string) bool { return s == StatusActive || s == StatusDisabled }

// ValidNewPassword reports whether password is acceptable as a new password for the account with this
// document number (the initial password).
func ValidNewPassword(password, documentNumber string) bool {
	return len(password) >= MinPasswordLength && password != documentNumber
}

// Identity document types. A person signs in with the number only: numbers are unique across types.
const (
	// DocumentDNI is the Peruvian national ID: 8 digits.
	DocumentDNI = "dni"
	// DocumentCE is the Peruvian foreign resident card (carné de extranjería): 9 to 12 digits.
	DocumentCE = "ce"
	// DocumentPassport is a passport or any other foreign ID: 6 to 12 letters or digits.
	DocumentPassport = "passport"
)

var documentPatterns = map[string]*regexp.Regexp{
	DocumentDNI:      regexp.MustCompile(`^[0-9]{8}$`),
	DocumentCE:       regexp.MustCompile(`^[0-9]{9,12}$`),
	DocumentPassport: regexp.MustCompile(`^[A-Z0-9]{6,12}$`),
}

// DocumentRules explains the accepted documents, for error messages.
const DocumentRules = "Invalid document: a DNI has 8 digits, a CE 9 to 12 digits, and a passport 6 to 12 letters or digits."

// NormalizeDocumentNumber is how a typed number is stored and looked up: without spaces or dashes, in upper case.
func NormalizeDocumentNumber(number string) string {
	return strings.ToUpper(strings.NewReplacer(" ", "", "-", "", ".", "").Replace(strings.TrimSpace(number)))
}

// NormalizeDocument checks a document against its type and returns the type and number as stored.
// An empty type is a DNI, the only type older clients send.
func NormalizeDocument(documentType, number string) (string, string, bool) {
	documentType = strings.ToLower(strings.TrimSpace(documentType))
	if documentType == "" {
		documentType = DocumentDNI
	}
	pattern, known := documentPatterns[documentType]
	number = NormalizeDocumentNumber(number)
	if !known || !pattern.MatchString(number) {
		return "", "", false
	}
	return documentType, number, true
}

type User struct {
	ID string
	// DocumentType and DocumentNumber are empty for people who sign in with an email only.
	DocumentType   string
	DocumentNumber string
	// Email is empty for people who only have a document. It is stored trimmed and in lower case.
	Email         string
	EmailVerified bool
	FullName      string
	// PasswordHash is empty for accounts that have no password yet (created with Google).
	PasswordHash string
	Status       string
	// MustChangePassword is set while the account still has its initial password (the document number).
	MustChangePassword bool
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

var emailPattern = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)

// NormalizeEmail trims and lower-cases an email and reports whether it has a valid form.
func NormalizeEmail(email string) (string, bool) {
	email = strings.ToLower(strings.TrimSpace(email))
	if len(email) < 3 || len(email) > 254 || !emailPattern.MatchString(email) {
		return "", false
	}
	return email, true
}

func normalizeName(name string) string { return strings.Join(strings.Fields(name), " ") }
