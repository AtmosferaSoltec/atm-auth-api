package tenant

import (
	"regexp"
	"strings"
	"time"
)

const (
	StatusActive   = "active"
	StatusDisabled = "disabled"
)

var rucPattern = regexp.MustCompile(`^[0-9]{11}$`)

// SystemRef identifies a system a tenant has contracted.
type SystemRef struct {
	ID   string
	Code string
	Name string
}

// Tenant is a customer company.
type Tenant struct {
	ID        string
	RUC       string
	LegalName string
	TradeName string
	Status    string
	CreatedAt time.Time
	UpdatedAt time.Time
	// Systems are the systems enabled for the tenant, ordered by code. Filled by GetByID and List.
	Systems []SystemRef
}

// DisplayName is what user interfaces show: the trade name, or the legal name when there is none.
func (t Tenant) DisplayName() string {
	if t.TradeName != "" {
		return t.TradeName
	}
	return t.LegalName
}

func validRUC(ruc string) bool { return rucPattern.MatchString(ruc) }

func normalizeName(name string) string { return strings.Join(strings.Fields(name), " ") }
