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

var (
	rucPattern    = regexp.MustCompile(`^[0-9]{11}$`)
	ubigeoPattern = regexp.MustCompile(`^[0-9]{6}$`)
)

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
	// Profile, all optional ("" means not set). Edited from the console; systems read it from here.
	Address    string
	Department string
	Province   string
	District   string
	// Ubigeo is the 6-digit INEI code of the district, which SUNAT requires on dispatch guides.
	Ubigeo string
	Phone  string
	Email  string
	// LogoFileID is the id of the logo in atm-storage-api, or "" when there is none.
	LogoFileID string
	// ClientID is the owner of the company (see the client package); ClientName is its name.
	ClientID   string
	ClientName string
	Status     string
	CreatedAt  time.Time
	UpdatedAt  time.Time
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

func validUbigeo(ubigeo string) bool { return ubigeoPattern.MatchString(ubigeo) }

func normalizeName(name string) string { return strings.Join(strings.Fields(name), " ") }
