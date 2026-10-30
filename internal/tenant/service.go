package tenant

import (
	"context"
	"fmt"
	"net/mail"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/AtmosferaSoltec/atm-auth-api/internal/platform"
)

type Service struct {
	repo Repository
}

func NewService(repo Repository) *Service {
	return &Service{repo: repo}
}

type CreateInput struct {
	RUC       string
	LegalName string
	TradeName string
	// ClientID is optional: without it the company gets a new client named after it.
	ClientID string
}

func (s *Service) Create(ctx context.Context, in CreateInput) (Tenant, error) {
	if !validRUC(in.RUC) {
		return Tenant{}, ErrInvalidRUC
	}
	legal := normalizeName(in.LegalName)
	if legal == "" {
		return Tenant{}, ErrInvalidLegalName
	}
	if in.ClientID != "" && !platform.IsUUID(in.ClientID) {
		return Tenant{}, ErrInvalidID
	}
	created, err := s.repo.Create(ctx, Tenant{
		RUC: in.RUC, LegalName: legal, TradeName: normalizeName(in.TradeName), Status: StatusActive, ClientID: in.ClientID,
	})
	if err != nil {
		return Tenant{}, fmt.Errorf("create tenant: %w", err)
	}
	return created, nil
}

// UpdateInput is the whole editable profile: a field left empty is cleared. The RUC never changes.
type UpdateInput struct {
	LegalName, TradeName                    string
	Address, Department, Province, District string
	Ubigeo, Phone, Email, LogoFileID        string
}

const (
	maxAddress = 255
	maxPlace   = 60
	maxPhone   = 20
	maxEmail   = 160
)

func validPhone(phone string) bool {
	for _, r := range phone {
		if !unicode.IsDigit(r) && !strings.ContainsRune("+-() .", r) {
			return false
		}
	}
	return true
}

// Update replaces the profile of a tenant and returns it with its systems.
func (s *Service) Update(ctx context.Context, id string, in UpdateInput) (Tenant, error) {
	if !platform.IsUUID(id) {
		return Tenant{}, ErrInvalidID
	}
	t := Tenant{
		ID: id, LegalName: normalizeName(in.LegalName), TradeName: normalizeName(in.TradeName),
		Address: normalizeName(in.Address), Department: normalizeName(in.Department), Province: normalizeName(in.Province),
		District: normalizeName(in.District), Ubigeo: strings.TrimSpace(in.Ubigeo), Phone: strings.TrimSpace(in.Phone),
		Email: strings.TrimSpace(in.Email), LogoFileID: strings.TrimSpace(in.LogoFileID),
	}
	if t.LegalName == "" {
		return Tenant{}, ErrInvalidLegalName
	}
	for _, f := range []struct {
		value string
		max   int
	}{{t.LegalName, 200}, {t.TradeName, 200}, {t.Address, maxAddress}, {t.Department, maxPlace}, {t.Province, maxPlace}, {t.District, maxPlace}} {
		if utf8.RuneCountInString(f.value) > f.max {
			return Tenant{}, ErrFieldTooLong
		}
	}
	if t.Ubigeo != "" && !validUbigeo(t.Ubigeo) {
		return Tenant{}, ErrInvalidUbigeo
	}
	if t.Phone != "" && (len(t.Phone) > maxPhone || !validPhone(t.Phone)) {
		return Tenant{}, ErrInvalidPhone
	}
	if t.Email != "" {
		parsed, err := mail.ParseAddress(t.Email)
		if len(t.Email) > maxEmail || err != nil || parsed.Address != t.Email {
			return Tenant{}, ErrInvalidEmail
		}
	}
	if t.LogoFileID != "" && !platform.IsUUID(t.LogoFileID) {
		return Tenant{}, ErrInvalidLogo
	}
	if err := s.repo.Update(ctx, t); err != nil {
		return Tenant{}, fmt.Errorf("update tenant: %w", err)
	}
	return s.Get(ctx, id)
}

func (s *Service) Get(ctx context.Context, id string) (Tenant, error) {
	if !platform.IsUUID(id) {
		return Tenant{}, ErrInvalidID
	}
	t, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return Tenant{}, fmt.Errorf("get tenant: %w", err)
	}
	return t, nil
}

func (s *Service) List(ctx context.Context) ([]Tenant, error) {
	ts, err := s.repo.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list tenants: %w", err)
	}
	return ts, nil
}

// ListForSystem returns the tenants a system serves: the ones that have it enabled and are active.
func (s *Service) ListForSystem(ctx context.Context, systemCode string) ([]Tenant, error) {
	if systemCode == "" {
		return nil, ErrSystemNotFound
	}
	ts, err := s.repo.ListForSystem(ctx, systemCode)
	if err != nil {
		return nil, fmt.Errorf("list tenants of system: %w", err)
	}
	return ts, nil
}

// SetClient moves the company to another client and returns it.
func (s *Service) SetClient(ctx context.Context, tenantID, clientID string) (Tenant, error) {
	if !platform.IsUUID(tenantID) || !platform.IsUUID(clientID) {
		return Tenant{}, ErrInvalidID
	}
	if err := s.repo.SetClient(ctx, tenantID, clientID); err != nil {
		return Tenant{}, fmt.Errorf("set tenant client: %w", err)
	}
	return s.Get(ctx, tenantID)
}

// EnableSystem records that the tenant has contracted the system.
func (s *Service) EnableSystem(ctx context.Context, tenantID, systemID string) error {
	if !platform.IsUUID(tenantID) || !platform.IsUUID(systemID) {
		return ErrInvalidID
	}
	if err := s.repo.EnableSystem(ctx, tenantID, systemID); err != nil {
		return fmt.Errorf("enable system: %w", err)
	}
	return nil
}

// DisableSystem removes the system from the tenant. Every access its users had in that system is removed with it.
func (s *Service) DisableSystem(ctx context.Context, tenantID, systemID string) error {
	if !platform.IsUUID(tenantID) || !platform.IsUUID(systemID) {
		return ErrInvalidID
	}
	if err := s.repo.DisableSystem(ctx, tenantID, systemID); err != nil {
		return fmt.Errorf("disable system: %w", err)
	}
	return nil
}
