package client

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type fakeRepo struct {
	created []string
	deleted string
	err     error
}

func (f *fakeRepo) Create(_ context.Context, name string) (Client, error) {
	f.created = append(f.created, name)
	return Client{ID: "00000000-0000-0000-0000-000000000001", Name: name}, f.err
}
func (f *fakeRepo) GetByID(context.Context, string) (Client, error) {
	return Client{ID: "00000000-0000-0000-0000-000000000001", Name: "Percy"}, f.err
}
func (f *fakeRepo) Update(context.Context, string, string) error { return f.err }
func (f *fakeRepo) List(context.Context) ([]Client, error)       { return nil, f.err }
func (f *fakeRepo) Delete(_ context.Context, id string) error {
	f.deleted = id
	return f.err
}

const someID = "00000000-0000-0000-0000-000000000001"

func TestCreateNormalizesAndValidatesName(t *testing.T) {
	repo := &fakeRepo{}
	svc := NewService(repo)

	if _, err := svc.Create(context.Background(), "  Percy   Tasayco "); err != nil {
		t.Fatal(err)
	}
	if len(repo.created) != 1 || repo.created[0] != "Percy Tasayco" {
		t.Fatalf("got %v", repo.created)
	}
	if _, err := svc.Create(context.Background(), "   "); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("got %v", err)
	}
	if _, err := svc.Create(context.Background(), strings.Repeat("a", 201)); !errors.Is(err, ErrNameTooLong) {
		t.Fatalf("got %v", err)
	}
	if len(repo.created) != 1 {
		t.Fatalf("an invalid name reached the repository: %v", repo.created)
	}
}

func TestRenameAndDeleteRejectABadID(t *testing.T) {
	svc := NewService(&fakeRepo{})

	if _, err := svc.Rename(context.Background(), "nope", "Percy"); !errors.Is(err, ErrInvalidID) {
		t.Fatalf("got %v", err)
	}
	if _, err := svc.Rename(context.Background(), someID, " "); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("got %v", err)
	}
	if err := svc.Delete(context.Background(), "nope"); !errors.Is(err, ErrInvalidID) {
		t.Fatalf("got %v", err)
	}
	if _, err := svc.Get(context.Background(), "nope"); !errors.Is(err, ErrInvalidID) {
		t.Fatalf("got %v", err)
	}
}

func TestDeleteSurfacesRepositoryErrors(t *testing.T) {
	svc := NewService(&fakeRepo{err: ErrClientHasTenants})

	if err := svc.Delete(context.Background(), someID); !errors.Is(err, ErrClientHasTenants) {
		t.Fatalf("got %v", err)
	}
}
