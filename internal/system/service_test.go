package system

import (
	"context"
	"errors"
	"sort"
	"testing"
)

type fakeRepo struct{ byCode map[string]System }

func newFakeRepo() *fakeRepo { return &fakeRepo{byCode: map[string]System{}} }

func (f *fakeRepo) Create(_ context.Context, s System) (System, error) {
	if _, ok := f.byCode[s.Code]; ok {
		return System{}, ErrCodeTaken
	}
	s.ID = "id-" + s.Code
	f.byCode[s.Code] = s
	return s, nil
}

func (f *fakeRepo) List(context.Context) ([]System, error) {
	var out []System
	for _, s := range f.byCode {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Code < out[j].Code })
	return out, nil
}

func (f *fakeRepo) GetByCode(_ context.Context, code string) (System, error) {
	s, ok := f.byCode[code]
	if !ok {
		return System{}, ErrSystemNotFound
	}
	return s, nil
}

func (f *fakeRepo) GetByID(_ context.Context, id string) (System, error) {
	for _, s := range f.byCode {
		if s.ID == id {
			return s, nil
		}
	}
	return System{}, ErrSystemNotFound
}

func (f *fakeRepo) Delete(_ context.Context, id string) error {
	for code, s := range f.byCode {
		if s.ID == id {
			delete(f.byCode, code)
			return nil
		}
	}
	return ErrSystemNotFound
}

func (f *fakeRepo) UpdateSession(_ context.Context, id, mode string, minutes int) (System, error) {
	for code, s := range f.byCode {
		if s.ID == id {
			s.SessionMode, s.SessionMinutes = mode, minutes
			f.byCode[code] = s
			return s, nil
		}
	}
	return System{}, ErrSystemNotFound
}

func TestCreate(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name string
		in   CreateInput
		want error
	}{
		{"ok", CreateInput{Code: "olympus", Name: "Olympus"}, nil},
		{"code with dash", CreateInput{Code: "atm-console", Name: "Console"}, nil},
		{"uppercase code", CreateInput{Code: "Olympus", Name: "Olympus"}, ErrInvalidCode},
		{"code with space", CreateInput{Code: "my sys", Name: "X"}, ErrInvalidCode},
		{"code starting with digit", CreateInput{Code: "1sys", Name: "X"}, ErrInvalidCode},
		{"empty name", CreateInput{Code: "nova", Name: " "}, ErrInvalidName},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := NewService(newFakeRepo()).Create(ctx, tt.in)
			if !errors.Is(err, tt.want) {
				t.Fatalf("got %v, want %v", err, tt.want)
			}
			if err == nil && s.Status != StatusActive {
				t.Fatalf("status %q", s.Status)
			}
		})
	}

	t.Run("duplicate code", func(t *testing.T) {
		svc := NewService(newFakeRepo())
		in := CreateInput{Code: "pulso", Name: "Pulso"}
		_, _ = svc.Create(ctx, in)
		if _, err := svc.Create(ctx, in); !errors.Is(err, ErrCodeTaken) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestList(t *testing.T) {
	ctx := context.Background()
	svc := NewService(newFakeRepo())
	_, _ = svc.Create(ctx, CreateInput{Code: "pulso", Name: "Pulso"})
	_, _ = svc.Create(ctx, CreateInput{Code: "nova", Name: "Nova"})
	got, err := svc.List(ctx)
	if err != nil || len(got) != 2 || got[0].Code != "nova" {
		t.Fatalf("got %+v err %v", got, err)
	}
}

func TestDelete(t *testing.T) {
	ctx := context.Background()
	const id = "11111111-1111-1111-1111-111111111111"
	seed := func() *Service {
		repo := newFakeRepo()
		repo.byCode["olympus"] = System{ID: id, Code: "olympus", Name: "Olympus"}
		return NewService(repo)
	}

	tests := []struct {
		name    string
		id      string
		confirm string
		want    error
	}{
		{"confirmed", id, "olympus", nil},
		{"wrong code", id, "pulso", ErrCodeMismatch},
		{"empty code", id, "", ErrCodeMismatch},
		{"different case", id, "Olympus", ErrCodeMismatch},
		{"unknown system", "22222222-2222-2222-2222-222222222222", "olympus", ErrSystemNotFound},
		{"not a uuid", "olympus", "olympus", ErrInvalidID},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := seed()
			if err := svc.Delete(ctx, tt.id, tt.confirm); !errors.Is(err, tt.want) {
				t.Fatalf("got %v, want %v", err, tt.want)
			}
			list, _ := svc.List(ctx)
			if wantLeft := tt.want != nil; wantLeft != (len(list) == 1) {
				t.Fatalf("systems left: %d", len(list))
			}
		})
	}
}

func TestSessionPolicy(t *testing.T) {
	ctx := context.Background()
	const id = "11111111-1111-1111-1111-111111111111"

	t.Run("a new system is persistent by default", func(t *testing.T) {
		s, err := NewService(newFakeRepo()).Create(ctx, CreateInput{Code: "olympus", Name: "Olympus"})
		if err != nil || s.SessionMode != SessionPersistent || s.SessionMinutes != 0 {
			t.Fatalf("got %+v err %v", s, err)
		}
	})

	tests := []struct {
		name    string
		mode    string
		minutes int
		want    error
		stored  int
	}{
		{"temporary", SessionTemporary, 30, nil, 30},
		{"lower bound", SessionTemporary, MinSessionMinutes, nil, MinSessionMinutes},
		{"upper bound", SessionTemporary, MaxSessionMinutes, nil, MaxSessionMinutes},
		{"too short", SessionTemporary, MinSessionMinutes - 1, ErrInvalidSessionMinutes, 0},
		{"too long", SessionTemporary, MaxSessionMinutes + 1, ErrInvalidSessionMinutes, 0},
		{"temporary without minutes", SessionTemporary, 0, ErrInvalidSessionMinutes, 0},
		{"persistent ignores minutes", SessionPersistent, 99, nil, 0},
		{"unknown mode", "forever", 30, ErrInvalidSessionMode, 0},
	}
	for _, tt := range tests {
		t.Run("create "+tt.name, func(t *testing.T) {
			s, err := NewService(newFakeRepo()).Create(ctx, CreateInput{Code: "olympus", Name: "Olympus", SessionMode: tt.mode, SessionMinutes: tt.minutes})
			if !errors.Is(err, tt.want) || (err == nil && s.SessionMinutes != tt.stored) {
				t.Fatalf("got %+v err %v", s, err)
			}
		})
		t.Run("update "+tt.name, func(t *testing.T) {
			repo := newFakeRepo()
			repo.byCode["olympus"] = System{ID: id, Code: "olympus", Name: "Olympus", SessionMode: SessionPersistent}
			s, err := NewService(repo).UpdateSession(ctx, id, tt.mode, tt.minutes)
			if !errors.Is(err, tt.want) || (err == nil && (s.SessionMode != tt.mode || s.SessionMinutes != tt.stored)) {
				t.Fatalf("got %+v err %v", s, err)
			}
		})
	}

	t.Run("update needs an explicit mode", func(t *testing.T) {
		if _, err := NewService(newFakeRepo()).UpdateSession(ctx, id, "", 0); !errors.Is(err, ErrInvalidSessionMode) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("update validates the id", func(t *testing.T) {
		if _, err := NewService(newFakeRepo()).UpdateSession(ctx, "x", SessionPersistent, 0); !errors.Is(err, ErrInvalidID) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("update of an unknown system", func(t *testing.T) {
		if _, err := NewService(newFakeRepo()).UpdateSession(ctx, id, SessionPersistent, 0); !errors.Is(err, ErrSystemNotFound) {
			t.Fatalf("got %v", err)
		}
	})
}
