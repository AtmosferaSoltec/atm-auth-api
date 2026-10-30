package system

import (
	"context"
	"errors"
	"sort"
	"testing"
)

type fakeRepo struct{ byCode map[string]System }

func newFakeRepo() *fakeRepo { return &fakeRepo{byCode: map[string]System{}} }

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

func (f *fakeRepo) UpdateSession(_ context.Context, id, mode string) (System, error) {
	for code, s := range f.byCode {
		if s.ID == id {
			s.SessionMode = mode
			f.byCode[code] = s
			return s, nil
		}
	}
	return System{}, ErrSystemNotFound
}

func TestList(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	repo.byCode["pulso"] = System{ID: "id-pulso", Code: "pulso", Name: "Pulso"}
	repo.byCode["nova"] = System{ID: "id-nova", Code: "nova", Name: "Nova"}
	got, err := NewService(repo).List(ctx)
	if err != nil || len(got) != 2 || got[0].Code != "nova" {
		t.Fatalf("got %+v err %v", got, err)
	}
}

func TestSessionPolicy(t *testing.T) {
	ctx := context.Background()
	const id = "11111111-1111-1111-1111-111111111111"

	tests := []struct {
		name string
		mode string
		want error
	}{
		{"persistent", SessionPersistent, nil},
		{"temporary", SessionTemporary, nil},
		{"unknown mode", "forever", ErrInvalidSessionMode},
		{"minutes are not a mode", "30", ErrInvalidSessionMode},
	}
	for _, tt := range tests {
		t.Run("update "+tt.name, func(t *testing.T) {
			repo := newFakeRepo()
			repo.byCode["olympus"] = System{ID: id, Code: "olympus", Name: "Olympus", SessionMode: SessionPersistent}
			s, err := NewService(repo).UpdateSession(ctx, id, tt.mode)
			if !errors.Is(err, tt.want) || (err == nil && s.SessionMode != tt.mode) {
				t.Fatalf("got %+v err %v", s, err)
			}
		})
	}

	t.Run("update needs an explicit mode", func(t *testing.T) {
		if _, err := NewService(newFakeRepo()).UpdateSession(ctx, id, ""); !errors.Is(err, ErrInvalidSessionMode) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("update validates the id", func(t *testing.T) {
		if _, err := NewService(newFakeRepo()).UpdateSession(ctx, "x", SessionPersistent); !errors.Is(err, ErrInvalidID) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("update of an unknown system", func(t *testing.T) {
		if _, err := NewService(newFakeRepo()).UpdateSession(ctx, id, SessionPersistent); !errors.Is(err, ErrSystemNotFound) {
			t.Fatalf("got %v", err)
		}
	})
}
