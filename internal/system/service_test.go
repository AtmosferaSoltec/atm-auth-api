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
