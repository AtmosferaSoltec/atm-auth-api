package role

import (
	"context"
	"errors"
	"testing"
)

type fakeRepo struct {
	roles []Role
	err   error
}

func (f *fakeRepo) List(context.Context, string) ([]Role, error) { return f.roles, f.err }

func TestList(t *testing.T) {
	ctx := context.Background()
	if _, err := NewService(&fakeRepo{}).List(ctx, "nope"); !errors.Is(err, ErrInvalidID) {
		t.Fatalf("got %v", err)
	}
	want := []Role{{Name: "admin"}}
	got, err := NewService(&fakeRepo{roles: want}).List(ctx, "11111111-1111-1111-1111-111111111111")
	if err != nil || len(got) != 1 || got[0].Name != "admin" {
		t.Fatalf("got %+v err %v", got, err)
	}
	boom := errors.New("boom")
	if _, err := NewService(&fakeRepo{err: boom}).List(ctx, "11111111-1111-1111-1111-111111111111"); !errors.Is(err, boom) {
		t.Fatalf("got %v", err)
	}
}
