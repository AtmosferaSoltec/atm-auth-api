package platform

import (
	"strings"
	"testing"
)

var testParams = Argon2Params{MemoryKiB: 8, Time: 1, Threads: 1}

func TestPasswordHasher(t *testing.T) {
	h := NewPasswordHasher(testParams)

	hash, err := h.Hash("s3cret")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$m=8,t=1,p=1$") {
		t.Fatalf("unexpected format: %s", hash)
	}

	if ok, err := h.Verify("s3cret", hash); err != nil || !ok {
		t.Fatalf("expected match, got ok=%v err=%v", ok, err)
	}
	if ok, err := h.Verify("wrong", hash); err != nil || ok {
		t.Fatalf("expected mismatch, got ok=%v err=%v", ok, err)
	}

	other, _ := h.Hash("s3cret")
	if other == hash {
		t.Fatal("hashes of the same password must differ (random salt)")
	}
}

func TestPasswordHasherVerifyUsesStoredParams(t *testing.T) {
	hash, _ := NewPasswordHasher(testParams).Hash("pw")
	strong := NewPasswordHasher(Argon2Params{MemoryKiB: 64, Time: 2, Threads: 2})
	if ok, err := strong.Verify("pw", hash); err != nil || !ok {
		t.Fatalf("expected match with stored params, got ok=%v err=%v", ok, err)
	}
}

func TestPasswordHasherVerifyRejectsBadFormat(t *testing.T) {
	h := NewPasswordHasher(testParams)
	for _, bad := range []string{"", "plain", "$bcrypt$x$y$z$w", "$argon2id$v=19$m=8,t=1,p=1$!!$!!"} {
		if _, err := h.Verify("pw", bad); err == nil {
			t.Fatalf("expected error for %q", bad)
		}
	}
}
