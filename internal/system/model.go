package system

import (
	"regexp"
	"strings"
	"time"
)

const (
	StatusActive   = "active"
	StatusDisabled = "disabled"
)

var codePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]*$`)

type System struct {
	ID        string
	Code      string
	Name      string
	Status    string
	CreatedAt time.Time
	UpdatedAt time.Time
}

func validCode(code string) bool { return codePattern.MatchString(code) }

func normalizeName(name string) string { return strings.Join(strings.Fields(name), " ") }
