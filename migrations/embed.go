package migrations

import "embed"

// Files holds the numbered SQL migrations.
//
//go:embed *.sql
var Files embed.FS
