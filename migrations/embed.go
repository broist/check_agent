package migrations

import "embed"

// Files contains the ordered, immutable SQL migrations.
//
//go:embed *.sql
var Files embed.FS
