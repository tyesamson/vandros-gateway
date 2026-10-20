package web

import "embed"

// Files holds the portal templates and stylesheet.
//
//go:embed templates static
var Files embed.FS
