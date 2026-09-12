package main

import "embed"

// embeddedUI contains the production React build output.
// ui/dist/.gitkeep keeps the directory present in a fresh clone so the embed
// directive compiles; run `make build-ui` to populate it before `make build-go`.
//
//go:embed all:ui/dist
var embeddedUI embed.FS
