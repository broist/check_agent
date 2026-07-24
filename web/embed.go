package web

import "embed"

// Files contains the server-rendered dashboard and static assets.
//
//go:embed *.html static/*
var Files embed.FS
