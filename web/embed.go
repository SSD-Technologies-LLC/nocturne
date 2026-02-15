package web

import "embed"

//go:embed all:dashboard
//go:embed all:public
var FS embed.FS
