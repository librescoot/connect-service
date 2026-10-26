package enrollment

import (
	_ "embed"
	"html/template"
)

//go:embed web/pair.html
var pairHTML string

//go:embed web/pair.css
var pairCSS string

//go:embed web/pair.js
var pairJS string

var pairPage = template.Must(template.New("pair").Parse(pairHTML))
