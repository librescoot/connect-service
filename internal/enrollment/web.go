package enrollment

import (
	"embed"
	"html/template"
	"io/fs"
	"net/http"
)

//go:embed web/pair.html
var pairHTML string

//go:embed web/pair.css
var pairCSS string

//go:embed web/pair.js
var pairJS string

//go:embed web/assets
var pairAssets embed.FS

var pairAssetHandler = func() http.Handler {
	assets, err := fs.Sub(pairAssets, "web/assets")
	if err != nil {
		panic(err)
	}
	return http.StripPrefix("/assets/", http.FileServer(http.FS(assets)))
}()

var pairPage = template.Must(template.New("pair").Parse(pairHTML))
