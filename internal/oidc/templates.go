package oidc

import (
	"embed"
	"html/template"
	"net/http"
	"net/url"
)

//go:embed templates/*.html
var templateFS embed.FS

var templates = template.Must(template.ParseFS(templateFS, "templates/*.html"))

// pageData is the model passed to every login theme page.
type pageData struct {
	Realm         string
	Title         string
	Error         string
	Message       string
	Username      string
	UsernameLabel string
	Action        string
	Fields        url.Values
}

func (h *Handler) render(w http.ResponseWriter, status int, page string, d pageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, must-revalidate, max-age=0")
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	w.Header().Set("Content-Security-Policy", "frame-src 'self'; frame-ancestors 'self'; object-src 'none';")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(status)
	if err := templates.ExecuteTemplate(w, page+".html", d); err != nil {
		h.Log.Error("render template", "page", page, "err", err)
	}
}

func (h *Handler) errorPage(w http.ResponseWriter, r *http.Request, status int, msg string) {
	h.render(w, status, "error", pageData{Title: "We are sorry...", Error: msg})
}

func (h *Handler) serverErrorPage(w http.ResponseWriter, r *http.Request, err error) {
	h.Log.Error("internal error", "path", r.URL.Path, "err", err)
	h.errorPage(w, r, http.StatusInternalServerError, "An internal server error has occurred.")
}
