package oidc

import (
	"embed"
	"html/template"
	"net/http"
	"net/url"
)

//go:embed templates/*.html
var templateFS embed.FS

var templates = template.Must(template.New("").Funcs(template.FuncMap{
	"js": func(s string) template.JS { return template.JS(s) },
}).ParseFS(templateFS, "templates/*.html"))

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

	// Links of the login page.
	RegisterURL, ResetURL, LoginURL, RestartURL string
	RememberMe, Remembered                      bool

	// A link shown on info pages.
	LinkURL, LinkText string

	// Registration and profile forms.
	Profile         []profileField
	Password, Terms bool
	FieldErrors     map[string]string

	OTP      *otpSetup
	WebAuthn *webauthnPage
}

// profileField is a user profile attribute on a form.
type profileField struct {
	Name, Label, Type, Value, Error string
	Required, ReadOnly              bool
}

// otpSetup is the content of the CONFIGURE_TOTP page.
type otpSetup struct {
	QR                      template.URL // a data: URL, trusted
	Secret, Type, Algorithm string
	Digits, Period, Counter int
}

// webauthnPage carries the WebAuthn options for the browser.
type webauthnPage struct {
	Options string // JSON of PublicKeyCredentialCreationOptions / RequestOptions
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
