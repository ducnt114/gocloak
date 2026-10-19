package oidc

import (
	"html/template"
	"io"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/theme"
)

// TemplateFuncs are the functions available to theme templates.
var TemplateFuncs = template.FuncMap{
	"js": func(s string) template.JS { return template.JS(s) },
}

// pageData is the model passed to every login theme page. Title, Error and
// Message are message keys (or literal texts) of the theme.
type pageData struct {
	Realm         string
	Title         string
	TitleArgs     []any
	Error         string
	ErrorArgs     []any
	Message       string
	MessageArgs   []any
	Username      string
	UsernameLabel string
	Action        string
	Fields        url.Values

	// Links of the login page.
	RegisterURL, ResetURL, LoginURL, RestartURL string
	RememberMe, Remembered                      bool

	// Identity provider buttons of the login page.
	Providers []providerLink

	// A link shown on info pages.
	LinkURL, LinkText string

	// Registration and profile forms.
	Profile         []profileField
	Password, Terms bool
	FieldErrors     map[string]profileField

	// Items is a list of message keys (e.g. required actions).
	Items []string

	// Frames are the front-channel logout URLs of clients, loaded in
	// hidden iframes (and allowed by the page's frame-src).
	Frames []string

	OTP      *otpSetup
	WebAuthn *webauthnPage

	// Theme and language, set by render.
	Locale       string
	Locales      []localeOption
	Styles       []string
	ResourcesURL string

	realm *model.Realm
	r     *http.Request
	user  *model.User
	th    *theme.Theme
}

// profileField is a user profile attribute on a form. Label and Error are
// message keys.
type profileField struct {
	Name, Label, Type, Value, Error string
	ErrorArgs                       []any
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

// localeOption is an entry of the language selector.
type localeOption struct {
	Code, Label, URL string
	Current          bool
}

// T translates a message key in the page's locale.
func (d pageData) T(key string, args ...any) string {
	if d.th == nil {
		return key
	}
	return d.th.Message(d.Locale, key, args...)
}

// ErrorText, MessageText and TitleText are the translated page texts.
func (d pageData) ErrorText() string   { return d.T(d.Error, d.ErrorArgs...) }
func (d pageData) MessageText() string { return d.T(d.Message, d.MessageArgs...) }
func (d pageData) TitleText() string   { return d.T(d.Title, d.TitleArgs...) }

// FieldText translates the error of a profile field.
func (d pageData) FieldText(f profileField) string { return d.T(f.Error, f.ErrorArgs...) }

// LanguageNames labels locales in language selectors.
var LanguageNames = map[string]string{
	"en": "English", "vi": "Tiếng Việt", "de": "Deutsch", "fr": "Français", "es": "Español", "it": "Italiano",
	"ja": "日本語", "ko": "한국어", "zh-CN": "中文简体", "zh-TW": "中文繁體", "pt-BR": "Português (Brasil)", "ru": "Русский",
	"nl": "Nederlands", "pl": "Polski", "cs": "Čeština", "th": "ไทย", "id": "Bahasa Indonesia",
}

const localeCookie = "KEYCLOAK_LOCALE"

// Locale picks the language of a page, following Keycloak: kc_locale,
// ui_locales, the KEYCLOAK_LOCALE cookie, the user's locale attribute, then
// Accept-Language, among the realm's supported locales. kc_locale is
// remembered in the cookie when w is given.
func (h *Handler) Locale(w http.ResponseWriter, r *http.Request, realm *model.Realm, user *model.User) string {
	def := "en"
	if realm == nil {
		return def
	}
	if realm.Settings.DefaultLocale != "" {
		def = realm.Settings.DefaultLocale
	}
	if !realm.Settings.InternationalizationEnabled {
		return def
	}
	supported := realm.Settings.SupportedLocales
	if len(supported) == 0 {
		supported = []string{def}
	}
	match := func(l string) string {
		l = strings.TrimSpace(l)
		if l == "" {
			return ""
		}
		for _, s := range supported {
			if strings.EqualFold(s, l) {
				return s
			}
		}
		for _, s := range supported {
			if strings.EqualFold(s, baseLocale(l)) {
				return s
			}
		}
		return ""
	}
	if r != nil {
		if l := match(r.URL.Query().Get("kc_locale")); l != "" {
			if w != nil {
				h.setCookie(w, r, realm, localeCookie, l, 365*24*3600)
			}
			return l
		}
		for _, l := range strings.Fields(r.URL.Query().Get("ui_locales")) {
			if m := match(l); m != "" {
				return m
			}
		}
		if c, err := r.Cookie(localeCookie); err == nil {
			if m := match(c.Value); m != "" {
				return m
			}
		}
	}
	if user != nil {
		if v := user.Attributes["locale"]; len(v) > 0 {
			if m := match(v[0]); m != "" {
				return m
			}
		}
	}
	if r != nil {
		for _, part := range strings.Split(r.Header.Get("Accept-Language"), ",") {
			tag, _, _ := strings.Cut(part, ";")
			if m := match(tag); m != "" {
				return m
			}
		}
	}
	return def
}

func baseLocale(l string) string {
	if i := strings.IndexAny(l, "-_"); i > 0 {
		return l[:i]
	}
	return l
}

func (h *Handler) render(w http.ResponseWriter, status int, page string, d pageData) {
	if d.realm == nil && d.r != nil {
		d.realm, _ = h.Svc.Store.GetRealmByName(d.r.Context(), d.r.PathValue("realm"))
	}
	themeName := ""
	if d.realm != nil {
		themeName = d.realm.Settings.LoginTheme
		if d.Realm == "" && page != "form-post" {
			d.Realm = realmTitle(d.realm)
		}
	}
	th, err := h.Themes.Get(theme.Login, themeName)
	if err != nil {
		h.Log.Error("load theme", "theme", themeName, "err", err)
		if th, err = h.Themes.Get(theme.Login, theme.Default); err != nil {
			http.Error(w, "theme error", http.StatusInternalServerError)
			return
		}
	}
	d.th = th
	d.Locale = h.Locale(w, d.r, d.realm, d.user)
	d.ResourcesURL = "/resources/" + url.PathEscape(th.Name) + "/login"
	if d.r != nil {
		d.ResourcesURL = h.URLs.Base(d.r) + d.ResourcesURL
		if d.realm != nil && d.realm.Settings.InternationalizationEnabled && len(d.realm.Settings.SupportedLocales) > 1 && d.r.Method == http.MethodGet {
			for _, l := range d.realm.Settings.SupportedLocales {
				u := *d.r.URL
				q := u.Query()
				q.Set("kc_locale", l)
				u.RawQuery = q.Encode()
				label := LanguageNames[l]
				if label == "" {
					label = l
				}
				d.Locales = append(d.Locales, localeOption{Code: l, Label: label, URL: u.String(), Current: l == d.Locale})
			}
		}
	}
	for _, s := range th.Styles {
		d.Styles = append(d.Styles, d.ResourcesURL+"/"+s)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Language", d.Locale)
	w.Header().Set("Cache-Control", "no-store, must-revalidate, max-age=0")
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	frameSrc := "'self'"
	for _, f := range d.Frames {
		if u, err := url.Parse(f); err == nil && u.Host != "" {
			frameSrc += " " + u.Host
		}
	}
	w.Header().Set("Content-Security-Policy", "frame-src "+frameSrc+"; frame-ancestors 'self'; object-src 'none';")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(status)
	if err := th.Execute(w, page+".html", d); err != nil {
		h.Log.Error("render template", "page", page, "theme", th.Name, "err", err)
	}
}

func (h *Handler) errorPage(w http.ResponseWriter, r *http.Request, status int, msg string, args ...any) {
	h.render(w, status, "error", pageData{Title: "errorTitle", Error: msg, ErrorArgs: args, r: r})
}

func (h *Handler) serverErrorPage(w http.ResponseWriter, r *http.Request, err error) {
	h.Log.Error("internal error", "path", r.URL.Path, "err", err)
	h.errorPage(w, r, http.StatusInternalServerError, "internalServerError")
}

// resources serves theme resources: /resources/{theme}/{type}/{path...}.
func (h *Handler) resources(w http.ResponseWriter, r *http.Request) {
	typ := r.PathValue("type")
	if typ != theme.Login && typ != theme.Account && typ != theme.Email {
		http.NotFound(w, r)
		return
	}
	th, err := h.Themes.Get(typ, r.PathValue("theme"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	p := r.PathValue("path")
	f, err := th.Open(p)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.IsDir() {
		http.NotFound(w, r)
		return
	}
	if ct := mime.TypeByExtension(path.Ext(p)); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	io.Copy(w, f)
}
