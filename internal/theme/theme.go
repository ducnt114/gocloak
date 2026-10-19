// Package theme loads the login, email and account themes: Go html
// templates, Keycloak style message bundles (messages/messages_<locale>.properties)
// and static resources.
//
// The built-in theme is embedded. A themes directory can add themes laid out
// like Keycloak's:
//
//	<dir>/<name>/<type>/theme.properties   parent=<theme>, styles=css/a.css css/b.css
//	<dir>/<name>/<type>/*.html             templates overriding pages of the parent
//	<dir>/<name>/<type>/messages/messages_<locale>.properties
//	<dir>/<name>/<type>/resources/...      served at /resources/<name>/<type>/...
//
// where <type> is login, email or account.
package theme

import (
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/ducnt114/gocloak/internal/i18n"
)

//go:embed all:default
var defaultFS embed.FS

// Theme types.
const (
	Login   = "login"
	Email   = "email"
	Account = "account"
)

// Default is the name of the built-in theme. Keycloak's built-in names
// map to it, so realms imported from Keycloak keep working.
const Default = "keycloak"

var builtinNames = map[string]bool{"": true, "keycloak": true, "keycloak.v2": true, "base": true, "gocloak": true}

// Manager loads themes, with caching unless disabled (development).
type Manager struct {
	Dir   string
	Cache bool
	Funcs template.FuncMap

	mu    sync.Mutex
	cache map[string]*Theme
}

// Theme is a loaded theme of one type.
type Theme struct {
	Name   string
	Type   string
	Styles []string

	tmpl     *template.Template
	messages map[string]map[string]string // locale -> key -> message
	layers   []fs.FS                      // resource roots: the theme first, the built-in theme last
}

type layer struct {
	fsys  fs.FS
	props map[string]string
}

// Get returns the theme of a type by name; unknown names fall back to the
// built-in theme.
func (m *Manager) Get(typ, name string) (*Theme, error) {
	if builtinNames[name] {
		name = Default
	}
	key := typ + "/" + name
	if m.Cache {
		m.mu.Lock()
		t := m.cache[key]
		m.mu.Unlock()
		if t != nil {
			return t, nil
		}
	}
	t, err := m.load(typ, name)
	if err != nil {
		return nil, err
	}
	if m.Cache {
		m.mu.Lock()
		if m.cache == nil {
			m.cache = map[string]*Theme{}
		}
		m.cache[key] = t
		m.mu.Unlock()
	}
	return t, nil
}

func (m *Manager) load(typ, name string) (*Theme, error) {
	builtin, err := fs.Sub(defaultFS, "default/"+typ)
	if err != nil {
		return nil, err
	}
	// The chain from the requested theme up to the built-in one.
	var chain []layer
	seen := map[string]bool{}
	for cur := name; !builtinNames[cur] && m.Dir != "" && !seen[cur]; {
		seen[cur] = true
		dir := path.Join(m.Dir, cur, typ)
		if st, err := os.Stat(dir); err != nil || !st.IsDir() {
			break
		}
		fsys := os.DirFS(dir)
		props := map[string]string{}
		if f, err := fsys.Open("theme.properties"); err == nil {
			props, err = i18n.Parse(f)
			f.Close()
			if err != nil {
				return nil, fmt.Errorf("theme %s: %w", cur, err)
			}
		}
		chain = append(chain, layer{fsys, props})
		cur = props["parent"]
	}
	chain = append(chain, layer{fsys: builtin, props: map[string]string{}})

	t := &Theme{Name: name, Type: typ, messages: map[string]map[string]string{}}
	tmpl := template.New("").Funcs(m.Funcs)
	// apply from the built-in theme down to the requested one, so that
	// templates and messages of children win
	for i := len(chain) - 1; i >= 0; i-- {
		l := chain[i]
		pages, _ := fs.Glob(l.fsys, "*.html")
		if len(pages) > 0 {
			if tmpl, err = tmpl.ParseFS(l.fsys, "*.html"); err != nil {
				return nil, fmt.Errorf("theme %s: %w", name, err)
			}
		}
		files, _ := fs.Glob(l.fsys, "messages/messages_*.properties")
		for _, f := range files {
			locale := strings.TrimSuffix(strings.TrimPrefix(path.Base(f), "messages_"), ".properties")
			if err := t.loadMessages(l.fsys, f, locale); err != nil {
				return nil, fmt.Errorf("theme %s: %w", name, err)
			}
		}
		if styles := strings.Fields(l.props["styles"]); len(styles) > 0 {
			t.Styles = styles
		}
		t.layers = append([]fs.FS{l.fsys}, t.layers...)
	}
	t.tmpl = tmpl
	return t, nil
}

func (t *Theme) loadMessages(fsys fs.FS, file, locale string) error {
	f, err := fsys.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	msgs, err := i18n.Parse(f)
	if err != nil {
		return err
	}
	if t.messages[locale] == nil {
		t.messages[locale] = map[string]string{}
	}
	for k, v := range msgs {
		t.messages[locale][k] = v
	}
	return nil
}

// Execute renders a page template.
func (t *Theme) Execute(w io.Writer, page string, data any) error {
	return t.tmpl.ExecuteTemplate(w, page, data)
}

// HasPage reports whether the theme defines a template.
func (t *Theme) HasPage(page string) bool { return t.tmpl.Lookup(page) != nil }

// Message returns a message in a locale (falling back to English, then to
// the key itself, so that literal texts pass through) formatted with args.
func (t *Theme) Message(locale, key string, args ...any) string {
	for _, l := range []string{locale, baseLocale(locale), "en"} {
		if m, ok := t.messages[l][key]; ok {
			return i18n.Format(m, args...)
		}
	}
	if len(args) > 0 {
		return i18n.Format(key, args...)
	}
	return key
}

// HasMessage reports whether a key exists in a locale or in English.
func (t *Theme) HasMessage(locale, key string) bool {
	_, ok := t.messages[locale][key]
	_, en := t.messages["en"][key]
	return ok || en
}

// Locales lists the locales the theme has messages for.
func (t *Theme) Locales() []string {
	var out []string
	for l := range t.messages {
		out = append(out, l)
	}
	sort.Strings(out)
	return out
}

func baseLocale(l string) string {
	if i := strings.IndexAny(l, "-_"); i > 0 {
		return l[:i]
	}
	return l
}

// Open opens a static resource of the theme (resources/<path>).
func (t *Theme) Open(p string) (fs.File, error) {
	p = path.Clean("/" + p)[1:]
	if p == "" || strings.HasPrefix(p, "..") {
		return nil, fs.ErrNotExist
	}
	for _, l := range t.layers {
		f, err := l.Open("resources/" + p)
		if err == nil {
			return f, nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
	}
	return nil, fs.ErrNotExist
}

// Names lists the themes of a type: the built-in one, then the theme
// directories providing that type.
func (m *Manager) Names(typ string) []string {
	names := []string{Default}
	if m.Dir == "" {
		return names
	}
	entries, err := os.ReadDir(m.Dir)
	if err != nil {
		return names
	}
	for _, e := range entries {
		if st, err := os.Stat(filepath.Join(m.Dir, e.Name(), typ)); err == nil && st.IsDir() && !builtinNames[e.Name()] {
			names = append(names, e.Name())
		}
	}
	return names
}
