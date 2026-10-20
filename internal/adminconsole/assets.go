// Package adminconsole serves Keycloak's admin console (the
// keycloak-admin-ui React application, Apache License 2.0) against
// gocloak's admin API. The console's files are not part of gocloak: they are
// read from the keycloak-admin-ui and keycloak-themes jars, which
// Download fetches from Maven Central.
package adminconsole

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ducnt114/gocloak/internal/i18n"
)

// Version is the Keycloak release whose admin console gocloak targets.
const Version = "26.0.7"

// Jars are the Maven artifacts holding the console.
var Jars = []string{"keycloak-admin-ui", "keycloak-themes"}

// Assets are the console's files.
type Assets struct {
	Version string
	admin   fs.FS // theme/keycloak.v2/admin
	common  fs.FS // theme/keycloak/common/resources
	base    fs.FS // theme/base/admin

	Entry   string   // entry script
	Styles  []string // entry styles
	Imports []string // module preloads
	closers []io.Closer
}

// Load opens the jars found in dir.
func Load(dir string) (*Assets, error) {
	a := &Assets{}
	open := func(artifact string) (*zip.ReadCloser, string, error) {
		matches, _ := filepath.Glob(filepath.Join(dir, artifact+"-*.jar"))
		if len(matches) == 0 {
			return nil, "", fmt.Errorf("%s jar not found in %s", artifact, dir)
		}
		sort.Strings(matches)
		f := matches[len(matches)-1]
		z, err := zip.OpenReader(f)
		if err != nil {
			return nil, "", err
		}
		a.closers = append(a.closers, z)
		v := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(f), artifact+"-"), ".jar")
		return z, v, nil
	}
	ui, v, err := open("keycloak-admin-ui")
	if err != nil {
		return nil, err
	}
	themes, _, err := open("keycloak-themes")
	if err != nil {
		a.Close()
		return nil, err
	}
	a.Version = v
	a.admin, _ = fs.Sub(ui, "theme/keycloak.v2/admin")
	a.common, _ = fs.Sub(themes, "theme/keycloak/common/resources")
	a.base, _ = fs.Sub(themes, "theme/base/admin")
	if err := a.readManifest(); err != nil {
		a.Close()
		return nil, err
	}
	return a, nil
}

// Close releases the jars.
func (a *Assets) Close() {
	for _, c := range a.closers {
		c.Close()
	}
}

func (a *Assets) readManifest() error {
	b, err := fs.ReadFile(a.admin, "resources/.vite/manifest.json")
	if err != nil {
		return fmt.Errorf("admin console manifest: %w", err)
	}
	var m map[string]struct {
		File    string   `json:"file"`
		CSS     []string `json:"css"`
		Imports []string `json:"imports"`
		IsEntry bool     `json:"isEntry"`
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	for _, e := range m {
		if !e.IsEntry {
			continue
		}
		a.Entry, a.Styles = e.File, e.CSS
		for _, imp := range e.Imports {
			if f := m[imp].File; f != "" {
				a.Imports = append(a.Imports, f)
			}
		}
	}
	if a.Entry == "" {
		return errors.New("admin console manifest has no entry")
	}
	return nil
}

// Messages returns the console's message bundle for a locale: the base
// admin theme overridden by keycloak.v2, falling back to English.
func (a *Assets) Messages(locale string) map[string]string {
	out := map[string]string{}
	read := func(fsys fs.FS, loc string) {
		f, err := fsys.Open("messages/messages_" + strings.ReplaceAll(loc, "-", "_") + ".properties")
		if err != nil {
			return
		}
		defer f.Close()
		msgs, err := i18n.Parse(f)
		if err != nil {
			return
		}
		for k, v := range msgs {
			out[k] = v
		}
	}
	for _, loc := range []string{"en", locale} {
		read(a.base, loc)
		read(a.admin, loc)
	}
	branded := make(map[string]string, len(out))
	for k, v := range out {
		branded[Rebrand(k)] = Rebrand(v)
	}
	return branded
}

// resource serves a file of a jar directory, rebranded (see Rebrand).
func serveFS(w http.ResponseWriter, r *http.Request, fsys fs.FS, name string) {
	name = path.Clean("/" + name)[1:]
	if b, ok, err := rebrandFile(fmt.Sprintf("%p/%s", fsys, name), name, func() ([]byte, error) {
		return fs.ReadFile(fsys, name)
	}); ok || err != nil {
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "public, max-age=2592000")
		http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(b))
		return
	}
	f, err := fsys.Open(name)
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
	rs, ok := f.(io.ReadSeeker)
	if !ok {
		b, err := io.ReadAll(f)
		if err != nil {
			http.Error(w, "read error", http.StatusInternalServerError)
			return
		}
		rs = strings.NewReader(string(b))
	}
	w.Header().Set("Cache-Control", "public, max-age=2592000")
	http.ServeContent(w, r, name, st.ModTime(), rs)
}

// Download fetches the console's jars from Maven Central into dir.
func Download(ctx context.Context, dir, version string, log func(string, ...any)) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	client := &http.Client{Timeout: 5 * time.Minute}
	for _, artifact := range Jars {
		name := artifact + "-" + version + ".jar"
		u := "https://repo1.maven.org/maven2/org/keycloak/" + artifact + "/" + version + "/" + name
		log("downloading %s", u)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return fmt.Errorf("download %s: HTTP %d", u, resp.StatusCode)
		}
		tmp := filepath.Join(dir, name+".part")
		f, err := os.Create(tmp)
		if err != nil {
			resp.Body.Close()
			return err
		}
		_, err = io.Copy(f, resp.Body)
		resp.Body.Close()
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
		if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
			return err
		}
	}
	return nil
}
