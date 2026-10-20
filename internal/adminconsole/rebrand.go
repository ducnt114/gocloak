package adminconsole

import (
	"bytes"
	"embed"
	"path"
	"regexp"
	"strings"
	"sync"
)

// The console comes from the upstream jars with the upstream name in its
// texts, CSS classes, component type names and logos. Rebrand renames it to
// gocloak in every text file as it is served, with the same rule the server
// uses for its own names (org.gocloak.keys.KeyProvider, fedToGocloak...), so
// the console and the server keep agreeing.

var brandRe = regexp.MustCompile(`(?i)www\.keycloak\.org|github\.com/keycloak(?:/[\w.-]+)?|keycloak`)

// Rebrand replaces the upstream name with gocloak, keeping its case:
// KEYCLOAK becomes GOCLOAK, keycloak gocloak, and Keycloak gocloak as a word
// or Gocloak inside an identifier (fedToKeycloak becomes fedToGocloak).
// Links to the upstream documentation and repository are kept.
func Rebrand(s string) string { return string(rebrand([]byte(s))) }

func rebrand(b []byte) []byte {
	idx := brandRe.FindAllIndex(b, -1)
	if len(idx) == 0 {
		return b
	}
	var out bytes.Buffer
	out.Grow(len(b))
	last := 0
	for _, m := range idx {
		i, j := m[0], m[1]
		out.Write(b[last:i])
		last = j
		word := string(b[i:j])
		switch {
		case j-i != len("keycloak"): // a kept link
			out.WriteString(word)
		case word == strings.ToUpper(word):
			out.WriteString("GOCLOAK")
		case word[0] >= 'A' && word[0] <= 'Z' && i > 0 && isIdentChar(b[i-1]):
			out.WriteString("Gocloak")
		default:
			out.WriteString("gocloak")
		}
	}
	out.Write(b[last:])
	return out.Bytes()
}

func isIdentChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '$'
}

// rebrandedTypes are the files whose text is rewritten.
var rebrandedTypes = map[string]bool{".js": true, ".mjs": true, ".css": true, ".html": true, ".json": true,
	".properties": true, ".txt": true}

//go:embed brand/*.svg
var brandFS embed.FS

// brandFiles replace the upstream logos of the console's resources.
var brandFiles = map[string]string{"resources/logo.svg": "brand/logo.svg", "resources/icon.svg": "brand/icon.svg",
	"resources/favicon.svg": "brand/favicon.svg"}

// rebrandCache keeps rewritten files (jar files never change while served).
var rebrandCache sync.Map // fs pointer + name -> []byte

func rebrandFile(key, name string, read func() ([]byte, error)) ([]byte, bool, error) {
	if !rebrandedTypes[path.Ext(name)] {
		return nil, false, nil
	}
	if v, ok := rebrandCache.Load(key); ok {
		return v.([]byte), true, nil
	}
	b, err := read()
	if err != nil {
		return nil, false, err
	}
	b = rebrand(b)
	rebrandCache.Store(key, b)
	return b, true, nil
}
