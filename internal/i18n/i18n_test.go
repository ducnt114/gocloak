package i18n

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	m, err := Parse(strings.NewReader("# comment\n! other\nkey=value\nspaced : x y \nmulti=line one \\\n    line two\nuni=Ti\\u1EBFng Vi\\u1EC7t\nempty=\nesc=a\\=b\\nc\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"key": "value", "spaced": "x y ", "multi": "line one line two", "uni": "Tiếng Việt", "empty": "", "esc": "a=b\nc"}
	for k, v := range want {
		if m[k] != v {
			t.Errorf("%s = %q, want %q", k, m[k], v)
		}
	}
}

func TestFormat(t *testing.T) {
	cases := map[string]string{
		Format("Invalid password: minimum length {0}.", 8): "Invalid password: minimum length 8.",
		Format("Passwords don''t match."):                  "Passwords don't match.",
		Format("{1} and {0}", "a", "b"):                    "b and a",
		Format("'{0}' is literal, {0} is not", "x"):        "{0} is literal, x is not",
		Format("missing {3}", "x"):                         "missing {3}",
	}
	for got, want := range cases {
		if got != want {
			t.Errorf("got %q want %q", got, want)
		}
	}
}
