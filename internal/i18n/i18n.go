// Package i18n reads message bundles (Java .properties files)
// and formats their messages ({0}-style placeholders, as Java's MessageFormat).
package i18n

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Parse reads a .properties document: key=value or key: value lines,
// '#' and '!' comments, backslash line continuations and \uXXXX escapes.
func Parse(r io.Reader) (map[string]string, error) {
	out := map[string]string{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	var logical strings.Builder
	for sc.Scan() {
		line := strings.TrimLeft(sc.Text(), " \t\f")
		if logical.Len() == 0 && (line == "" || line[0] == '#' || line[0] == '!') {
			continue
		}
		// an odd number of trailing backslashes continues the line
		trailing := len(line) - len(strings.TrimRight(line, `\`))
		if trailing%2 == 1 {
			logical.WriteString(line[:len(line)-1])
			continue
		}
		logical.WriteString(line)
		key, value := splitEntry(logical.String())
		logical.Reset()
		k, err := unescape(key)
		if err != nil {
			return nil, err
		}
		v, err := unescape(value)
		if err != nil {
			return nil, err
		}
		out[k] = v
	}
	if logical.Len() > 0 {
		key, value := splitEntry(logical.String())
		k, _ := unescape(key)
		v, _ := unescape(value)
		out[k] = v
	}
	return out, sc.Err()
}

func splitEntry(s string) (string, string) {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '=', ':', ' ', '\t':
			key := s[:i]
			rest := strings.TrimLeft(s[i:], " \t")
			if rest != "" && (rest[0] == '=' || rest[0] == ':') {
				rest = strings.TrimLeft(rest[1:], " \t")
			}
			return key, rest
		}
	}
	return s, ""
}

func unescape(s string) (string, error) {
	if !strings.Contains(s, `\`) {
		return s, nil
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' || i+1 >= len(s) {
			b.WriteByte(c)
			continue
		}
		i++
		switch s[i] {
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		case 'r':
			b.WriteByte('\r')
		case 'f':
			b.WriteByte('\f')
		case 'u':
			if i+4 >= len(s) {
				return "", fmt.Errorf("invalid unicode escape in %q", s)
			}
			n, err := strconv.ParseUint(s[i+1:i+5], 16, 32)
			if err != nil {
				return "", fmt.Errorf("invalid unicode escape in %q", s)
			}
			r := rune(n)
			// combine UTF-16 surrogate pairs
			if r >= 0xD800 && r < 0xDC00 && i+10 < len(s) && s[i+5] == '\\' && s[i+6] == 'u' {
				if lo, err := strconv.ParseUint(s[i+7:i+11], 16, 32); err == nil {
					r = (r-0xD800)<<10 + (rune(lo) - 0xDC00) + 0x10000
					i += 6
				}
			}
			var buf [4]byte
			b.Write(buf[:utf8.EncodeRune(buf[:], r)])
			i += 4
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String(), nil
}

// Format substitutes {0}, {1}... in a MessageFormat pattern. Text in
// single quotes is literal and ” is a quote.
func Format(pattern string, args ...any) string {
	if !strings.ContainsAny(pattern, "{'") {
		return pattern
	}
	var b strings.Builder
	quoted := false
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		switch {
		case c == '\'':
			if i+1 < len(pattern) && pattern[i+1] == '\'' {
				b.WriteByte('\'')
				i++
			} else {
				quoted = !quoted
			}
		case c == '{' && !quoted:
			end := strings.IndexByte(pattern[i:], '}')
			if end < 0 {
				b.WriteString(pattern[i:])
				return b.String()
			}
			spec := pattern[i+1 : i+end]
			if comma := strings.IndexByte(spec, ','); comma >= 0 {
				spec = spec[:comma]
			}
			n, err := strconv.Atoi(strings.TrimSpace(spec))
			if err == nil && n >= 0 && n < len(args) {
				b.WriteString(fmt.Sprint(args[n]))
			} else {
				b.WriteString(pattern[i : i+end+1])
			}
			i += end
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}
