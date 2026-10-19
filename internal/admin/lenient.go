package admin

import (
	"bytes"
	"encoding/json"
	"strconv"
)

// Keycloak's JSON binding (Jackson) is lenient: a single value is accepted
// where a list is expected, and numbers or booleans where strings are. The
// admin console relies on it, so these types accept the same input.

// strMap is a map of strings accepting scalar values.
type strMap map[string]string

func (m *strMap) UnmarshalJSON(b []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if raw == nil {
		*m = nil
		return nil
	}
	out := make(strMap, len(raw))
	for k, v := range raw {
		s, err := scalarString(v)
		if err != nil {
			return &json.UnmarshalTypeError{Value: string(v), Field: k}
		}
		out[k] = s
	}
	*m = out
	return nil
}

// listMap is a map of string lists accepting single values.
type listMap map[string][]string

func (m *listMap) UnmarshalJSON(b []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if raw == nil {
		*m = nil
		return nil
	}
	out := make(listMap, len(raw))
	for k, v := range raw {
		v = bytes.TrimSpace(v)
		if len(v) > 0 && v[0] == '[' {
			var items []json.RawMessage
			if err := json.Unmarshal(v, &items); err != nil {
				return err
			}
			list := make([]string, 0, len(items))
			for _, it := range items {
				s, err := scalarString(it)
				if err != nil {
					return &json.UnmarshalTypeError{Value: string(it), Field: k}
				}
				list = append(list, s)
			}
			out[k] = list
			continue
		}
		if string(v) == "null" {
			out[k] = nil
			continue
		}
		s, err := scalarString(v)
		if err != nil {
			return &json.UnmarshalTypeError{Value: string(v), Field: k}
		}
		out[k] = []string{s}
	}
	*m = out
	return nil
}

// scalarString reads a JSON string, number, boolean or null as a string.
func scalarString(v json.RawMessage) (string, error) {
	var x any
	if err := json.Unmarshal(v, &x); err != nil {
		return "", err
	}
	switch t := x.(type) {
	case string:
		return t, nil
	case bool:
		return strconv.FormatBool(t), nil
	case float64:
		return string(bytes.TrimSpace(v)), nil
	case nil:
		return "", nil
	}
	return "", &json.UnmarshalTypeError{Value: string(v)}
}
