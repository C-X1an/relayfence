package relayfence

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"unicode/utf8"
)

const MaxPolicyBytes = 1 << 20

type Rule struct {
	Identity      string   `json:"identity"`
	Destinations  []string `json:"destinations"`
	MaxActive     int      `json:"max_active"`
	MaxBytes      int64    `json:"max_bytes"`
	MaxDurationMS int64    `json:"max_duration_ms"`
	IdleTimeoutMS int64    `json:"idle_timeout_ms"`
}
type Policy struct {
	SchemaVersion   int    `json:"schema_version"`
	Revision        uint64 `json:"revision"`
	GlobalMaxActive int    `json:"global_max_active"`
	Rules           []Rule `json:"rules"`
}

func ValidIdentity(id string) bool {
	const prefix = "urn:relayfence:workload:"
	if !strings.HasPrefix(id, prefix) {
		return false
	}
	rest := strings.TrimPrefix(id, prefix)
	if len(rest) == 0 || len(rest) > 63 {
		return false
	}
	for i, c := range rest {
		if !(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') && !(c == '-' && i > 0) {
			return false
		}
	}
	return true
}

// Validate returns a deep copy; callers cannot mutate an installed snapshot.
func (p Policy) Validate() (Policy, error) {
	if p.SchemaVersion != 1 || p.Revision == 0 || p.GlobalMaxActive < 1 || p.GlobalMaxActive > 1024 || len(p.Rules) > 1024 {
		return Policy{}, ErrInvalid
	}
	out := p
	out.Rules = make([]Rule, len(p.Rules))
	ids := map[string]bool{}
	for i, r := range p.Rules {
		if !ValidIdentity(r.Identity) || ids[r.Identity] || r.MaxActive < 1 || r.MaxActive > 256 || r.MaxBytes < 1 || r.MaxBytes > 1<<30 || r.MaxDurationMS < 1 || r.MaxDurationMS > 3600000 || r.IdleTimeoutMS < 1 || r.IdleTimeoutMS > 60000 || r.IdleTimeoutMS > r.MaxDurationMS || len(r.Destinations) < 1 || len(r.Destinations) > 256 {
			return Policy{}, ErrInvalid
		}
		ids[r.Identity] = true
		out.Rules[i] = r
		out.Rules[i].Destinations = make([]string, len(r.Destinations))
		seen := map[string]bool{}
		for k, d := range r.Destinations {
			_, canon, err := Authority(d)
			if err != nil || seen[canon] {
				return Policy{}, ErrInvalid
			}
			seen[canon] = true
			out.Rules[i].Destinations[k] = canon
		}
	}
	// The installed snapshot must fit the same representation that startup
	// reads. Direct library updates obey the file bound as well as JSON input.
	encoded, err := json.Marshal(out)
	if err != nil || len(encoded)+1 > MaxPolicyBytes {
		return Policy{}, ErrInvalid
	}
	return out, nil
}

// StrictJSON rejects duplicate members, unknown fields, trailing values and
// excessive nesting/size before decoding the typed configuration.
func StrictJSON(data []byte, target any) error {
	if len(data) > MaxPolicyBytes || !utf8.Valid(data) {
		return ErrInvalid
	}
	tokens := json.NewDecoder(bytes.NewReader(data))
	tokens.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 32 {
			return ErrInvalid
		}
		t, err := tokens.Token()
		if err != nil {
			return err
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for tokens.More() {
				k, err := tokens.Token()
				if err != nil {
					return err
				}
				key, ok := k.(string)
				if !ok || seen[key] {
					return ErrInvalid
				}
				seen[key] = true
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			end, err := tokens.Token()
			if err != nil || end != json.Delim('}') {
				return ErrInvalid
			}
		case '[':
			for tokens.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			end, err := tokens.Token()
			if err != nil || end != json.Delim(']') {
				return ErrInvalid
			}
		default:
			return ErrInvalid
		}
		return nil
	}
	if err := walk(0); err != nil {
		return fmt.Errorf("%w: invalid JSON", ErrInvalid)
	}
	if _, err := tokens.Token(); err != io.EOF {
		return ErrInvalid
	}
	var shape any
	shapeDecoder := json.NewDecoder(bytes.NewReader(data))
	shapeDecoder.UseNumber()
	if err := shapeDecoder.Decode(&shape); err != nil {
		return ErrInvalid
	}
	if err := exactFields(shape, reflect.TypeOf(target)); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return fmt.Errorf("%w: invalid fields", ErrInvalid)
	}
	return nil
}
func ReadPolicy(path string) (Policy, error) {
	file, err := os.Open(path)
	if err != nil {
		return Policy{}, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, MaxPolicyBytes+1))
	if err != nil {
		return Policy{}, err
	}
	var p Policy
	if err := StrictJSON(data, &p); err != nil {
		return Policy{}, err
	}
	return p.Validate()
}

// encoding/json matches struct fields case-insensitively. Reject aliases first
// so REVISION and revision cannot silently overwrite the same logical field.
func exactFields(value any, typ reflect.Type) error {
	if typ == nil {
		return ErrInvalid
	}
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if value == nil {
		return nil
	}
	switch typ.Kind() {
	case reflect.Struct:
		object, ok := value.(map[string]any)
		if !ok {
			return ErrInvalid
		}
		fields := map[string]reflect.Type{}
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			if !field.IsExported() {
				continue
			}
			name := strings.Split(field.Tag.Get("json"), ",")[0]
			if name == "-" {
				continue
			}
			if name == "" {
				name = field.Name
			}
			fields[name] = field.Type
		}
		for name, child := range object {
			field, exists := fields[name]
			if !exists {
				return ErrInvalid
			}
			if err := exactFields(child, field); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		array, ok := value.([]any)
		if !ok {
			return ErrInvalid
		}
		for _, child := range array {
			if err := exactFields(child, typ.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}
