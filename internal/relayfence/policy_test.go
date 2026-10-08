package relayfence

import (
	"strings"

	"bytes"
	"encoding/json"
	"testing"
)

func TestStrictJSON(t *testing.T) {
	p := labPolicy("example.test:443")
	b, _ := json.Marshal(p)
	var got Policy
	if e := StrictJSON(b, &got); e != nil {
		t.Fatal(e)
	}
	invalid := [][]byte{[]byte(`{"schema_version":1,"schema_version":1}`), []byte(`{"bogus":1}`), []byte(`{"REVISION":1}`), []byte(`{"revision":1,"Revision":2}`), []byte(`{} {}`), []byte(`{"rules":[{"identity":"a","identity":"b"}]}`), bytes.Repeat([]byte("x"), MaxPolicyBytes+1), []byte(strings.Repeat("[", 34) + strings.Repeat("]", 34))}
	for _, b := range invalid {
		var v Policy
		if StrictJSON(b, &v) == nil {
			t.Fatalf("accepted invalid JSON: %.100s", b)
		}
	}
}
func TestPolicyValidation(t *testing.T) {
	p := labPolicy("Example.Test.:443")
	v, e := p.Validate()
	if e != nil || v.Rules[0].Destinations[0] != "example.test:443" {
		t.Fatalf("%v %v", v, e)
	}
	p.Rules[0].Destinations[0] = "mutated.test:443"
	if v.Rules[0].Destinations[0] != "example.test:443" {
		t.Fatal("caller changed snapshot")
	}
	for _, mutate := range []func(*Policy){func(p *Policy) { p.SchemaVersion = 2 }, func(p *Policy) { p.Revision = 0 }, func(p *Policy) { p.GlobalMaxActive = 0 }, func(p *Policy) { p.Rules[0].MaxBytes = -1 }, func(p *Policy) { p.Rules[0].Identity = "CN=demo" }, func(p *Policy) { p.Rules[0].Destinations = nil }, func(p *Policy) { p.Rules[0].Destinations = []string{"a.test:443", "A.test.:443"} }, func(p *Policy) { p.Rules = append(p.Rules, p.Rules[0]) }, func(p *Policy) { p.Rules[0].IdleTimeoutMS = p.Rules[0].MaxDurationMS + 1 }} {
		q := labPolicy("a.test:443")
		mutate(&q)
		if _, e := q.Validate(); e == nil {
			t.Fatal("accepted invalid policy")
		}
	}
}

func FuzzStrictJSON(f *testing.F) {
	f.Add([]byte(`{"revision":1}`))
	f.Add([]byte(`{"a":1,"a":2}`))
	f.Fuzz(func(t *testing.T, b []byte) { var p Policy; _ = StrictJSON(b, &p) })
}
