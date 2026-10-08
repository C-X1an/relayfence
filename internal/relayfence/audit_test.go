package relayfence

import (
	"os"

	"strings"

	"bytes"
	"testing"

	"path/filepath"
)

func TestAuditIntegrity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a, e := OpenAudit(path)
	if e != nil {
		t.Fatal(e)
	}
	if e = a.Record(Event{Kind: "denied", Reason: "policy_denied"}); e != nil {
		t.Fatal(e)
	}
	if e = a.Record(Event{Kind: "closed", Bytes: 17}); e != nil {
		t.Fatal(e)
	}
	if e = a.Close(); e != nil {
		t.Fatal(e)
	}
	data, _ := os.ReadFile(path)
	rows, e := VerifyAudit(data)
	if e != nil || len(rows) != 2 {
		t.Fatalf("%v %v", rows, e)
	}
	changed := bytes.Replace(data, []byte("policy_denied"), []byte("policy_allowed"), 1)
	if _, e = VerifyAudit(changed); e == nil {
		t.Fatal("content tampering accepted")
	}
	lines := bytes.SplitAfter(data, []byte("\n"))
	if _, e = VerifyAudit(append(append([]byte{}, lines[1]...), lines[0]...)); e == nil {
		t.Fatal("reordering accepted")
	}
	if _, e = VerifyAudit(data[:len(data)-1]); e == nil {
		t.Fatal("partial final record accepted")
	}
	a, e = OpenAudit(path)
	if e != nil {
		t.Fatal(e)
	}
	if e = a.Record(Event{Kind: "allowed"}); e != nil {
		t.Fatal(e)
	}
	a.Close()
	rows, e = ReadAudit(path)
	if e != nil || len(rows) != 3 {
		t.Fatal("restart chain failure", e)
	}

	if _, e = VerifyAudit(lines[0]); e != nil {
		t.Fatal("valid prefix must verify; do not claim rollback protection")
	}
}
func TestInspectEscapes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a, e := OpenAudit(path)
	if e != nil {
		t.Fatal(e)
	}
	if e = a.Record(Event{Kind: "denied", Identity: "<script>alert(1)</script>"}); e != nil {
		t.Fatal(e)
	}
	a.Close()
	var out bytes.Buffer
	if e = InspectAudit(path, &out); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(out.String(), "<script>") || !strings.Contains(out.String(), "&lt;script&gt;") {
		t.Fatal("HTML escaping failed")
	}
}
