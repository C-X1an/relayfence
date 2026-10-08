package relayfence

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDemo(t *testing.T) {
	dir := t.TempDir()
	if e := Demo(dir); e != nil {
		t.Fatal(e)
	}
	for _, file := range []string{"audit.jsonl", "inspection.html", "report.json"} {
		st, e := os.Stat(filepath.Join(dir, file))
		if e != nil || st.Size() == 0 {
			t.Fatalf("missing %s", file)
		}
	}
	if e := Demo(dir); e == nil {
		t.Fatal("demo overwrote prior evidence")
	}
}
