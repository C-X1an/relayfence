package relayfence

import (
	"strings"

	"context"
	"io"
	"net/http"
	"path/filepath"
	"testing"

	"os"
)

func TestAdmin(t *testing.T) {
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "admin.sock")
	s := mustStore(t, labPolicy("a.test:443"))
	a, e := StartAdmin(path, s)
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close(context.Background())
	st, e := os.Stat(path)
	if e != nil || st.Mode().Perm() != 0600 {
		t.Fatal("socket mode", e)
	}
	client := AdminClient(path)
	defer client.CloseIdleConnections()
	request := func(method, path, body string) int {
		t.Helper()
		req, e := http.NewRequest(method, "http://unix"+path, strings.NewReader(body))
		if e != nil {
			t.Fatal(e)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, e := client.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}
	if request("GET", "/v1/status", "") != 200 {
		t.Fatal("status")
	}
	update := `{"expected_revision":1,"policy":{"schema_version":1,"revision":2,"global_max_active":8,"rules":[]}}`
	if request("PUT", "/v1/policy", update) != 200 || s.Status().Revision != 2 {
		t.Fatal("CAS update")
	}
	if request("PUT", "/v1/policy", update) != 409 {
		t.Fatal("stale CAS accepted")
	}
	if request("PUT", "/v1/policy", `{"unknown":1}`) != 400 {
		t.Fatal("unknown field accepted")
	}
	if request("PUT", "/v1/policy", strings.Repeat(" ", MaxPolicyBytes+1)) != 400 {
		t.Fatal("oversize accepted")
	}
	if _, e = StartAdmin(path, s); e == nil {
		t.Fatal("existing admin socket replaced")
	}
}
