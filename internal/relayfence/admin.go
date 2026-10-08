package relayfence

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

type PolicyUpdate struct {
	ExpectedRevision uint64 `json:"expected_revision"`
	Policy           Policy `json:"policy"`
}

// AdminHandler is deliberately not mounted on the gateway's network listener.
func AdminHandler(store *Store) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/status" && r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(store.Status())
			return
		}
		if r.URL.Path != "/v1/policy" || r.Method != http.MethodPut {
			errorJSON(w, 404, "not_found")
			return
		}
		if r.Header.Get("Content-Type") != "application/json" {
			errorJSON(w, 400, "bad_request")
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxPolicyBytes))
		var update PolicyUpdate
		if err != nil || StrictJSON(body, &update) != nil {
			errorJSON(w, 400, "bad_request")
			return
		}
		if err = store.Replace(update.ExpectedRevision, update.Policy); err != nil {
			status, code := 400, "bad_request"
			if errors.Is(err, ErrStale) {
				status, code = 409, "stale_session"
			}
			if errors.Is(err, ErrUnavailable) {
				status, code = 503, "unavailable"
			}
			errorJSON(w, status, code)
			return
		}
		_ = json.NewEncoder(w).Encode(store.Status())
	})
}

type Admin struct {
	server   *http.Server
	listener net.Listener
	path     string
}

// StartAdmin refuses existing sockets rather than deleting an unrelated endpoint.
func StartAdmin(path string, store *Store) (*Admin, error) {
	if store == nil {
		return nil, ErrInvalid
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	st, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() || st.Mode().Perm() != 0700 {
		return nil, errors.New("admin parent must be a0700 directory")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		return nil, errors.New("admin socket path already exists or is inaccessible")
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err = os.Chmod(path, 0600); err != nil {
		listener.Close()
		return nil, err
	}
	server := &http.Server{Handler: AdminHandler(store), ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 4096}
	a := &Admin{server, listener, path}
	go func() { _ = server.Serve(listener) }()
	return a, nil
}
func (a *Admin) Close(ctx context.Context) error {
	err := a.server.Shutdown(ctx)
	if err != nil {
		_ = a.server.Close()
	}
	return err
}
func AdminClient(path string) *http.Client {
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", path)
		}, MaxIdleConns: 1,
	}}
}
