//go:build !windows

package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"testing"
	"time"

	rf "github.com/C-X1an/relayfence/internal/relayfence"
)

// The child uses real TCP/mTLS and the production shutdown coordinator with
// the labelled owned-loopback dial fixture. This is an actual process SIGTERM
// control, not public-network validation of the production resolver/dialer.
func TestDaemonShutdownSIGTERMProcess(t *testing.T) {
	if os.Getenv("RELAYFENCE_SHUTDOWN_TEST_CHILD") == "1" {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		f := newShutdownFixture(t, "closed", nil, nil, nil)
		c, reader := f.request(t, "CONNECT")
		response, err := http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
		if err != nil || response.StatusCode != 200 {
			t.Fatalf("CONNECT: %v %v", response, err)
		}
		assertShutdownEcho(t, c, reader)
		fmt.Println("SHUTDOWN_FIXTURE_READY")
		select {
		case <-ctx.Done():
		case <-time.After(5 * time.Second):
			t.Fatal("SIGTERM was not received")
		}
		start := time.Now()
		f.cancel()
		if _, err = reader.ReadByte(); err == nil {
			t.Fatal("SIGTERM left peer connected")
		}
		awaitShutdown(t, f.audit.entered, "SIGTERM closed audit barrier")
		select {
		case err = <-f.result:
			t.Fatalf("SIGTERM returned before audit/release: %v", err)
		case <-time.After(100 * time.Millisecond):
		}
		if f.closed.Load() || f.store.Status().Active != 1 {
			t.Fatal("SIGTERM prematurely closed audit or released session")
		}
		close(f.audit.release)
		select {
		case err = <-f.result:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("SIGTERM failed to join")
		}
		rows, err := rf.ReadAudit(f.path)
		if err != nil || len(rows) != 2 || rows[1].Event.Kind != "closed" || rows[0].Event.Session != rows[1].Event.Session || f.store.Status().Active != 0 || !f.closed.Load() || time.Since(start) > time.Second {
			t.Fatalf("SIGTERM finalization: %+v %v %+v", rows, err, f.store.Status())
		}
		fmt.Println("SHUTDOWN_FIXTURE_JOINED")
		return
	}

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestDaemonShutdownSIGTERMProcess$", "-test.v")
	cmd.Env = append(os.Environ(), "RELAYFENCE_SHUTDOWN_TEST_CHILD=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill() }()
	ready := make(chan struct{})
	scanned := make(chan struct{})
	var output bytes.Buffer
	var scanErr error
	go func() {
		defer close(scanned)
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			fmt.Fprintln(&output, line)
			if line == "SHUTDOWN_FIXTURE_READY" {
				close(ready)
			}
		}
		scanErr = scanner.Err()
	}()
	select {
	case <-ready:
	case <-scanned:
		_ = cmd.Wait()
		t.Fatalf("child failed before readiness: %s %s", output.String(), stderr.String())
	case <-ctx.Done():
		t.Fatal("SIGTERM child did not become ready")
	}
	if err = cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	<-scanned
	if err = cmd.Wait(); err != nil || scanErr != nil {
		t.Fatalf("SIGTERM process failure: %v %v\n%s\n%s", err, scanErr, output.String(), stderr.String())
	}
	if !bytes.Contains(output.Bytes(), []byte("SHUTDOWN_FIXTURE_JOINED")) {
		t.Fatalf("child did not verify audit/release join: %s", output.String())
	}
	t.Log("actual SIGTERM child joined real mTLS tunnel, close audit and release; owned-loopback transport fixture")
}
