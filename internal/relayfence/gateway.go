package relayfence

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

type Dialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}
type Gateway struct {
	Store       *Store
	Resolver    Resolver
	Dialer      Dialer
	Audit       Audit
	DNSTimeout  time.Duration
	DialTimeout time.Duration
	labLoopback bool // only the in-process synthetic demo can opt into loopback
}

func NewGateway(store *Store, audit Audit) (*Gateway, error) {
	if store == nil || audit == nil {
		return nil, ErrInvalid
	}
	return &Gateway{Store: store, Resolver: net.DefaultResolver, Dialer: &net.Dialer{Timeout: 3 * time.Second}, Audit: audit, DNSTimeout: 3 * time.Second, DialTimeout: 3 * time.Second}, nil
}
func TLSConfig(cert tls.Certificate, clientCA *x509.CertPool) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, ClientCAs: clientCA, ClientAuth: tls.RequireAndVerifyClientCert, NextProtos: []string{"http/1.1"}}
}
func HTTPServer(g *Gateway, config *tls.Config) *http.Server {
	return &http.Server{Handler: g, TLSConfig: config, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 8 << 10, TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){}}
}
func identity(r *http.Request) (string, error) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return "", ErrDenied
	}
	uris := r.TLS.VerifiedChains[0][0].URIs
	if len(uris) != 1 || !ValidIdentity(uris[0].String()) {
		return "", ErrDenied
	}
	return uris[0].String(), nil
}
func errorJSON(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Connection", "close")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code}})
}
func (g *Gateway) deny(w http.ResponseWriter, status int, code, id, dest string, session *Session) {
	event := Event{Kind: "denied", Identity: id, Destination: dest, Reason: code}
	if session != nil {
		event.Session = session.ID
		event.Revision = session.Revision
	}
	if err := g.Audit.Record(event); err != nil {
		g.Store.Poison()
		status = http.StatusServiceUnavailable
		code = "unavailable"
	}
	errorJSON(w, status, code)
}
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		g.deny(w, 405, "method_not_allowed", "", "", nil)
		return
	}
	id, err := identity(r)
	if err != nil {
		g.deny(w, 403, "identity_denied", "", "", nil)
		return
	}
	host, dest, err := Authority(r.RequestURI)
	if err != nil || r.ContentLength > 0 || len(r.TransferEncoding) > 0 {
		g.deny(w, 400, "bad_request", id, "", nil)
		return
	}
	session, err := g.Store.Reserve(r.Context(), id, dest)
	if err != nil {
		code := 403
		if errors.Is(err, ErrCapacity) {
			code = 429
		}
		if errors.Is(err, ErrUnavailable) {
			code = 503
		}
		g.deny(w, code, err.Error(), id, dest, nil)
		return
	}
	defer session.Release()
	go func() { <-session.Context.Done(); session.Close() }()
	dnsCtx, cancelDNS := context.WithTimeout(session.Context, g.DNSTimeout)
	ips, err := resolveChecked(dnsCtx, g.Resolver, host, g.labLoopback)
	cancelDNS()
	if err != nil {
		status := 502
		code := "upstream_failed"
		if errors.Is(err, ErrAddress) {
			status = 403
			code = "address_denied"
		}
		g.deny(w, status, code, id, dest, session)
		return
	}
	port := dest[strings.LastIndex(dest, ":")+1:]
	dialCtx, cancelDial := context.WithTimeout(session.Context, g.DialTimeout)
	upstream, err := g.Dialer.DialContext(dialCtx, "tcp", net.JoinHostPort(ips[0].String(), port))
	cancelDial()
	if err != nil {
		g.deny(w, 502, "upstream_failed", id, dest, session)
		return
	}
	defer closeTransport(upstream)
	if err = g.Store.Attach(session, upstream); err != nil {
		g.deny(w, 409, "stale_session", id, dest, session)
		return
	}
	event := Event{Kind: "allowed", Session: session.ID, Identity: id, Destination: dest, IP: ips[0].String(), Revision: session.Revision}
	if err = g.Audit.Record(event); err != nil {
		g.Store.Poison()
		errorJSON(w, 503, "unavailable")
		return
	}
	if session.Context.Err() != nil {
		g.deny(w, 409, "stale_session", id, dest, session)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		g.deny(w, 500, "unavailable", id, dest, session)
		return
	}
	client, buffer, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer closeTransport(client)
	if err = g.Store.Attach(session, client); err != nil {
		return
	}
	if err = client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return
	}
	if _, err = fmt.Fprint(buffer, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err = buffer.Flush(); err != nil {
		return
	}
	deadline, _ := session.Context.Deadline()
	if err = client.SetDeadline(deadline); err != nil {
		return
	}
	if err = upstream.SetDeadline(deadline); err != nil {
		return
	}
	// Drain only bytes buffered by net/http, then read the hijacked TLS
	// connection directly. Reading through its old connReader after EOF can
	// cancel the HTTP context and destroy a valid half-closed response.
	reader := bufio.NewReader(io.MultiReader(io.LimitReader(buffer.Reader, int64(buffer.Reader.Buffered())), client))
	bytes, reason := relay(session, client, reader, upstream)
	event.Kind = "closed"
	event.Bytes = bytes
	event.Reason = reason
	if err = g.Audit.Record(event); err != nil {
		g.Store.Poison()
	}
}

type closeWriter interface{ CloseWrite() error }

func relay(session *Session, client net.Conn, reader *bufio.Reader, upstream net.Conn) (uint64, string) {
	budget := NewBudget(session.Limits.MaxBytes)
	var written atomic.Uint64
	var last atomic.Int64
	start := time.Now()
	results := make(chan error, 2)
	pump := func(dst net.Conn, src io.Reader) {
		buffer := make([]byte, 32<<10)
		for {
			n, readErr := src.Read(buffer)
			if n > 0 {
				permitted := budget.Take(n)
				if permitted == 0 {
					results <- ErrBudget
					return
				}
				offset := 0
				for offset < permitted {
					nw, writeErr := dst.Write(buffer[offset:permitted])
					if nw < 0 || nw > permitted-offset {
						results <- io.ErrShortWrite
						return
					}
					if nw > 0 {
						written.Add(uint64(nw))
						last.Store(time.Since(start).Nanoseconds())
						offset += nw
					}
					if writeErr != nil {
						results <- writeErr
						return
					}
					if nw == 0 {
						results <- io.ErrNoProgress
						return
					}
				}
				if permitted < n {
					results <- ErrBudget
					return
				}
			}
			if readErr != nil {
				if errors.Is(readErr, io.EOF) {
					if cw, ok := dst.(closeWriter); ok {
						if err := cw.CloseWrite(); err != nil {
							results <- err
							return
						}
					}
					results <- nil
				} else {
					results <- readErr
				}
				return
			}
			if n == 0 {
				results <- io.ErrNoProgress
				return
			}
		}
	}
	go pump(upstream, reader)
	go pump(client, upstream)
	idle := time.Duration(session.Limits.IdleTimeoutMS) * time.Millisecond
	interval := idle / 4
	if interval < time.Millisecond {
		interval = time.Millisecond
	}
	if interval > 100*time.Millisecond {
		interval = 100 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	tick := ticker.C
	done := session.Context.Done()
	reason := "eof"
	for completed := 0; completed < 2; {
		select {
		case err := <-results:
			completed++
			if err != nil && reason == "eof" {
				if errors.Is(err, ErrBudget) {
					reason = "byte_budget"
				} else {
					reason = "io_error"
				}
				session.Close()
			}
		case <-done:
			if reason == "eof" {
				if errors.Is(session.Context.Err(), context.DeadlineExceeded) {
					reason = "lifetime"
				} else {
					reason = "cancelled"
				}
			}
			session.Close()
			done = nil
		case <-tick:
			if time.Since(start)-time.Duration(last.Load()) >= idle {
				if reason == "eof" {
					reason = "idle"
				}
				session.Close()
				tick = nil
			}
		}
	}
	return written.Load(), reason
}
