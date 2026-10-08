package relayfence

import (
	"errors"

	"strings"

	"crypto/tls"
	"testing"

	"context"
	"net/http"
	"net/netip"
	"time"

	"bufio"
	"fmt"

	"io"
)

func TestAuthority(t *testing.T) {
	valid := map[string]string{"Example.COM:443": "example.com:443", "example.com.:443": "example.com:443", "xn--bcher-kva.example:8443": "xn--bcher-kva.example:8443", "a:1": "a:1"}
	for input, want := range valid {
		t.Run(input, func(t *testing.T) {
			host, got, e := Authority(input)
			if e != nil || got != want || host == "" {
				t.Fatalf("got %q %q %v", host, got, e)
			}
		})
	}
	for _, input := range []string{"127.0.0.1:443", "2130706433:443", "0x7f000001:443", "[::1]:443", "a:0443", "a:0", "a:65536", "a:443/", "a:443?x", "user@a:443", "a%2ecom:443", "a..b:443", "-a:443", "a-:443", "a:443\r\nX: y", "a:443 ", "a:443:5", "a..:443", "a", "a:", "https://a:443", "b\u00fccher.example:443", strings.Repeat("a", 64) + ":443"} {
		t.Run(fmt.Sprintf("invalid_%q", input), func(t *testing.T) {
			if _, _, e := Authority(input); e == nil {
				t.Fatalf("accepted %q", input)
			}
		})
	}
}
func TestPublicAddress(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "10.2.3.4", "172.31.255.254", "192.168.4.2", "169.254.169.254", "100.100.100.200", "0.0.0.0", "192.0.0.9", "198.18.0.1", "192.0.2.1", "198.51.100.1", "203.0.113.1", "224.0.0.1", "240.0.0.1", "::1", "::", "fe80::1", "fc00::1", "::ffff:127.0.0.1", "64:ff9b::7f00:1", "2001:db8::1", "2002:7f00:1::", "3fff::1", "fe80::1%eth0"} {
		if PublicAddress(netip.MustParseAddr(ip)) {
			t.Errorf("unsafe address accepted: %s", ip)
		}
	}
	for _, ip := range []string{"8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111", "::ffff:8.8.8.8"} {
		if !PublicAddress(netip.MustParseAddr(ip)) {
			t.Errorf("public address denied: %s", ip)
		}
	}
	if PublicAddress(netip.Addr{}) {
		t.Fatal("invalid address accepted")
	}
}
func TestMixedDNS(t *testing.T) {
	for _, answers := range [][]netip.Addr{{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("127.0.0.1")}, {netip.MustParseAddr("::ffff:10.0.0.1")}, nil, make([]netip.Addr, 17)} {
		resolver := resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) { return answers, nil })
		if _, e := resolveChecked(context.Background(), resolver, "example.test", false); !errors.Is(e, ErrAddress) {
			t.Fatalf("answers %v: %v", answers, e)
		}
	}
	calls := 0
	resolver := resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		calls++
		return []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("8.8.8.8")}, nil
	})
	ips, e := resolveChecked(context.Background(), resolver, "example.test", false)
	if e != nil || calls != 1 || len(ips) != 2 || ips[0].String() != "1.1.1.1" {
		t.Fatalf("dedup/sort/resolution: %v %v calls=%d", ips, e, calls)
	}
}

func FuzzAuthority(f *testing.F) {
	for _, s := range []string{"example.test:443", "127.0.0.1:443", "[::1]:443", "a.:1", "a..:1", "\x00"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		host, canonical, e := Authority(s)
		if e != nil {
			return
		}
		if host == "" || !strings.HasPrefix(canonical, host+":") {
			t.Fatal("invalid canonical result")
		}
		h2, c2, e2 := Authority(canonical)
		if e2 != nil || h2 != host || c2 != canonical {
			t.Fatal("canonicalization not idempotent")
		}
	})
}

func BenchmarkAuthority(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, _, e := Authority("api.example.com:443"); e != nil {
			b.Fatal(e)
		}
	}
}

// The original CONNECT target is authoritative; net/http has discarded raw Host.
func TestConnectRequestTargetAuthority(t *testing.T) {
	f := newFixture(t, echo, nil)
	config := &tls.Config{RootCAs: f.pki.pool, ServerName: "proxy.test", Certificates: []tls.Certificate{f.pki.client}, MinVersion: tls.VersionTLS13}
	c, e := tls.Dial("tcp", f.server.address, config)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	_, e = fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: forbidden.test:443\r\n\r\nauthority", f.destination)
	if e != nil {
		t.Fatal(e)
	}
	r := bufio.NewReader(c)
	response, e := http.ReadResponse(r, &http.Request{Method: http.MethodConnect})
	if e != nil || response.StatusCode != 200 {
		t.Fatalf("%v %v", response, e)
	}
	b := make([]byte, 9)
	if _, e = io.ReadFull(r, b); e != nil || string(b) != "authority" {
		t.Fatalf("original target did not receive payload: %q %v", b, e)
	}
}
