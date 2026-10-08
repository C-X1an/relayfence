// Package relayfence implements bounded, revision-fenced outbound tunnels.
package relayfence

import (
	"context"
	"errors"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

var (
	ErrInvalid     = errors.New("bad_request")
	ErrDenied      = errors.New("policy_denied")
	ErrCapacity    = errors.New("capacity_exceeded")
	ErrUnavailable = errors.New("unavailable")
	ErrStale       = errors.New("stale_session")
	ErrAddress     = errors.New("address_denied")
	ErrBudget      = errors.New("byte_budget_exhausted")
)

// Authority accepts a deliberately narrow DNS-name:port grammar. IP literals,
// Unicode, URI syntax and ambiguous numeric forms are not part of this API.
func Authority(raw string) (host, canonical string, err error) {
	// Check the wire grammar before Unicode case folding can turn a non-ASCII
	// code point into an ASCII letter (for example the Kelvin sign into k).
	for i := 0; i < len(raw); i++ {
		if raw[i] >= 0x80 {
			return "", "", ErrInvalid
		}
	}
	if len(raw) > 260 || strings.ContainsAny(raw, "[]/@%?#\\\r\n\t ") || strings.Count(raw, ":") != 1 {
		return "", "", ErrInvalid
	}
	parts := strings.SplitN(raw, ":", 2)
	host = strings.ToLower(strings.TrimSuffix(parts[0], "."))
	port := parts[1]
	if host == "" || len(host) > 253 || port == "" || (len(port) > 1 && port[0] == '0') {
		return "", "", ErrInvalid
	}
	for _, c := range port {
		if c < '0' || c > '9' {
			return "", "", ErrInvalid
		}
	}
	n, e := strconv.Atoi(port)
	if e != nil || n < 1 || n > 65535 {
		return "", "", ErrInvalid
	}
	numeric := true
	for _, c := range host {
		if (c < '0' || c > '9') && c != '.' {
			numeric = false
		}
	}
	if numeric || strings.HasPrefix(host, "0x") {
		return "", "", ErrInvalid
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", "", ErrInvalid
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') && c != '-' {
				return "", "", ErrInvalid
			}
		}
	}
	return host, host + ":" + port, nil
}

var deniedPrefixes = func() []netip.Prefix {
	// Conservative selection of special-purpose address blocks. Some globally
	// reachable special services are intentionally denied (see architecture).
	raw := []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20"}
	out := make([]netip.Prefix, 0, len(raw))
	for _, p := range raw {
		out = append(out, netip.MustParsePrefix(p))
	}
	return out
}()
var ipv6Global = netip.MustParsePrefix("2000::/3")

// PublicAddress is a conservative policy classifier, not a routability oracle.
func PublicAddress(ip netip.Addr) bool {
	if !ip.IsValid() || ip.Zone() != "" {
		return false
	}
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() {
		return false
	}
	if ip.Is6() && !ipv6Global.Contains(ip) {
		return false
	}
	for _, p := range deniedPrefixes {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

type Resolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

func resolveChecked(ctx context.Context, resolver Resolver, host string, labLoopback bool) ([]netip.Addr, error) {
	ips, err := resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 || len(ips) > 16 {
		return nil, ErrAddress
	}
	seen := map[netip.Addr]bool{}
	valid := make([]netip.Addr, 0, len(ips))
	for _, original := range ips {
		ip := original.Unmap()
		allowed := PublicAddress(original) || (labLoopback && original.Zone() == "" && ip.IsLoopback())
		if !allowed {
			return nil, ErrAddress
		} // MUTATION_POINT_IP
		if !seen[ip] {
			valid = append(valid, ip)
			seen[ip] = true
		}
	}
	sort.Slice(valid, func(i, j int) bool { return valid[i].Compare(valid[j]) < 0 })
	return valid, nil
}
