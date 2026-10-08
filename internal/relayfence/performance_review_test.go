package relayfence

import (
	"net/netip"
	"testing"
)

func BenchmarkPublicAddress(b *testing.B) {
	cases := []struct {
		name, address string
		allowed       bool
	}{
		{"public_ipv4", "8.8.8.8", true},
		{"private_ipv4", "10.0.0.1", false},
		{"public_ipv6", "2606:4700:4700::1111", true},
		{"mapped_loopback", "::ffff:127.0.0.1", false},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			address := netip.MustParseAddr(tc.address)
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if PublicAddress(address) != tc.allowed {
					b.Fatal("unexpected address decision")
				}
			}
		})
	}
}
