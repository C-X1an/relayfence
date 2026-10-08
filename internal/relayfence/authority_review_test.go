package relayfence

import "testing"

func TestAuthorityRejectsUnicode(t *testing.T) {
	for _, authority := range []string{"\u212a.test:443", "api.\u212A.test:443", "\u0130.test:443", "\u017f.test:443", "\uff2b.test:443", "k.test:\uff14\uff14\uff13"} {
		t.Run(authority, func(t *testing.T) {
			if _, _, err := Authority(authority); err == nil {
				t.Fatalf("non-ASCII authority accepted: %q", authority)
			}
		})
	}
	if _, canonical, err := Authority("K.TEST.:443"); err != nil || canonical != "k.test:443" {
		t.Fatalf("ASCII case/root-dot normalization changed: %q %v", canonical, err)
	}
	policy := labPolicy("\u212a.test:443")
	if _, err := policy.Validate(); err == nil {
		t.Fatal("non-ASCII policy destination accepted")
	}
}
