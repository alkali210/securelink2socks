package acl

import (
	"net/netip"
	"os"
	"testing"
)

func TestDocumentedRules(t *testing.T) {
	b, err := os.ReadFile("../../testdata/securelink/app.push.txt")
	if err != nil {
		t.Fatal(err)
	}
	s, err := ParsePush(string(b))
	if err != nil {
		t.Fatal(err)
	}
	if s.Len() != 3 {
		t.Fatal("wrong rule count")
	}
	for _, tc := range []struct {
		addr  string
		allow bool
	}{
		{"192.0.2.10:443", true}, {"192.0.2.11:443", false}, {"198.51.100.20:21", true}, {"198.51.100.20:22", false},
		{"203.0.113.0:65535", true}, {"203.0.113.3:1", true}, {"203.0.113.4:80", false}, {"203.0.113.2:0", false}, {"[::ffff:192.0.2.10]:443", false},
	} {
		if got := s.AllowsTCP(netip.MustParseAddrPort(tc.addr)); got != tc.allow {
			t.Errorf("%s got %v", tc.addr, got)
		}
	}
}

func TestInvalidRuleInvalidatesWholeSnapshot(t *testing.T) {
	valid := "app [addr:192.0.2.1/32][proto:any] [port:any],"
	for _, rule := range []string{
		"app", "app [addr:nope][proto:any] [port:any]", "app [addr:192.0.2.1/33][proto:any] [port:any]",
		"app [addr:192.0.2.1/32][proto:udp] [port:any]",
		"app [addr:192.0.2.1/32][proto:unknown] [port:any]", "app [addr:192.0.2.1/32][proto:any] [port:0]",
		"app [addr:192.0.2.1/32][proto:any] [port:65536]", "app [addr:192.0.2.1/32][proto:any] [port:80-90]",
		"app [addr:192.0.2.1/32][proto:any] [port:+80]", "app [addr:::1/128][proto:any] [port:any]",
		"app [addr:192.0.2.1/32][proto:any] [port:80] extra", "app [addr:192.0.2.1/32][proto:any] [port:80,443]",
	} {
		if s, err := ParsePush(valid + rule); err == nil || s != nil {
			t.Errorf("accepted %q", rule)
		}
	}
}

func TestLiveGrammarWithSyntheticAddresses(t *testing.T) {
	fixture, err := os.ReadFile("../../testdata/securelink/app-live-shape.push.txt")
	if err != nil {
		t.Fatal(err)
	}
	if parsed, err := ParsePush(string(fixture)); err != nil || parsed.Len() != 3 {
		t.Fatal("live-shape fixture rejected")
	}
	s, err := ParsePush("app [addr:192.0.2.10/32][proto:tcp port:443;8443],app [domain:example.invalid][proto:any port:any],app [addr:198.51.100.0/24][proto:any port:22]")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		target string
		allow  bool
	}{
		{"192.0.2.10:443", true}, {"192.0.2.10:8443", true}, {"192.0.2.10:80", false},
		{"192.0.2.11:443", false}, {"198.51.100.20:22", true}, {"198.51.100.20:443", false},
		{"203.0.113.1:443", false},
	} {
		if s.AllowsTCP(netip.MustParseAddrPort(tc.target)) != tc.allow {
			t.Errorf("wrong decision for %s", tc.target)
		}
	}
	for _, ports := range []string{"443;", ";443", "443;;8443", "any;443", "443;0", "443;65536", "443;80-90"} {
		if s, err := ParsePush("app [addr:192.0.2.10/32][proto:tcp port:" + ports + "]"); err == nil || s != nil {
			t.Fatal("accepted malformed list")
		}
	}
}

func TestEmptyAndDeduplication(t *testing.T) {
	for _, raw := range []string{"", "cipher AES-256-GCM"} {
		s, err := ParsePush(raw)
		if err != nil || s.Len() != 0 || s.AllowsTCP(netip.MustParseAddrPort("192.0.2.1:80")) {
			t.Fatal("missing ACL allowed traffic")
		}
	}
	s, err := ParsePush("app [addr:192.0.2.5/24][proto:any] [port:80],app [addr:192.0.2.0/24][proto:any] [port:80]")
	if err != nil || s.Len() != 1 || !s.AllowsTCP(netip.MustParseAddrPort("192.0.2.255:80")) {
		t.Fatal("prefix normalization/deduplication failed")
	}
	var absent *Snapshot
	if absent.AllowsTCP(netip.MustParseAddrPort("192.0.2.1:80")) {
		t.Fatal("nil ACL allowed traffic")
	}
}

func FuzzParsePush(f *testing.F) {
	f.Add("app [addr:192.0.2.1/32][proto:any] [port:443]")
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 8192 {
			t.Skip()
		}
		snapshot, err := ParsePush(s)
		if err != nil && snapshot != nil {
			t.Fatal("invalid snapshot published")
		}
	})
}
