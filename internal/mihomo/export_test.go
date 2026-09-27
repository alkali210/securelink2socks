package mihomo

import (
	"bytes"
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"securelink2socks/internal/acl"
)

func options() Options {
	return Options{Remote: netip.MustParseAddrPort("203.0.113.9:10000"), Listen: netip.MustParseAddrPort("127.0.0.1:1080"), GeneratedAt: time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)}
}
func policy(t *testing.T, raw string) *acl.Snapshot {
	t.Helper()
	p, err := acl.ParsePush(raw)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestExportDeterministicAndConstrained(t *testing.T) {
	rules := []string{
		"app [addr:192.0.2.5/24][proto:any port:443;80]",
		"app [domain:*.example.invalid][proto:tcp port:443]",
		"app [domain:exact.invalid][proto:tcp port:any]",
		"app [domain:ip.xmu.edu.cn][proto:tcp port:443]",
		"app [domain:192.0.2.10][proto:tcp port:8080]",
	}
	a, err := Render(policy(t, strings.Join(rules, ",")), options())
	if err != nil {
		t.Fatal(err)
	}
	b, err := Render(policy(t, strings.Join([]string{rules[4], rules[3], rules[2], rules[1], rules[0], rules[1]}, ",")), options())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("rule order/duplicates changed output")
	}
	text := string(a)
	for _, want := range []string{"DST-PORT,443", "DST-PORT,80", "IP-CIDR,192.0.2.0/24,no-resolve", "NOT,((DOMAIN,example.invalid))", "ip4.xmu.edu.cn: ip.xmu.edu.cn", "DOMAIN,ip4.xmu.edu.cn", "MATCH,DIRECT", "port: 1080"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %s", want)
		}
	}
	lastAllow := strings.LastIndex(text, ",XMU")
	firstGuard := strings.Index(text, ",REJECT")
	if firstGuard < lastAllow {
		t.Fatal("guard masks a later overlapping grant")
	}
	if strings.Index(text, "DOMAIN,ids.xmu.edu.cn,DIRECT") > lastAllow {
		t.Fatal("SSO exception below ACL")
	}
	opt := options()
	opt.Fragment = true
	opt.Listen = netip.MustParseAddrPort("127.0.0.1:12345")
	fragment, err := Render(policy(t, rules[1]), opt)
	if err != nil {
		t.Fatal(err)
	}
	for _, unwanted := range []string{"mixed-port:", "MATCH,", "hosts:", "proxies: []"} {
		if strings.Contains(string(fragment), unwanted) {
			t.Fatalf("fragment contains %s", unwanted)
		}
	}
	if !strings.Contains(string(fragment), "port: 12345") {
		t.Fatal("listener override lost")
	}
}

func TestWritePreservesExistingOnFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.yaml")
	original := []byte("existing user config")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	p := policy(t, "app [domain:allowed.invalid][proto:tcp port:443]")
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tc := range []struct {
		ctx    context.Context
		policy *acl.Snapshot
		opt    Options
	}{
		{context.Background(), nil, options()},
		{context.Background(), policy(t, "route 192.0.2.0 255.255.255.0"), options()},
		{canceled, p, options()},
		{context.Background(), p, Options{}},
	} {
		if err := Write(tc.ctx, path, tc.policy, tc.opt); err == nil {
			t.Fatal("invalid export succeeded")
		}
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, original) {
			t.Fatal("existing file damaged")
		}
	}
	for _, port := range []uint16{443, 8443} {
		next := policy(t, "app [domain:allowed.invalid][proto:tcp port:"+strconv.Itoa(int(port))+"]")
		if err := Write(context.Background(), path, next, options()); err != nil {
			t.Fatal(err)
		}
		expected, _ := Render(next, options())
		got, _ := os.ReadFile(path)
		if !bytes.Equal(got, expected) {
			t.Fatal("incomplete replacement")
		}
	}
	files, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(files) != 1 {
		t.Fatal("temporary file leaked")
	}
}

func TestRejectInvalidOptions(t *testing.T) {
	p := policy(t, "app [domain:allowed.invalid][proto:tcp port:any]")
	for _, address := range []string{"0.0.0.0:1080", "127.0.0.1:0", "[::1]:1080"} {
		opt := options()
		opt.Listen = netip.MustParseAddrPort(address)
		if _, err := Render(p, opt); err == nil {
			t.Fatal("accepted listener", address)
		}
	}
}
