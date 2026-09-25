package tunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"securelink2socks/internal/acl"
	"securelink2socks/internal/gateway"
	"strconv"
	"testing"
)

func TestDomainAuthorizationAndResolution(t *testing.T) {
	policy, err := acl.ParsePush("app [domain:allowed.example][proto:tcp port:443],app [addr:192.0.2.1/32][proto:tcp port:80]")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		host, ip string
		port     uint16
		allow    bool
	}{
		{"ALLOWED.EXAMPLE.", "198.51.100.1", 443, true},
		{"allowed.example", "198.51.100.1", 80, false},
		{"other.example", "198.51.100.1", 443, false},
		{"other.example", "192.0.2.1", 80, true},
		{"allowed.example", "127.0.0.1", 443, false},
		{"allowed.example", "::1", 443, false},
	} {
		t.Run(tc.host+tc.ip+strconv.Itoa(int(tc.port)), func(t *testing.T) {
			calls := 0
			conn, err := dialDomain(t.Context(), policy, tc.host, tc.port, func(context.Context, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr(tc.ip)}, nil
			}, func(_ context.Context, n, a string) (net.Conn, error) {
				calls++
				if n != "tcp4" || a != netip.AddrPortFrom(netip.MustParseAddr(tc.ip), tc.port).String() {
					t.Fatal("wrong destination")
				}
				x, y := net.Pipe()
				t.Cleanup(func() { x.Close(); y.Close() })
				return x, nil
			})
			if tc.allow {
				if err != nil || conn == nil || calls != 1 {
					t.Fatal("allowed request failed", err)
				}
			} else if !errors.Is(err, gateway.ErrDenied) || calls != 0 {
				t.Fatal("unauthorized dial", err, calls)
			}
		})
	}
	if policy.AllowsTCP(netip.MustParseAddrPort("198.51.100.1:443")) {
		t.Fatal("domain grant escaped to IP ACL")
	}
}

func TestVPNDNSUsesOnlyPushedServer(t *testing.T) {
	server := netip.MustParseAddr("192.0.2.53")
	ips, err := lookupIPv4(t.Context(), "localhost", []netip.Addr{server}, func(ctx context.Context, n, a string) (net.Conn, error) {
		if a != "192.0.2.53:53" || (n != "udp4" && n != "tcp4") {
			t.Errorf("unexpected DNS route %s %s", n, a)
		}
		client, remote := net.Pipe()
		go func() {
			defer remote.Close()
			q := make([]byte, 4096)
			n, err := remote.Read(q)
			if err != nil {
				return
			}
			q = q[:n]
			if len(q) < 17 {
				return
			}
			// Copy only the question (the resolver can append an EDNS record).
			end := 12
			for end < len(q) && q[end] != 0 {
				end += int(q[end]) + 1
			}
			end += 5
			if end > len(q) {
				return
			}
			r := append([]byte(nil), q[:end]...)
			r[2] = 0x81
			r[3] = 0x80
			binary.BigEndian.PutUint16(r[6:8], 1)
			binary.BigEndian.PutUint16(r[10:12], 0)
			r = append(r, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 198, 51, 100, 7)
			remote.Write(r)
		}()
		return client, nil
	})
	if err != nil || len(ips) != 1 || ips[0].String() != "198.51.100.7" {
		t.Fatal(ips, err)
	}
	calls := 0
	_, err = lookupIPv4(t.Context(), "allowed.example", nil, func(context.Context, string, string) (net.Conn, error) { calls++; return nil, nil })
	if err == nil || calls != 0 {
		t.Fatal("missing VPN DNS fell back")
	}
}
