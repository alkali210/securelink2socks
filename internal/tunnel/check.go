// SPDX-License-Identifier: AGPL-3.0-or-later
package tunnel

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"time"

	"github.com/n0madic/go-openvpn"
	"github.com/n0madic/go-openvpn/pkg/netstack"
	"securelink2socks/internal/acl"
	"securelink2socks/internal/securelink"
)

type Report struct {
	Transport    string `json:"transport"`
	Remote       string `json:"remote"`
	Cipher       string `json:"cipher"`
	IPv4         string `json:"ipv4"`
	ACLRules     int    `json:"acl_rules"`
	TCPConnected bool   `json:"tcp_connected"`
}

// Check performs one opt-in userspace handshake and optional authorized TCP
// connect. It creates no host interface, route, DNS configuration or listener.
func Check(ctx context.Context, profile securelink.Profile, target netip.AddrPort) (Report, error) {
	var report Report
	parsed, err := profile.Parse()
	if err != nil {
		return report, err
	}
	cfg := parsed.Config
	cfg.AutoReconnect = false
	// Upstream logs may contain raw pushes and server-provided auth errors.
	// Diagnostic output below is an explicit allowlist instead.
	cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	handshakeCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	cli, err := openvpn.Dial(handshakeCtx, cfg)
	if err != nil {
		if ctx.Err() != nil {
			return report, ctx.Err()
		}
		return report, errors.New("OpenVPN handshake failed (server details withheld)")
	}
	defer cli.Close()
	pr := cli.PushedOptions()
	report.Transport = cfg.Network
	report.Remote = cli.UnderlayRemoteAddr().String()
	report.Cipher = pr.Cipher
	if !pr.LocalIP.Is4() {
		return report, errors.New("VPN did not assign IPv4")
	}
	report.IPv4 = pr.LocalIP.String()
	switch pr.Cipher {
	case "AES-128-GCM", "AES-256-GCM", "CHACHA20-POLY1305":
	default:
		return report, errors.New("VPN did not negotiate supported AEAD")
	}
	snapshot, err := acl.ParsePush(pr.Raw)
	if err != nil {
		return report, err
	}
	report.ACLRules = snapshot.Len()
	if snapshot.Len() == 0 {
		return report, errors.New("no usable app ACL; traffic denied")
	}
	stack, err := netstack.New(cli)
	if err != nil {
		return report, errors.New("userspace stack creation failed")
	}
	defer stack.Close()
	if !target.IsValid() {
		return report, nil
	}
	if !snapshot.AllowsTCP(target) {
		return report, errors.New("target denied by SecureLink ACL")
	}
	dialCtx, stop := context.WithTimeout(ctx, 10*time.Second)
	defer stop()
	conn, err := stack.DialContext(dialCtx, "tcp4", target.String())
	if err != nil {
		return report, errors.New("authorized userspace TCP connection failed")
	}
	defer conn.Close()
	report.TCPConnected = true
	return report, nil
}
