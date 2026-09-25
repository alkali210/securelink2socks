// SPDX-License-Identifier: AGPL-3.0-or-later
package tunnel

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/n0madic/go-openvpn"
	"github.com/n0madic/go-openvpn/pkg/netstack"
	"securelink2socks/internal/acl"
	"securelink2socks/internal/securelink"
)

type Session struct {
	client *openvpn.Client
	stack  *netstack.Net
	acl    *acl.Snapshot
	once   sync.Once
}

func (s *Session) AllowsTCP(target netip.AddrPort) bool { return s.acl.AllowsTCP(target) }
func (s *Session) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return s.stack.DialContext(ctx, network, address)
}
func (s *Session) Done() <-chan struct{} { return s.client.SessionDone() }
func (s *Session) Err() error {
	err := s.client.SessionError()
	if errors.Is(err, openvpn.ErrAuthFailed) {
		return ErrVPNAuthRejected
	}
	return errors.New("VPN session disconnected")
}
func (s *Session) Close() error { s.once.Do(func() { s.stack.Close(); s.client.Close() }); return nil }

// Open returns only a complete, verified userspace tunnel with a nonempty ACL.
// The caller owns the session; canceling the handshake context doesn't close it.
func Open(ctx context.Context, profile securelink.Profile) (result *Session, report Report, err error) {
	parsed, err := profile.ParseXMU()
	if err != nil {
		return nil, report, err
	}
	cfg := parsed.Config
	cfg.AutoReconnect = false
	cfg.RestartOnPush = true
	cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	progress := &handshakeProgress{}
	cfg.HandshakeTracer = progress
	report.Transport = cfg.Network
	report.Remote = cfg.RemoteAddr
	dialCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	cli, err := openvpn.Dial(dialCtx, cfg)
	report.Stage = progress.stage()
	if err != nil {
		if errors.Is(err, openvpn.ErrAuthFailed) {
			return nil, report, ErrVPNAuthRejected
		}
		return nil, report, errors.New("OpenVPN handshake failed: " + handshakeReason(err))
	}
	defer func() {
		if result == nil {
			cli.Close()
		}
	}()
	pr := cli.PushedOptions()
	report.Cipher = pr.Cipher
	if !pr.LocalIP.Is4() {
		return nil, report, errors.New("VPN did not assign IPv4")
	}
	report.IPv4 = pr.LocalIP.String()
	switch pr.Cipher {
	case "AES-128-GCM", "AES-256-GCM", "CHACHA20-POLY1305":
	default:
		return nil, report, errors.New("VPN did not negotiate supported AEAD")
	}
	snapshot, err := acl.ParsePush(pr.Raw)
	if err != nil {
		return nil, report, err
	}
	report.ACLRules = snapshot.Len()
	if snapshot.Len() == 0 {
		return nil, report, errors.New("no usable app ACL; traffic denied")
	}
	verifyCtx, stop := context.WithTimeout(ctx, 12*time.Second)
	defer stop()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for !report.DataChannelVerified {
		stats := cli.Stats()
		if stats.PingIn > 0 || stats.Forwarded > 0 {
			report.DataChannelVerified = true
			break
		}
		select {
		case <-verifyCtx.Done():
			return nil, report, errors.New("no authenticated VPN data received before verification timeout")
		case <-cli.SessionDone():
			return nil, report, errors.New("VPN disconnected before data verification")
		case <-tick.C:
		}
	}
	stack, err := netstack.New(cli)
	if err != nil {
		return nil, report, errors.New("userspace stack creation failed")
	}
	result = &Session{client: cli, stack: stack, acl: snapshot}
	return result, report, nil
}
