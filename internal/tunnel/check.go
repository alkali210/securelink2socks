// SPDX-License-Identifier: AGPL-3.0-or-later
package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/n0madic/go-openvpn"
	"securelink2socks/internal/securelink"
)

type Report struct {
	Stage               string `json:"stage,omitempty"`
	AEADProbe           bool   `json:"aead_probe,omitempty"`
	Transport           string `json:"transport"`
	Remote              string `json:"remote"`
	Cipher              string `json:"cipher"`
	IPv4                string `json:"ipv4"`
	ACLRules            int    `json:"acl_rules"`
	TCPConnected        bool   `json:"tcp_connected"`
	DataChannelVerified bool   `json:"data_channel_verified"`
}

var ErrVPNAuthRejected = errors.New("VPN authentication rejected")

// Check performs one opt-in userspace handshake and optional authorized TCP
// connect. It creates no host interface, route, DNS configuration or listener.
func Check(ctx context.Context, profile securelink.Profile, target netip.AddrPort) (Report, error) {
	return check(ctx, profile, target, false)
}

func CheckAEAD(ctx context.Context, profile securelink.Profile) (Report, error) {
	return check(ctx, profile, netip.AddrPort{}, true)
}

func check(ctx context.Context, profile securelink.Profile, target netip.AddrPort, experiment bool) (Report, error) {
	session, report, err := Open(ctx, profile)
	report.AEADProbe = experiment
	if err != nil {
		return report, err
	}
	defer session.Close()
	if !target.IsValid() {
		return report, nil
	}
	if !session.AllowsTCP(target) {
		return report, errors.New("target denied by SecureLink ACL")
	}
	dialCtx, stop := context.WithTimeout(ctx, 10*time.Second)
	defer stop()
	conn, err := session.DialContext(dialCtx, "tcp4", target.String())
	if err != nil {
		return report, errors.New("authorized userspace TCP connection failed")
	}
	defer conn.Close()
	report.TCPConnected = true
	return report, nil
}

type handshakeProgress struct {
	mu   sync.Mutex
	last string
}

func (p *handshakeProgress) OnHandshakeEvent(e openvpn.HandshakeEvent) {
	p.mu.Lock()
	p.last = e.Stage.String()
	p.mu.Unlock()
}
func (p *handshakeProgress) stage() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.last == "" {
		return "transport"
	}
	return p.last
}

func handshakeReason(err error) string {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return fmt.Sprintf("socket system error %d", uint64(errno))
	}
	var certErr *tls.CertificateVerificationError
	if errors.As(err, &certErr) {
		return "server certificate verification failed"
	}
	if errors.Is(err, openvpn.ErrAuthFailed) {
		message := strings.ToLower(err.Error())
		if strings.Contains(message, "cipher") && (strings.Contains(message, "negotiat") || strings.Contains(message, "shared")) {
			return "server rejected data-cipher negotiation"
		}
		if strings.Contains(message, "token") && (strings.Contains(message, "expir") || strings.Contains(message, "invalid")) {
			return "server rejected expired or invalid VPN token"
		}
		if strings.HasSuffix(err.Error(), ": AUTH_FAILED") {
			return "server rejected VPN authentication without a reason"
		}
		return "server rejected VPN authentication"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if errors.Is(err, io.EOF) {
		return "peer closed the connection"
	}
	if errors.Is(err, io.ErrClosedPipe) {
		return "control stream closed"
	}
	for _, item := range []struct{ match, reason string }{
		{"not a PUSH_REPLY message", "received a control message other than PUSH_REPLY"},
		{"control message too long", "server control message exceeds size limit"},
		{"control: unsupported data cipher", "server selected an unsupported data cipher"},
		{"PUSH_REPLY missing cipher", "PUSH_REPLY did not select a cipher"},
		{"control: read response", "could not read server control response"},
		{"control: parse PUSH_REPLY", "PUSH_REPLY could not be parsed"},
		{"context deadline exceeded", "timeout"},
	} {
		if strings.Contains(err.Error(), item.match) {
			return item.reason
		}
	}
	return "protocol/transport failure (server details withheld)"
}
