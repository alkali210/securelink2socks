// SPDX-License-Identifier: AGPL-3.0-or-later
package tunnel

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"securelink2socks/internal/acl"
	"securelink2socks/internal/gateway"
)

// DNS is an internal session service, not a SOCKS UDP or general DNS listener.
// Only authenticated server-pushed resolver addresses may bypass app ACLs,
// and only for DNS on port 53 through this session's userspace stack.
func (s *Session) lookupIPv4(ctx context.Context, host string) ([]netip.Addr, error) {
	return lookupIPv4(ctx, host, s.dns, s.stack.DialContext)
}
func lookupIPv4(ctx context.Context, host string, servers []netip.Addr, dial func(context.Context, string, string) (net.Conn, error)) ([]netip.Addr, error) {
	for i, server := range servers {
		if i >= 4 {
			break
		}
		if !server.Is4() || !server.IsGlobalUnicast() {
			continue
		}
		queryCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		ips, err := resolveDNS(queryCtx, host, netip.AddrPortFrom(server, 53).String(), dial)
		cancel()
		if err == nil && len(ips) > 0 {
			return ips, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, errors.New("VPN DNS lookup failed")
}

func (s *Session) DialDomainContext(ctx context.Context, host string, port uint16) (net.Conn, error) {
	return dialDomain(ctx, s.acl, host, port, s.lookupIPv4, s.stack.DialContext)
}

func dialDomain(ctx context.Context, policy *acl.Snapshot, host string, port uint16,
	lookup func(context.Context, string) ([]netip.Addr, error),
	dial func(context.Context, string, string) (net.Conn, error)) (net.Conn, error) {
	host, ok := acl.CanonicalDomain(host)
	if !ok || port == 0 || policy == nil {
		return nil, gateway.ErrDenied
	}
	domainAllowed := policy.AllowsDomainTCP(host, port)
	ips, err := lookup(ctx, host)
	if err != nil {
		return nil, err
	}
	last := error(gateway.ErrDenied)
	for i, ip := range ips {
		if i >= 16 {
			break
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if !ip.Is4() || !ip.IsGlobalUnicast() {
			continue
		}
		target := netip.AddrPortFrom(ip, port)
		if !domainAllowed && !policy.AllowsTCP(target) {
			continue
		}
		conn, err := dial(ctx, "tcp4", target.String())
		if err == nil {
			return conn, nil
		}
		last = err
	}
	return nil, last
}
