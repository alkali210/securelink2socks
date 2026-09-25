// SPDX-License-Identifier: AGPL-3.0-or-later
package gateway

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"

	"securelink2socks/internal/acl"
)

var ErrUnavailable = errors.New("VPN unavailable")
var ErrDenied = errors.New("destination denied by ACL")

type Tunnel interface {
	DialContext(context.Context, string, string) (net.Conn, error)
	AllowsTCP(netip.AddrPort) bool
	Done() <-chan struct{}
	Err() error
	Close() error
}

// Backend publishes a complete tunnel/ACL generation under one lock. Replacing
// it cancels pending dials and closes all connections authorized by the old ACL.
type Backend struct {
	mu      sync.Mutex
	current *generation
}
type generation struct {
	tunnel Tunnel
	ctx    context.Context
	cancel context.CancelFunc
	conns  map[*trackedConn]struct{}
}

func alive(t Tunnel) bool {
	select {
	case <-t.Done():
		return false
	default:
		return true
	}
}

func (b *Backend) Ready() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.current != nil && alive(b.current.tunnel)
}

// Replace also closes the previous Tunnel. Pass nil to immediately fail closed.
func (b *Backend) Replace(t Tunnel) {
	b.mu.Lock()
	old := b.current
	b.current = nil
	var conns []*trackedConn
	if old != nil {
		old.cancel()
		for c := range old.conns {
			conns = append(conns, c)
		}
	}
	if t != nil {
		ctx, cancel := context.WithCancel(context.Background())
		b.current = &generation{tunnel: t, ctx: ctx, cancel: cancel, conns: make(map[*trackedConn]struct{})}
	}
	b.mu.Unlock()
	for _, c := range conns {
		c.Close()
	}
	if old != nil {
		old.tunnel.Close()
	}
}

func (b *Backend) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	target, err := netip.ParseAddrPort(address)
	var host string
	var port uint64
	if network != "tcp4" {
		return nil, ErrDenied
	}
	domain := err != nil
	if domain {
		var rawPort string
		host, rawPort, err = net.SplitHostPort(address)
		if err != nil {
			return nil, ErrDenied
		}
		var ok bool
		host, ok = acl.CanonicalDomain(host)
		port, err = strconv.ParseUint(rawPort, 10, 16)
		if !ok || err != nil || port == 0 {
			return nil, ErrDenied
		}
	} else if !target.Addr().Is4() || target.Port() == 0 {
		return nil, ErrDenied
	}
	b.mu.Lock()
	g := b.current
	if g == nil || !alive(g.tunnel) {
		b.mu.Unlock()
		return nil, ErrUnavailable
	}
	if !domain && !g.tunnel.AllowsTCP(target) {
		b.mu.Unlock()
		return nil, ErrDenied
	}
	b.mu.Unlock()
	dialCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(g.ctx, cancel)
	defer cancel()
	defer stop()
	var conn net.Conn
	if domain {
		if dt, ok := g.tunnel.(interface {
			DialDomainContext(context.Context, string, uint16) (net.Conn, error)
		}); ok {
			conn, err = dt.DialDomainContext(dialCtx, host, uint16(port))
		} else {
			err = ErrDenied
		}
	} else {
		conn, err = g.tunnel.DialContext(dialCtx, "tcp4", target.String())
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.current != g || !alive(g.tunnel) || g.ctx.Err() != nil || ctx.Err() != nil {
		if conn != nil {
			conn.Close()
		}
		return nil, ErrUnavailable
	}
	if err != nil {
		return nil, err
	}
	c := &trackedConn{Conn: conn, backend: b, g: g, done: make(chan struct{})}
	g.conns[c] = struct{}{}
	return c, nil
}

type trackedConn struct {
	net.Conn
	backend *Backend
	g       *generation
	once    sync.Once
	err     error
	done    chan struct{}
}

func (c *trackedConn) Close() error {
	c.once.Do(func() {
		close(c.done)
		c.err = c.Conn.Close()
		c.backend.mu.Lock()
		delete(c.g.conns, c)
		c.backend.mu.Unlock()
	})
	return c.err
}
func (c *trackedConn) Done() <-chan struct{} { return c.done }
func (c *trackedConn) CloseWrite() error {
	if v, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return v.CloseWrite()
	}
	return c.Close()
}
