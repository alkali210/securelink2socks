package gateway

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

type fakeTunnel struct {
	done  chan struct{}
	once  sync.Once
	allow bool
	dial  func(context.Context) (net.Conn, error)
	calls int
}

func (f *fakeTunnel) Done() <-chan struct{}         { return f.done }
func (f *fakeTunnel) Err() error                    { return errors.New("disconnected") }
func (f *fakeTunnel) Close() error                  { f.once.Do(func() { close(f.done) }); return nil }
func (f *fakeTunnel) AllowsTCP(netip.AddrPort) bool { return f.allow }
func (f *fakeTunnel) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	f.calls++
	return f.dial(ctx)
}
func TestRevocationClosesConnectionsAndDeniesNewDials(t *testing.T) {
	b := &Backend{}
	if _, e := b.DialContext(t.Context(), "tcp4", "192.0.2.1:443"); !errors.Is(e, ErrUnavailable) {
		t.Fatal(e)
	}
	a, peer := net.Pipe()
	defer peer.Close()
	f := &fakeTunnel{done: make(chan struct{}), allow: true, dial: func(context.Context) (net.Conn, error) { return a, nil }}
	b.Replace(f)
	c, e := b.DialContext(t.Context(), "tcp4", "192.0.2.1:443")
	if e != nil {
		t.Fatal(e)
	}
	b.Replace(nil)
	if b.Ready() {
		t.Fatal("ready after revoke")
	}
	peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, e = peer.Read(make([]byte, 1)); !errors.Is(e, io.EOF) {
		t.Fatal("old connection did not close", e)
	}
	c.Close()
	f2 := &fakeTunnel{done: make(chan struct{}), allow: false}
	b.Replace(f2)
	defer b.Replace(nil)
	if _, e = b.DialContext(t.Context(), "tcp4", "192.0.2.1:443"); !errors.Is(e, ErrDenied) || f2.calls != 0 {
		t.Fatal("denied target dialed")
	}
}

func TestLateDialCannotJoinNewGeneration(t *testing.T) {
	b := &Backend{}
	entered, release := make(chan struct{}), make(chan struct{})
	c, peer := net.Pipe()
	defer peer.Close()
	f := &fakeTunnel{done: make(chan struct{}), allow: true, dial: func(context.Context) (net.Conn, error) { close(entered); <-release; return c, nil }}
	b.Replace(f)
	result := make(chan error, 1)
	go func() {
		conn, e := b.DialContext(t.Context(), "tcp4", "192.0.2.1:443")
		if conn != nil {
			conn.Close()
		}
		result <- e
	}()
	<-entered
	b.Replace(&fakeTunnel{done: make(chan struct{}), allow: false})
	defer b.Replace(nil)
	close(release)
	select {
	case e := <-result:
		if !errors.Is(e, ErrUnavailable) {
			t.Fatal("late connection published", e)
		}
	case <-time.After(time.Second):
		t.Fatal("late dial stuck")
	}
	peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, e := peer.Read(make([]byte, 1)); !errors.Is(e, io.EOF) {
		t.Fatal("late connection leaked", e)
	}
}
func TestReplacementCancelsInflightDial(t *testing.T) {
	b := &Backend{}
	entered := make(chan struct{})
	f := &fakeTunnel{done: make(chan struct{}), allow: true, dial: func(ctx context.Context) (net.Conn, error) { close(entered); <-ctx.Done(); return nil, ctx.Err() }}
	b.Replace(f)
	done := make(chan error, 1)
	go func() { _, e := b.DialContext(t.Context(), "tcp4", "192.0.2.1:443"); done <- e }()
	<-entered
	b.Replace(nil)
	select {
	case e := <-done:
		if !errors.Is(e, ErrUnavailable) {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("dial not canceled")
	}
}

// Domain lookups/dials must not survive replacement of their ACL generation.
type domainTunnel struct {
	*fakeTunnel
	domainDial func(context.Context) (net.Conn, error)
}

func (f *domainTunnel) DialDomainContext(ctx context.Context, host string, port uint16) (net.Conn, error) {
	return f.domainDial(ctx)
}
func TestReplacementCancelsDomainResolution(t *testing.T) {
	b := &Backend{}
	entered := make(chan struct{})
	f := &domainTunnel{fakeTunnel: &fakeTunnel{done: make(chan struct{})}, domainDial: func(ctx context.Context) (net.Conn, error) { close(entered); <-ctx.Done(); return nil, ctx.Err() }}
	b.Replace(f)
	defer b.Replace(nil)
	done := make(chan error, 1)
	go func() { _, err := b.DialContext(t.Context(), "tcp4", "allowed.example:443"); done <- err }()
	<-entered
	b.Replace(nil)
	select {
	case err := <-done:
		if !errors.Is(err, ErrUnavailable) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("old DNS lookup not canceled")
	}
}
