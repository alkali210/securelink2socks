package app

import (
	"context"
	"net"
	"net/netip"
	"securelink2socks/internal/gateway"
	"securelink2socks/internal/securelink"
	"sync"
	"testing"
	"time"
)

type testTunnel struct {
	done chan struct{}
	once sync.Once
}

func (t *testTunnel) Done() <-chan struct{}         { return t.done }
func (t *testTunnel) Err() error                    { return nil }
func (t *testTunnel) Close() error                  { t.once.Do(func() { close(t.done) }); return nil }
func (t *testTunnel) AllowsTCP(netip.AddrPort) bool { return false }
func (t *testTunnel) DialContext(context.Context, string, string) (net.Conn, error) {
	panic("unexpected dial")
}
func waitState(t *testing.T, states <-chan State, want State) {
	t.Helper()
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	for {
		select {
		case s := <-states:
			if s == want {
				return
			}
		case <-timer.C:
			t.Fatalf("missing state %s", want)
		}
	}
}
func TestReconnectAndShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	b := &gateway.Backend{}
	states := make(chan State, 20)
	first := &testTunnel{done: make(chan struct{})}
	second := &testTunnel{done: make(chan struct{})}
	attempt := 0
	s := &Supervisor{Backend: b, Notify: func(v State) { states <- v }, MinBackoff: time.Millisecond, MaxBackoff: time.Millisecond, Connect: func(context.Context) (gateway.Tunnel, error) {
		attempt++
		if attempt == 1 {
			return first, nil
		}
		return second, nil
	}}
	done := make(chan struct{})
	go func() { defer close(done); s.Run(ctx) }()
	waitState(t, states, Ready)
	first.Close()
	waitState(t, states, Reconnecting)
	waitState(t, states, Ready)
	if !b.Ready() {
		t.Fatal("new generation not ready")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("supervisor did not stop")
	}
	if b.Ready() {
		t.Fatal("ready after shutdown")
	}
}
func TestNeedsLoginDoesNotRetryUntilSignaled(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	states := make(chan State, 20)
	login := make(chan struct{})
	attempts := make(chan struct{}, 10)
	s := &Supervisor{Backend: &gateway.Backend{}, Notify: func(v State) { states <- v }, Connect: func(context.Context) (gateway.Tunnel, error) {
		attempts <- struct{}{}
		return nil, securelink.ErrNeedsLogin
	}, WaitLogin: func(ctx context.Context) {
		select {
		case <-ctx.Done():
		case <-login:
		}
	}}
	done := make(chan struct{})
	go func() { defer close(done); s.Run(ctx) }()
	waitState(t, states, NeedsLogin)
	<-attempts
	select {
	case <-attempts:
		t.Fatal("login failure spun")
	case <-time.After(30 * time.Millisecond):
	}
	login <- struct{}{}
	waitState(t, states, NeedsLogin)
	cancel()
	<-done
}
