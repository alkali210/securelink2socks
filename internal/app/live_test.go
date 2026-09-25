package app_test

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"os"
	"securelink2socks/internal/app"
	"securelink2socks/internal/gateway"
	"securelink2socks/internal/socks"
	"securelink2socks/internal/storage"
	"testing"
	"time"
)

func liveRequest(t *testing.T, address string, request []byte) net.Conn {
	t.Helper()
	c, e := net.DialTimeout("tcp4", address, 3*time.Second)
	if e != nil {
		t.Fatal(e)
	}
	c.SetDeadline(time.Now().Add(15 * time.Second))
	c.Write([]byte{5, 1, 0})
	var m [2]byte
	if _, e = io.ReadFull(c, m[:]); e != nil || m != [2]byte{5, 0} {
		c.Close()
		t.Fatal("SOCKS method", e)
	}
	c.Write(request)
	return c
}
func TestLiveSOCKS(t *testing.T) {
	if os.Getenv("SECURELINK2SOCKS_E2E") != "1" || os.Getenv("SECURELINK2SOCKS_TEST_TARGET") == "" {
		t.Skip("explicit live session and target required")
	}
	target, e := netip.ParseAddrPort(os.Getenv("SECURELINK2SOCKS_TEST_TARGET"))
	if e != nil || !target.Addr().Is4() || target.Port() == 0 {
		t.Fatal("invalid literal test target")
	}
	home, e := storage.Home()
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 75*time.Second)
	defer cancel()
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	b := &gateway.Backend{}
	states := make(chan app.State, 20)
	sessions := make(chan gateway.Tunnel, 4)
	connect := app.Connector(home, nil)
	super := &app.Supervisor{Backend: b, Connect: func(ctx context.Context) (gateway.Tunnel, error) {
		v, e := connect(ctx)
		if e == nil {
			sessions <- v
		}
		return v, e
	}, Notify: func(s app.State) { states <- s }}
	serverDone := make(chan error, 1)
	go func() { serverDone <- socks.Serve(ctx, l, b) }()
	superDone := make(chan struct{})
	go func() { defer close(superDone); super.Run(ctx) }()
	defer func() {
		cancel()
		<-superDone
		if e := <-serverDone; e != nil {
			t.Error(e)
		}
	}()
	for {
		select {
		case state := <-states:
			if state == app.Ready {
				goto ready
			}
			if state == app.NeedsLogin {
				t.Fatal("cached session needs login")
			}
		case <-ctx.Done():
			t.Fatal("VPN not ready")
		}
	}
ready:
	ip := target.Addr().As4()
	request := append([]byte{5, 1, 0, 1}, ip[:]...)
	request = binary.BigEndian.AppendUint16(request, target.Port())
	c := liveRequest(t, l.Addr().String(), request)
	var r [10]byte
	if _, e = io.ReadFull(c, r[:]); e != nil || r[1] != 0 {
		c.Close()
		t.Fatalf("CONNECT reply=%d error=%v", r[1], e)
	}
	t.Log("live IPv4 SOCKS CONNECT succeeded")
	first := <-sessions
	first.Close()
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, e = c.Read(make([]byte, 1)); e == nil {
		c.Close()
		t.Fatal("revoked SOCKS connection still open")
	}
	if timeout, ok := e.(net.Error); ok && timeout.Timeout() {
		c.Close()
		t.Fatal("revocation did not close the client socket before its deadline")
	}
	c.Close()
	for {
		select {
		case state := <-states:
			if state == app.Ready {
				goto recovered
			}
		case <-ctx.Done():
			t.Fatal("reconnect failed")
		}
	}
recovered:
	c = liveRequest(t, l.Addr().String(), request)
	if _, e = io.ReadFull(c, r[:]); e != nil || r[1] != 0 {
		c.Close()
		t.Fatal("SOCKS did not recover")
	}
	c.Close()
	t.Log("same SOCKS listener recovered after forced VPN session closure")
	for _, tc := range []struct {
		request []byte
		code    byte
	}{{[]byte{5, 1, 0, 3}, 8}, {[]byte{5, 3, 0, 1}, 7}, {[]byte{5, 1, 0, 1, 192, 0, 2, 1, 1, 187}, 2}} {
		c = liveRequest(t, l.Addr().String(), tc.request)
		_, e = io.ReadFull(c, r[:])
		c.Close()
		if e != nil || r[1] != tc.code {
			t.Fatalf("negative reply=%d expected=%d", r[1], tc.code)
		}
	}
}
