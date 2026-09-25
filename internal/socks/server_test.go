package socks

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"securelink2socks/internal/gateway"
	"testing"
	"time"
)

type fakeBackend struct {
	ready bool
	calls int
	dial  func(context.Context, string, string) (net.Conn, error)
}

func (f *fakeBackend) Ready() bool { return f.ready }
func (f *fakeBackend) DialContext(c context.Context, n, a string) (net.Conn, error) {
	f.calls++
	return f.dial(c, n, a)
}
func startPipe(t *testing.T, b Backend) (net.Conn, <-chan struct{}) {
	t.Helper()
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() { defer close(done); Handle(t.Context(), server, b) }()
	client.SetDeadline(time.Now().Add(3 * time.Second))
	t.Cleanup(func() {
		client.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("handler leaked")
		}
	})
	return client, done
}
func negotiate(t *testing.T, c net.Conn) {
	t.Helper()
	c.Write([]byte{5, 1, 0})
	var b [2]byte
	if _, e := io.ReadFull(c, b[:]); e != nil || b != [2]byte{5, 0} {
		t.Fatalf("method %v %v", b, e)
	}
}
func TestRejectUnsupportedAndUnavailable(t *testing.T) {
	for _, tc := range []struct {
		name    string
		request []byte
		ready   bool
		code    byte
	}{
		{"domain", []byte{5, 1, 0, 3}, true, 8}, {"ipv6", []byte{5, 1, 0, 4}, true, 8},
		{"bind", []byte{5, 2, 0, 1}, true, 7}, {"udp", []byte{5, 3, 0, 1}, true, 7},
		{"unavailable", []byte{5, 1, 0, 1, 192, 0, 2, 1, 1, 187}, false, 3},
		{"invalid reserved", []byte{5, 1, 1, 1}, true, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := &fakeBackend{ready: tc.ready}
			c, _ := startPipe(t, b)
			negotiate(t, c)
			c.Write(tc.request)
			var reply [10]byte
			if _, e := io.ReadFull(c, reply[:]); e != nil || reply[1] != tc.code {
				t.Fatalf("reply %v %v", reply, e)
			}
			if b.calls != 0 {
				t.Fatal("unexpected dial")
			}
		})
	}
}
func TestDeniedAndMethodRejection(t *testing.T) {
	b := &fakeBackend{ready: true, dial: func(context.Context, string, string) (net.Conn, error) { return nil, gateway.ErrDenied }}
	c, _ := startPipe(t, b)
	negotiate(t, c)
	c.Write([]byte{5, 1, 0, 1, 192, 0, 2, 1, 1, 187})
	var r [10]byte
	io.ReadFull(c, r[:])
	if r[1] != 2 {
		t.Fatal("wrong denial")
	}
	c2, _ := startPipe(t, b)
	c2.Write([]byte{5, 1, 2})
	var m [2]byte
	io.ReadFull(c2, m[:])
	if m[1] != 255 {
		t.Fatal("accepted password auth")
	}
}
func TestRelayPayloadAndShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	upstream, echo := net.Pipe()
	defer echo.Close()
	b := &fakeBackend{ready: true, dial: func(_ context.Context, n, a string) (net.Conn, error) {
		if n != "tcp4" || a != "192.0.2.1:443" {
			t.Error("wrong target")
		}
		return upstream, nil
	}}
	client, server := net.Pipe()
	defer client.Close()
	done := make(chan struct{})
	go func() { defer close(done); Handle(ctx, server, b) }()
	client.SetDeadline(time.Now().Add(5 * time.Second))
	negotiate(t, client)
	client.Write([]byte{5, 1, 0, 1, 192, 0, 2, 1, 1, 187})
	var r [10]byte
	io.ReadFull(client, r[:])
	if r[1] != 0 {
		t.Fatal("CONNECT failed")
	}
	payload := bytes.Repeat([]byte("stream-data"), 8192)
	go func() {
		buf := make([]byte, len(payload))
		if _, e := io.ReadFull(echo, buf); e == nil {
			echo.Write(buf)
		}
	}()
	written := make(chan error, 1)
	go func() { _, e := client.Write(payload); written <- e }()
	got := make([]byte, len(payload))
	if _, e := io.ReadFull(client, got); e != nil || !bytes.Equal(got, payload) {
		t.Fatal("relay payload mismatch", e)
	}
	if e := <-written; e != nil {
		t.Fatal(e)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("shutdown leaked relay")
	}
}
func TestListenRejectsNonLoopback(t *testing.T) {
	for _, a := range []string{"0.0.0.0:1080", "localhost:1080", "[::1]:1080", "127.0.0.2:1080", "127.0.0.1:0"} {
		if l, e := Listen(a); e == nil {
			l.Close()
			t.Fatal("unsafe listen accepted")
		}
	}
}
func TestErrorReplies(t *testing.T) {
	if errorReply(errors.New("secret")) != 1 || errorReply(context.DeadlineExceeded) != 6 {
		t.Fatal("mapping")
	}
}

func TestTCPHalfClose(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	up, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer up.Close()
	go func() {
		c, e := up.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		b, e := io.ReadAll(c)
		if e == nil {
			c.Write(append([]byte("response:"), b...))
		}
	}()
	b := &fakeBackend{ready: true, dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp4", up.Addr().String())
	}}
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, l, b) }()
	c, e := net.Dial("tcp4", l.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	negotiate(t, c)
	c.Write([]byte{5, 1, 0, 1, 192, 0, 2, 1, 1, 187})
	var r [10]byte
	io.ReadFull(c, r[:])
	if r[1] != 0 {
		t.Fatal("connect")
	}
	c.Write([]byte("request"))
	c.(*net.TCPConn).CloseWrite()
	got, e := io.ReadAll(c)
	if e != nil || string(got) != "response:request" {
		t.Fatalf("half close lost response: %q %v", got, e)
	}
	cancel()
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not stop")
	}
}
