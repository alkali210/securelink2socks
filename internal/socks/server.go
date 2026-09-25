// SPDX-License-Identifier: AGPL-3.0-or-later
package socks

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"syscall"
	"time"

	"securelink2socks/internal/acl"
	"securelink2socks/internal/gateway"
)

type Backend interface {
	Ready() bool
	DialContext(context.Context, string, string) (net.Conn, error)
}

// Listen accepts only an explicit IPv4 loopback address; it never resolves DNS.
func Listen(address string) (net.Listener, error) {
	ap, err := netip.ParseAddrPort(address)
	if err != nil || ap.Addr() != netip.MustParseAddr("127.0.0.1") || ap.Port() == 0 {
		return nil, errors.New("SOCKS listen address must be 127.0.0.1 with a nonzero port")
	}
	return net.Listen("tcp4", ap.String())
}

func Serve(ctx context.Context, l net.Listener, b Backend) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { l.Close() })
	defer stop()
	var wg sync.WaitGroup
	defer func() { cancel(); l.Close(); wg.Wait() }()
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		wg.Add(1)
		go func() { defer wg.Done(); Handle(ctx, c, b) }()
	}
}

// Handle never resolves the requested address and has no direct-network dial.
func Handle(ctx context.Context, c net.Conn, b Backend) {
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	var h [2]byte
	if _, err := io.ReadFull(c, h[:]); err != nil || h[0] != 5 || h[1] == 0 {
		return
	}
	methods := make([]byte, int(h[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	method := byte(255)
	for _, v := range methods {
		if v == 0 {
			method = 0
		}
	}
	if _, err := c.Write([]byte{5, method}); err != nil || method == 255 {
		return
	}
	var req [4]byte
	if _, err := io.ReadFull(c, req[:]); err != nil {
		return
	}
	if req[0] != 5 || req[2] != 0 {
		reply(c, 1)
		return
	}
	if req[1] != 1 {
		reply(c, 7)
		return
	}
	var host string
	switch req[3] {
	case 1:
		var ip [4]byte
		if _, err := io.ReadFull(c, ip[:]); err != nil {
			return
		}
		host = netip.AddrFrom4(ip).String()
	case 3:
		var size [1]byte
		if _, err := io.ReadFull(c, size[:]); err != nil {
			return
		}
		if size[0] == 0 {
			reply(c, 8)
			return
		}
		name := make([]byte, int(size[0]))
		if _, err := io.ReadFull(c, name); err != nil {
			return
		}
		var ok bool
		host, ok = acl.CanonicalDomain(string(name))
		if !ok {
			reply(c, 8)
			return
		}
	default:
		reply(c, 8)
		return
	}
	var portBytes [2]byte
	if _, err := io.ReadFull(c, portBytes[:]); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBytes[:])
	if port == 0 {
		reply(c, 2)
		return
	}
	address := net.JoinHostPort(host, strconv.Itoa(int(port)))
	if !b.Ready() {
		reply(c, 3)
		return
	}
	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	remote, err := b.DialContext(dialCtx, "tcp4", address)
	cancel()
	if err != nil {
		reply(c, errorReply(err))
		return
	}
	defer remote.Close()
	// Revocation also closes an idle client-side reader, not just the tunnel.
	relayDone := make(chan struct{})
	defer close(relayDone)
	if v, ok := remote.(interface{ Done() <-chan struct{} }); ok {
		go func() {
			select {
			case <-v.Done():
				c.Close()
			case <-relayDone:
			}
		}()
	}
	stopRemote := context.AfterFunc(ctx, func() { remote.Close() })
	defer stopRemote()
	if !reply(c, 0) {
		return
	}
	c.SetDeadline(time.Time{})
	done := make(chan struct{}, 1)
	go func() {
		_, err := io.Copy(remote, c)
		if err != nil {
			remote.Close()
			c.Close()
		} else {
			closeWrite(remote)
		}
		done <- struct{}{}
	}()
	_, err = io.Copy(c, remote)
	if err != nil {
		remote.Close()
		c.Close()
	} else {
		closeWrite(c)
	}
	<-done
}

func closeWrite(c net.Conn) {
	if v, ok := c.(interface{ CloseWrite() error }); ok {
		v.CloseWrite()
	} else {
		c.Close()
	}
}
func reply(c net.Conn, code byte) bool {
	_, err := c.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
	return err == nil
}
func errorReply(err error) byte {
	switch {
	case errors.Is(err, gateway.ErrDenied):
		return 2
	case errors.Is(err, gateway.ErrUnavailable):
		return 3
	case errors.Is(err, context.DeadlineExceeded):
		return 6
	case errors.Is(err, syscall.ECONNREFUSED):
		return 5
	case errors.Is(err, syscall.ENETUNREACH):
		return 3
	case errors.Is(err, syscall.EHOSTUNREACH):
		return 4
	default:
		return 1
	}
}
