package session_test

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"github.com/n0madic/go-openvpn/internal/control"
	"github.com/n0madic/go-openvpn/internal/session"
	"github.com/n0madic/go-openvpn/internal/tlscrypt"
	"github.com/n0madic/go-openvpn/internal/transport"
	"testing"
	"time"
)

func TestPolicyUpdateRevokesSession(t *testing.T) {
	for _, message := range []string{"PUSH_REPLY,app malformed,push-continuation 2", "PUSH_UPDATE,app malformed", ""} {
		t.Run(message, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
			defer cancel()
			var key [tlscrypt.StaticKeyLen]byte
			rand.Read(key[:])
			wrap, _ := tlscrypt.New(key, tlscrypt.DirectionNormal)
			clientTr, serverTr := transport.MemoryPair()
			cert, pool := genSelfSignedCert(t)
			trigger := make(chan struct{})
			serverDone := make(chan error, 1)
			go func() {
				conn, e := minimalServerHandshake(ctx, serverTr, wrap, cert, t)
				if e != nil {
					serverDone <- e
					return
				}
				defer conn.Close()
				select {
				case <-trigger:
				case <-ctx.Done():
					serverDone <- ctx.Err()
					return
				}
				if message != "" {
					e = control.WriteControlMessage(conn, message)
				}
				serverDone <- e
			}()
			s, e := session.DialWithTransport(ctx, session.Config{Network: "memory", RemoteAddr: "memB", TLSConfig: &tls.Config{ServerName: "localhost", RootCAs: pool}, TLSCryptV1: key[:], RestartOnPush: true}, clientTr)
			if e != nil {
				t.Fatal(e)
			}
			defer s.Close()
			close(trigger)
			select {
			case <-s.Done():
				if s.CloseErr() == nil {
					t.Fatal("no restart reason")
				}
			case <-ctx.Done():
				t.Fatal("policy update left session active")
			}
			if e := <-serverDone; e != nil {
				t.Fatal(e)
			}
		})
	}
}
