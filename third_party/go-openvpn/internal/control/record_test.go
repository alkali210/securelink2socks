// SPDX-License-Identifier: AGPL-3.0-or-later
package control_test

import (
	"bytes"
	"errors"
	"github.com/n0madic/go-openvpn/internal/control"
	"io"
	"testing"
)

// Models the peer's per-TLS-record command extractor: fragments without NUL
// are invalid, even though a stream reader would silently reassemble them.
type recordPeer struct{ got []byte }

func (p *recordPeer) Write(b []byte) (int, error) {
	if len(b) < 2 || b[len(b)-1] != 0 {
		return 0, errors.New("unterminated control record")
	}
	p.got = bytes.Clone(b)
	return len(b), nil
}

type shortWriter struct{}

func (shortWriter) Write(b []byte) (int, error) { return len(b) - 1, nil }

func TestWriteControlMessageRecord(t *testing.T) {
	p := &recordPeer{}
	if err := control.WriteControlMessage(p, "PUSH_REQUEST"); err != nil {
		t.Fatal(err)
	}
	if string(p.got) != "PUSH_REQUEST\x00" {
		t.Fatal("wrong record")
	}
	if err := control.WriteControlMessage(shortWriter{}, "PUSH_REQUEST"); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal("short write lost")
	}
}
