// SPDX-License-Identifier: AGPL-3.0-or-later
package control

import (
	"strings"
	"testing"
)

func TestOptionsCipherKeySize(t *testing.T) {
	for _, tc := range []struct{ ciphers, cipher, bits string }{
		{"AES-128-GCM:AES-256-GCM", "AES-128-GCM", "128"},
		{"AES-256-GCM:AES-128-GCM", "AES-256-GCM", "256"},
		{"CHACHA20-POLY1305", "CHACHA20-POLY1305", "256"},
	} {
		s := buildOptionsString(tc.ciphers, "TCPv4_CLIENT")
		for _, want := range []string{"cipher " + tc.cipher, "keysize " + tc.bits, "proto TCPv4_CLIENT"} {
			if !strings.Contains(","+s+",", ","+want+",") {
				t.Errorf("missing %q in %q", want, s)
			}
		}
	}
}
