// SPDX-License-Identifier: AGPL-3.0-or-later
package control

import (
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"testing"

	"github.com/n0madic/go-openvpn/internal/proto"
)

func TestLegacyKeysIndependentGolden(t *testing.T) {
	var c, s proto.KeyMethod2
	for i := range c.PreMaster {
		c.PreMaster[i] = byte(i)
	}
	for i := range c.Random1 {
		c.Random1[i] = byte(i)
		s.Random1[i] = byte(i + 32)
		c.Random2[i] = byte(i + 64)
		s.Random2[i] = byte(i + 96)
	}
	got := DeriveLegacyKeys(&c, &s, 0x0102030405060708, 0x1112131415161718)
	// Independently generated with Python hashlib/hmac, following OpenVPN
	// ssl.c generate_key_expansion_openvpn_prf and RFC 2246 section 5.
	const want = "1e91bc63a7b1db12ba2c614f2a5770a6ad3bafd6f21e24f5b1f09cbe15562cb4"
	if fmt.Sprintf("%x", sha256.Sum256(got[:])) != want {
		t.Fatal("PRF vector mismatch")
	}
	selected, err := DeriveNegotiatedKeys(tls.ConnectionState{}, "cipher AES-128-GCM", &c, &s, 0x0102030405060708, 0x1112131415161718)
	if err != nil || selected != got {
		t.Fatal("legacy derivation not selected")
	}
	if _, err := DeriveNegotiatedKeys(tls.ConnectionState{}, "key-derivation unknown", &c, &s, 1, 2); err == nil {
		t.Fatal("unknown derivation accepted")
	}
}
