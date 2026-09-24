// SPDX-License-Identifier: AGPL-3.0-or-later
package control

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"hash"
	"strings"

	"github.com/n0madic/go-openvpn/internal/proto"
)

// DeriveNegotiatedKeys follows the authenticated PUSH policy. Advertising EKM
// support does not select it; older peers use the OpenVPN KEY_METHOD 2 PRF.
func DeriveNegotiatedKeys(state tls.ConnectionState, raw string, client, server *proto.KeyMethod2, clientSID, serverSID uint64) (DataKeyMaterial, error) {
	ekm := false
	for _, option := range strings.Split(raw, ",") {
		f := strings.Fields(option)
		if len(f) == 0 {
			continue
		}
		switch f[0] {
		case "key-derivation":
			if len(f) != 2 || f[1] != "tls-ekm" {
				return DataKeyMaterial{}, errors.New("control: unsupported key derivation")
			}
			ekm = true
		case "protocol-flags":
			for _, flag := range f[1:] {
				if flag == "tls-ekm" {
					ekm = true
				}
			}
		}
	}
	if ekm {
		return DeriveDataKeys(state)
	}
	return DeriveLegacyKeys(client, server, clientSID, serverSID), nil
}

// DeriveLegacyKeys implements ssl.c's generate_key_expansion_openvpn_prf.
// MD5/SHA1 are the protocol's combined HMAC PRF, not TLS certificate hashes
// or data ciphers. The encrypted data channel remains negotiated AEAD.
func DeriveLegacyKeys(client, server *proto.KeyMethod2, clientSID, serverSID uint64) DataKeyMaterial {
	seed := append([]byte("OpenVPN master secret"), client.Random1[:]...)
	seed = append(seed, server.Random1[:]...)
	master := legacyPRF(client.PreMaster[:], seed, 48)
	defer clear(master)
	seed = append([]byte("OpenVPN key expansion"), client.Random2[:]...)
	seed = append(seed, server.Random2[:]...)
	seed = binary.BigEndian.AppendUint64(seed, clientSID)
	seed = binary.BigEndian.AppendUint64(seed, serverSID)
	out := legacyPRF(master, seed, DataKeyMaterialLen)
	var keys DataKeyMaterial
	copy(keys[:], out)
	clear(out)
	return keys
}

func legacyPRF(secret, seed []byte, n int) []byte {
	half := (len(secret) + 1) / 2
	a := pHash(md5.New, secret[:half], seed, n)
	b := pHash(sha1.New, secret[len(secret)-half:], seed, n)
	for i := range a {
		a[i] ^= b[i]
	}
	clear(b)
	return a
}

func pHash(h func() hash.Hash, secret, seed []byte, n int) []byte {
	mac := hmac.New(h, secret)
	mac.Write(seed)
	a := mac.Sum(nil)
	defer func() { clear(a) }()
	out := make([]byte, 0, n)
	for len(out) < n {
		mac.Reset()
		mac.Write(a)
		mac.Write(seed)
		block := mac.Sum(nil)
		out = append(out, block[:min(len(block), n-len(out))]...)
		clear(block)
		mac.Reset()
		mac.Write(a)
		next := mac.Sum(nil)
		clear(a)
		a = next
	}
	return out
}
