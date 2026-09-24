// SPDX-License-Identifier: AGPL-3.0-or-later
// Package plaincontrol implements OpenVPN's TLS control packet framing when
// neither tls-auth nor tls-crypt is configured. "Plain" describes only the
// outer packet header; the payload still carries authenticated TLS records.
package plaincontrol

import (
	"encoding/binary"
	"github.com/n0madic/go-openvpn/internal/proto"
)

type Wrapper struct{}

func (Wrapper) Wrap(opcodeKID byte, sessionID uint64, payload []byte) []byte {
	pkt := make([]byte, 1, proto.HeaderLen+len(payload))
	pkt[0] = opcodeKID
	pkt = binary.BigEndian.AppendUint64(pkt, sessionID)
	return append(pkt, payload...)
}

func (Wrapper) Unwrap(pkt []byte) (byte, uint64, uint32, []byte, error) {
	h, body, err := proto.ParseControlHeader(pkt)
	if err != nil {
		return 0, 0, 0, nil, err
	}
	switch h.Opcode {
	case proto.PControlHardResetClientV2, proto.PControlHardResetServerV2, proto.PControlSoftResetV1, proto.PControlV1, proto.PAckV1:
	default:
		return 0, 0, 0, nil, proto.ErrUnknownOpcode
	}
	// There is no outer replay packet ID without tls-auth/tls-crypt. Message
	// sequencing/duplicate handling lives in the reliable layer and inner TLS.
	return pkt[0], h.SessionID, 0, body, nil
}
