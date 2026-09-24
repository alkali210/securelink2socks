// SPDX-License-Identifier: AGPL-3.0-or-later
package plaincontrol

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestHardResetWireFormat(t *testing.T) {
	// OpenVPN V2 reset: opcode/key-id, 8-byte SID, zero ACK count, msg-id 0.
	want, _ := hex.DecodeString("3801020304050607080000000000")
	w := Wrapper{}
	got := w.Wrap(0x38, 0x0102030405060708, []byte{0, 0, 0, 0, 0})
	if !bytes.Equal(got, want) {
		t.Fatalf("wire = %x", got)
	}
	op, sid, pid, body, err := w.Unwrap(want)
	if err != nil || op != 0x38 || sid != 0x0102030405060708 || pid != 0 || !bytes.Equal(body, want[9:]) {
		t.Fatal("invalid unpacking")
	}
}

func TestRejectInvalidFraming(t *testing.T) {
	for n := 0; n < 9; n++ {
		if _, _, _, _, err := (Wrapper{}).Unwrap(make([]byte, n)); err == nil {
			t.Fatal("short header accepted")
		}
	}
	if _, _, _, _, err := (Wrapper{}).Unwrap([]byte{0x48, 0, 0, 0, 0, 0, 0, 0, 1}); err == nil {
		t.Fatal("data packet accepted as control")
	}
}
