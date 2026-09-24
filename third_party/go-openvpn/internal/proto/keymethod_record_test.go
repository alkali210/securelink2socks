// SPDX-License-Identifier: AGPL-3.0-or-later
package proto

import (
	"strings"
	"testing"
)

func TestKeyMethodCannotExceedTLSRecord(t *testing.T) {
	if _, err := MarshalKeyMethod2(KeyMethod2{PeerInfo: strings.Repeat("x", 16384)}); err == nil {
		t.Fatal("oversized KEY_METHOD 2 accepted")
	}
}
