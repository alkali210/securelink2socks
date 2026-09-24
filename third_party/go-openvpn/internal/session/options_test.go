// SPDX-License-Identifier: AGPL-3.0-or-later
package session

import "testing"

func TestOptionsTransport(t *testing.T) {
	for _, tc := range []struct{ network, remote, want string }{
		{"tcp", "192.0.2.1:10000", "TCPv4_CLIENT"},
		{"udp", "192.0.2.1:1194", "UDPv4"},
		{"tcp", "[2001:db8::1]:1194", "TCPv6_CLIENT"},
	} {
		if got := optionsProto(tc.network, tc.remote); got != tc.want {
			t.Errorf("got %s, want %s", got, tc.want)
		}
	}
}
