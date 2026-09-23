// SPDX-License-Identifier: AGPL-3.0-or-later
package openvpn

import (
	"github.com/n0madic/go-openvpn/internal/proto"
	"testing"
)

// Regression: custom authorization options must survive parsing, public
// conversion and reconnect dispatch, even when the core does not know them.
func TestCustomPushPreserved(t *testing.T) {
	raw := "ifconfig 192.0.2.2 255.255.255.0,topology subnet,app [addr:198.51.100.1/32][proto:any] [port:443]"
	internal, err := proto.ParsePushReply("PUSH_REPLY," + raw)
	if err != nil {
		t.Fatal(err)
	}
	public := publicPushReply(internal)
	if public.Raw != raw || public.LocalIP.String() != "192.0.2.2" {
		t.Fatal("public conversion lost raw push or parsed fields")
	}
	c := &Client{}
	called := false
	c.OnReconnect(func(p PushReply) {
		called = true
		if p.Raw != raw {
			t.Fatal("reconnect dropped custom options")
		}
	})
	c.FireOnReconnect(public)
	if !called {
		t.Fatal("reconnect callback missing")
	}
}
