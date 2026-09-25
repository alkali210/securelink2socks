package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestOfflineCLI(t *testing.T) {
	t.Setenv("SECURELINK2SOCKS_E2E", "")
	var out bytes.Buffer
	if err := run(context.Background(), nil, &out); err != nil || !strings.Contains(out.String(), "SOCKS supports NO AUTH") {
		t.Fatal("missing stage/help")
	}
	for _, args := range [][]string{{"serve"}, {"login", "--force"}, {"login"}, {"check"}, {"check", "--aead-probe"}, {"probe", "192.0.2.1:443"}} {
		err := run(context.Background(), args, &out)
		if err == nil || !strings.Contains(err.Error(), "SECURELINK2SOCKS_E2E") {
			t.Fatal("live command ran without opt-in")
		}
	}
	for _, addr := range []string{"example.com:443", "[::1]:443", "192.0.2.1:0"} {
		err := run(context.Background(), []string{"probe", addr}, &out)
		if err == nil || !strings.Contains(err.Error(), "literal IPv4") {
			t.Fatal("probe accepted non-IPv4/invalid target")
		}
	}
}
