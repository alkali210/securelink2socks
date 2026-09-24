// SPDX-License-Identifier: AGPL-3.0-or-later
package tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/n0madic/go-openvpn"
)

func TestHandshakeReasonDoesNotLeakServerContent(t *testing.T) {
	const secret = "PRIVATE_TOKEN_AND_PROFILE"
	for _, err := range []error{
		errors.New(secret),
		fmt.Errorf("%w: AUTH_FAILED,%s", openvpn.ErrAuthFailed, secret),
		fmt.Errorf("%w: AUTH_FAILED,invalid token %s", openvpn.ErrAuthFailed, secret),
		fmt.Errorf("%w: AUTH_FAILED,cipher negotiation %s", openvpn.ErrAuthFailed, secret),
		fmt.Errorf("control: parse PUSH_REPLY: %s", secret),
	} {
		if got := handshakeReason(err); strings.Contains(got, secret) || got == "" {
			t.Fatal("unsafe error classification")
		}
	}
	for _, tc := range []struct {
		err  error
		want string
	}{
		{fmt.Errorf("%w: AUTH_FAILED", openvpn.ErrAuthFailed), "server rejected VPN authentication without a reason"},
		{context.DeadlineExceeded, "timeout"},
		{io.EOF, "peer closed the connection"},
	} {
		if got := handshakeReason(tc.err); got != tc.want {
			t.Errorf("got %q want %q", got, tc.want)
		}
	}
}
