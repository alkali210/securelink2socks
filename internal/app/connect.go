// SPDX-License-Identifier: AGPL-3.0-or-later
package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"securelink2socks/internal/gateway"
	"securelink2socks/internal/securelink"
	"securelink2socks/internal/tunnel"
)

// Connector reloads the session cache on each attempt; it never prompts or
// logs API/profile/server text. VPN auth rejection gets one forced refresh.
func Connector(home string, notify func(State)) func(context.Context) (gateway.Tunnel, error) {
	return func(ctx context.Context) (gateway.Tunnel, error) {
		c, err := securelink.New(home)
		if err != nil {
			return nil, securelink.ErrNeedsLogin
		}
		for attempt := 0; attempt < 2; attempt++ {
			if err = c.EnsureSession(ctx, attempt > 0); err != nil {
				return nil, err
			}
			v, e := c.VPNConfig(ctx)
			if e != nil {
				if errors.Is(e, securelink.ErrNeedsLogin) && attempt == 0 {
					continue
				}
				return nil, e
			}
			p, e := c.Profile(v)
			if e != nil {
				return nil, e
			}
			if notify != nil {
				notify(Connecting)
			}
			s, _, e := tunnel.Open(ctx, p)
			if errors.Is(e, tunnel.ErrVPNAuthRejected) {
				if attempt == 0 {
					continue
				}
				return nil, securelink.ErrNeedsLogin
			}
			if e != nil {
				// Never wrap a nil *Session in a non-nil Tunnel interface: the
				// supervisor must be able to safely clean up canceled attempts.
				return nil, e
			}
			return s, nil
		}
		return nil, securelink.ErrNeedsLogin
	}
}

// WaitForLogin watches metadata only. NeedsLogin makes no further network
// requests until an external login atomically replaces the session file.
func WaitForLogin(home string) func(context.Context) {
	return func(ctx context.Context) {
		path := filepath.Join(home, "session.json")
		previous, _ := os.Stat(path)
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
			next, err := os.Stat(path)
			if err == nil && (previous == nil || !os.SameFile(previous, next) || previous.ModTime() != next.ModTime() || previous.Size() != next.Size()) {
				return
			}
		}
	}
}
