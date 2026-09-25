// SPDX-License-Identifier: AGPL-3.0-or-later
package openvpn

import (
	"errors"
	"github.com/n0madic/go-openvpn/internal/session"
)

// SessionDone refers to the current session. Use with AutoReconnect disabled
// when an application owns reconnect and must revoke old data-plane streams.
func (c *Client) SessionDone() <-chan struct{} { return c.session().Done() }

// SessionError returns its closure cause. It may contain server text; callers
// should classify it without logging it verbatim.
func (c *Client) SessionError() error {
	err := c.session().CloseErr()
	var auth *session.AuthFailedError
	if errors.As(err, &auth) {
		return ErrAuthFailed
	}
	return err
}
