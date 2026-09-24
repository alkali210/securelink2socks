// SPDX-License-Identifier: AGPL-3.0-or-later
package control

import (
	"errors"
	"io"
	"strings"

	"github.com/n0madic/go-openvpn/internal/proto"
)

// ReadPushReply reassembles native OpenVPN push-continuation bundles before
// interpreting cipher, addressing or authorization. Partial policy is invalid.
func ReadPushReply(r io.Reader) (string, error) {
	var body strings.Builder
	for fragment := 0; fragment < 4096; fragment++ {
		msg, err := ReadControlMessage(r)
		if err != nil {
			return "", err
		}
		if !strings.HasPrefix(msg, proto.PushReplyPrefix) {
			if fragment == 0 || strings.HasPrefix(msg, "AUTH_FAILED") {
				return msg, nil
			}
			return "", errors.New("control: unexpected PUSH continuation message")
		}
		continuation := ""
		for _, option := range strings.Split(strings.TrimPrefix(msg, proto.PushReplyPrefix), ",") {
			fields := strings.Fields(option)
			if len(fields) > 0 && fields[0] == "push-continuation" {
				if continuation != "" || len(fields) != 2 || (fields[1] != "1" && fields[1] != "2") {
					return "", errors.New("control: invalid PUSH continuation")
				}
				continuation = fields[1]
				continue
			}
			if body.Len()+len(option)+1 > 4*1024*1024 {
				return "", errors.New("control: PUSH bundle too large")
			}
			if body.Len() > 0 {
				body.WriteByte(',')
			}
			body.WriteString(option)
		}
		if continuation == "2" {
			continue
		}
		if (fragment == 0 && continuation == "1") || (fragment > 0 && continuation != "1") {
			return "", errors.New("control: invalid final PUSH continuation")
		}
		return proto.PushReplyPrefix + body.String(), nil
	}
	return "", errors.New("control: too many PUSH fragments")
}
