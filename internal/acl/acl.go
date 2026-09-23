// SPDX-License-Identifier: AGPL-3.0-or-later
// Package acl interprets the narrowly documented SecureLink app authorization
// format. Unknown syntax invalidates the entire snapshot.
package acl

import (
	"errors"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

type rule struct {
	prefix  netip.Prefix
	port    uint16
	anyPort bool
}

// Snapshot has no exported mutable fields and is safe to share between readers.
type Snapshot struct{ rules []rule }

func (s *Snapshot) Len() int {
	if s == nil {
		return 0
	}
	return len(s.rules)
}
func (s *Snapshot) AllowsTCP(target netip.AddrPort) bool {
	if s == nil || !target.Addr().Is4() || target.Port() == 0 {
		return false
	}
	for _, r := range s.rules {
		if r.prefix.Contains(target.Addr()) && (r.anyPort || r.port == target.Port()) {
			return true
		}
	}
	return false
}

// Reference docs show proto:any with port:any or a decimal single port.
// TCP/UDP/ranges/lists remain rejected until real raw PUSH evidence exists.
var appPattern = regexp.MustCompile(`^app\s+\[addr:([^\[\]\s]+)\]\s*\[proto:any\]\s*\[port:([^\[\]\s]+)\]$`)

func ParsePush(raw string) (*Snapshot, error) {
	if len(raw) > 4*1024*1024 || strings.ContainsRune(raw, '\x00') {
		return nil, errors.New("invalid PUSH body")
	}
	s := &Snapshot{}
	seen := map[rule]bool{}
	for _, option := range strings.Split(raw, ",") {
		option = strings.TrimSpace(option)
		fields := strings.Fields(option)
		if len(fields) == 0 || fields[0] != "app" {
			continue
		}
		m := appPattern.FindStringSubmatch(option)
		if m == nil {
			return nil, errors.New("unsupported app ACL syntax")
		}
		prefix, err := netip.ParsePrefix(m[1])
		if err != nil || !prefix.Addr().Is4() {
			return nil, errors.New("invalid app IPv4 prefix")
		}
		r := rule{prefix: prefix.Masked(), anyPort: m[2] == "any"}
		if !r.anyPort {
			for _, ch := range m[2] {
				if ch < '0' || ch > '9' {
					return nil, errors.New("invalid app port")
				}
			}
			p, err := strconv.ParseUint(m[2], 10, 16)
			if err != nil || p == 0 {
				return nil, errors.New("invalid app port")
			}
			r.port = uint16(p)
		}
		if !seen[r] {
			s.rules = append(s.rules, r)
			seen[r] = true
		}
	}
	return s, nil
}
