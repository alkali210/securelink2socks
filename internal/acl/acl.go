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
type domainRule struct {
	name    string
	port    uint16
	anyPort bool
}
type Snapshot struct {
	rules   []rule
	domains []domainRule
}

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

// Live XMU pushes combine proto and port in one bracket and use semicolon
// port lists. Keep the separated bracket form from the reference fixtures.
var appPattern = regexp.MustCompile(`^app\s+\[(addr|domain):([^\[\]\s]+)\]\s*\[proto:(any|tcp)(?:\]\s*\[|\s+)port:([^\[\]\s]+)\]$`)

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
		var ports []uint16
		if m[4] != "any" {
			for _, part := range strings.Split(m[4], ";") {
				for _, ch := range part {
					if ch < '0' || ch > '9' {
						return nil, errors.New("invalid app port")
					}
				}
				p, err := strconv.ParseUint(part, 10, 16)
				if err != nil || p == 0 {
					return nil, errors.New("invalid app port")
				}
				ports = append(ports, uint16(p))
			}
		} else {
			ports = []uint16{0}
		}
		if m[1] == "domain" {
			name := m[2]
			// Some XMU rules encode an IPv4 literal in the domain field.
			if ip, err := netip.ParseAddr(name); err == nil && ip.Is4() {
				for _, port := range ports {
					r := rule{prefix: netip.PrefixFrom(ip, 32), port: port, anyPort: port == 0}
					if !seen[r] {
						s.rules = append(s.rules, r)
						seen[r] = true
					}
				}
				continue
			}
			wildcard := strings.HasPrefix(name, "*.")
			if wildcard {
				name = strings.TrimPrefix(name, "*.")
			}
			name, ok := CanonicalDomain(name)
			if !ok {
				return nil, errors.New("invalid app domain")
			}
			if wildcard {
				name = "*." + name
			}
			for _, port := range ports {
				s.domains = append(s.domains, domainRule{name, port, port == 0})
			}
			continue
		}
		prefix, err := netip.ParsePrefix(m[2])
		if err != nil || !prefix.Addr().Is4() {
			return nil, errors.New("invalid app IPv4 prefix")
		}
		for _, port := range ports {
			r := rule{prefix: prefix.Masked(), port: port, anyPort: port == 0}
			if !seen[r] {
				s.rules = append(s.rules, r)
				seen[r] = true
			}
		}
	}
	return s, nil
}

// CanonicalDomain accepts ASCII DNS hostnames, including already-encoded IDNA.
func CanonicalDomain(name string) (string, bool) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if len(name) == 0 || len(name) > 253 {
		return "", false
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return "", false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", false
			}
		}
	}
	return name, true
}
func (s *Snapshot) DomainLen() int {
	if s == nil {
		return 0
	}
	return len(s.domains)
}
func (s *Snapshot) AllowsDomainTCP(name string, port uint16) bool {
	name, ok := CanonicalDomain(name)
	if !ok || port == 0 || s == nil {
		return false
	}
	for _, r := range s.domains {
		match := name == r.name
		if strings.HasPrefix(r.name, "*.") {
			match = strings.HasSuffix(name, r.name[1:])
		}
		if match && (r.anyPort || r.port == port) {
			return true
		}
	}
	return false
}
