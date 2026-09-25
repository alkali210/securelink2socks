// SPDX-License-Identifier: AGPL-3.0-or-later
package tunnel

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"securelink2socks/internal/acl"
)

type dnsDial func(context.Context, string, string) (net.Conn, error)

func resolveDNS(ctx context.Context, host, server string, dial dnsDial) ([]netip.Addr, error) {
	for depth := 0; depth < 8; depth++ {
		var seed [2]byte
		if _, err := rand.Read(seed[:]); err != nil {
			return nil, err
		}
		name, err := dnsmessage.NewName(host + ".")
		if err != nil {
			return nil, err
		}
		query := dnsmessage.Message{Header: dnsmessage.Header{ID: binary.BigEndian.Uint16(seed[:]), RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
		packet, err := query.Pack()
		if err != nil {
			return nil, err
		}
		var answer dnsmessage.Message
		for _, network := range []string{"udp4", "tcp4"} {
			var wire []byte
			// Leave time for TCP when a server silently drops UDP.
			exchangeCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
			wire, err = dnsExchange(exchangeCtx, network, server, packet, dial)
			cancel()
			if err != nil {
				continue
			}
			err = answer.Unpack(wire)
			if err != nil {
				continue
			}
			if answer.ID != query.ID || !answer.Response || answer.OpCode != 0 || len(answer.Questions) != 1 ||
				answer.Questions[0].Type != dnsmessage.TypeA || answer.Questions[0].Class != dnsmessage.ClassINET ||
				!strings.EqualFold(answer.Questions[0].Name.String(), name.String()) {
				err = errors.New("invalid VPN DNS response")
				continue
			}
			if answer.Truncated {
				err = errors.New("truncated VPN DNS response")
				continue
			}
			if answer.RCode != dnsmessage.RCodeSuccess {
				return nil, errors.New("VPN DNS returned no usable answer")
			}
			break
		}
		if err != nil {
			return nil, err
		}
		ips, next, err := dnsAnswers(host, answer.Answers)
		if err != nil {
			return nil, err
		}
		if len(ips) > 0 {
			return ips, nil
		}
		if next == host {
			return nil, errors.New("VPN DNS returned no IPv4 address")
		}
		host = next
	}
	return nil, errors.New("VPN DNS alias chain too long")
}

func dnsAnswers(host string, answers []dnsmessage.Resource) ([]netip.Addr, string, error) {
	seen := map[string]bool{}
	for depth := 0; depth < 8; depth++ {
		if seen[host] {
			return nil, "", errors.New("VPN DNS alias loop")
		}
		seen[host] = true
		var ips []netip.Addr
		next := ""
		for _, r := range answers {
			if r.Header.Class != dnsmessage.ClassINET || !strings.EqualFold(r.Header.Name.String(), host+".") {
				continue
			}
			switch body := r.Body.(type) {
			case *dnsmessage.AResource:
				if len(ips) < 16 {
					ips = append(ips, netip.AddrFrom4(body.A))
				}
			case *dnsmessage.CNAMEResource:
				var ok bool
				next, ok = acl.CanonicalDomain(body.CNAME.String())
				if !ok {
					return nil, "", errors.New("invalid VPN DNS alias")
				}
			}
		}
		if len(ips) > 0 {
			return ips, host, nil
		}
		if next == "" {
			return nil, host, nil
		}
		host = next
	}
	return nil, "", errors.New("VPN DNS alias chain too long")
}

func dnsExchange(ctx context.Context, network, server string, query []byte, dial dnsDial) ([]byte, error) {
	conn, err := dial(ctx, network, server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		if err = conn.SetDeadline(deadline); err != nil {
			return nil, err
		}
	}
	if network == "tcp4" {
		frame := binary.BigEndian.AppendUint16(nil, uint16(len(query)))
		frame = append(frame, query...)
		if _, err = io.Copy(conn, bytes.NewReader(frame)); err != nil {
			return nil, err
		}
		var size [2]byte
		if _, err = io.ReadFull(conn, size[:]); err != nil {
			return nil, err
		}
		result := make([]byte, int(binary.BigEndian.Uint16(size[:])))
		_, err = io.ReadFull(conn, result)
		return result, err
	}
	if n, err := conn.Write(query); err != nil {
		return nil, err
	} else if n != len(query) {
		return nil, io.ErrShortWrite
	}
	result := make([]byte, 65535)
	n, err := conn.Read(result)
	return result[:n], err
}
