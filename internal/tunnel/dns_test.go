package tunnel

import (
	"context"
	"encoding/binary"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"net"
	"testing"
	"time"
)

func TestDNSRejectsUnrelatedAnswersAndFollowsCNAME(t *testing.T) {
	name := func(s string) dnsmessage.Name { return dnsmessage.MustNewName(s + ".") }
	answers := []dnsmessage.Resource{
		{Header: dnsmessage.ResourceHeader{Name: name("unrelated.test"), Class: dnsmessage.ClassINET}, Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 99}}},
		{Header: dnsmessage.ResourceHeader{Name: name("allowed.test"), Class: dnsmessage.ClassINET}, Body: &dnsmessage.CNAMEResource{CNAME: name("alias.test")}},
		{Header: dnsmessage.ResourceHeader{Name: name("alias.test"), Class: dnsmessage.ClassINET}, Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}}},
	}
	ips, _, err := dnsAnswers("allowed.test", answers)
	if err != nil || len(ips) != 1 || ips[0].String() != "192.0.2.1" {
		t.Fatal(ips, err)
	}
	answers[2].Body = &dnsmessage.CNAMEResource{CNAME: name("allowed.test")}
	if _, _, err = dnsAnswers("allowed.test", answers); err == nil {
		t.Fatal("alias loop accepted")
	}
}

func TestDNSTruncationAndMismatchedQuestion(t *testing.T) {
	for _, mismatch := range []bool{false, true} {
		calls := 0
		ips, err := resolveDNS(t.Context(), "allowed.test", "192.0.2.53:53", func(ctx context.Context, network, address string) (net.Conn, error) {
			calls++
			client, server := net.Pipe()
			go func() {
				defer server.Close()
				q := make([]byte, 4096)
				if network == "tcp4" {
					var size [2]byte
					if _, e := io.ReadFull(server, size[:]); e != nil {
						return
					}
					q = q[:binary.BigEndian.Uint16(size[:])]
					if _, e := io.ReadFull(server, q); e != nil {
						return
					}
				} else {
					n, e := server.Read(q)
					if e != nil {
						return
					}
					q = q[:n]
				}
				var message dnsmessage.Message
				if message.Unpack(q) != nil {
					return
				}
				message.Response = true
				message.Truncated = network == "udp4"
				if mismatch {
					message.Questions[0].Name = dnsmessage.MustNewName("other.test.")
				}
				message.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("allowed.test."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}, Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 7}}}}
				packet, _ := message.Pack()
				if network == "tcp4" {
					packet = append(binary.BigEndian.AppendUint16(nil, uint16(len(packet))), packet...)
				}
				server.Write(packet)
			}()
			return client, nil
		})
		if calls != 2 {
			t.Fatal("no bounded TCP retry", calls)
		}
		if mismatch {
			if err == nil {
				t.Fatal("mismatched question accepted")
			}
		} else if err != nil || len(ips) != 1 {
			t.Fatal(ips, err)
		}
	}
}

func TestDNSCancellationClosesConnection(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := dnsExchange(ctx, "udp4", "192.0.2.53:53", []byte{1}, func(context.Context, string, string) (net.Conn, error) {
			a, b := net.Pipe()
			go func() { defer b.Close(); var x [1]byte; b.Read(x[:]); close(started); b.Read(x[:]) }()
			return a, nil
		})
		done <- err
	}()
	<-started
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled query succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("query not canceled")
	}
}
