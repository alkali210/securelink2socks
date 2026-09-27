package mihomo

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Optional offline interoperability test against a real Mihomo binary. No
// campus sessions, public DNS or external target connections are used.
func TestMihomoCore(t *testing.T) {
	binaryPath := os.Getenv("SECURELINK2SOCKS_MIHOMO")
	if binaryPath == "" {
		t.Skip("set SECURELINK2SOCKS_MIHOMO to test a local core")
	}
	binaryPath, err := filepath.Abs(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	sock, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sock.Close()
	go func() {
		for {
			conn, err := sock.Accept()
			if err != nil {
				return
			}
			go mockSOCKS(conn, "mock")
		}
	}()
	existingSock, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer existingSock.Close()
	go func() {
		for {
			conn, err := existingSock.Accept()
			if err != nil {
				return
			}
			go mockSOCKS(conn, "existing")
		}
	}()
	opt := options()
	opt.Listen = netip.MustParseAddrPort(sock.Addr().String())
	p := policy(t, strings.Join([]string{
		"app [domain:*.example.invalid][proto:tcp port:443]",
		"app [domain:root.invalid][proto:tcp port:any]",
		"app [domain:ip.xmu.edu.cn][proto:tcp port:443]",
		"app [addr:192.0.2.0/24][proto:tcp port:80]",
		"app [addr:192.0.2.10/32][proto:tcp port:443]",
	}, ","))
	dir := t.TempDir()
	full, err := Render(p, opt)
	if err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(config, full, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	check := exec.CommandContext(ctx, binaryPath, "-t", "-d", dir, "-f", config)
	if output, err := check.CombinedOutput(); err != nil {
		t.Fatalf("full config: %v %s", err, output)
	}
	// Merge the fragment into a config with an existing public proxy and final
	// rule. An apex host excluded by the wildcard must reach that existing rule.
	opt.Fragment = true
	fragment, err := Render(p, opt)
	if err != nil {
		t.Fatal(err)
	}
	hold, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := hold.Addr().String()
	_, port, _ := net.SplitHostPort(address)
	hold.Close()
	merged := fmt.Sprintf("mixed-port: %s\nallow-lan: false\nbind-address: 127.0.0.1\nmode: rule\nlog-level: silent\nipv6: false\ndns:\n  enable: false\ntun:\n  enable: false\n", port) + string(fragment)
	existing := fmt.Sprintf("  - name: Existing\n    type: socks5\n    server: 127.0.0.1\n    port: %d\n    udp: false\nrules:\n", netip.MustParseAddrPort(existingSock.Addr().String()).Port())
	merged = strings.Replace(merged, "rules:\n", existing, 1)
	merged += "  - DOMAIN,example.invalid,Existing\n  - MATCH,REJECT\n"
	if err := os.WriteFile(config, []byte(merged), 0600); err != nil {
		t.Fatal(err)
	}
	check = exec.CommandContext(ctx, binaryPath, "-t", "-d", dir, "-f", config)
	if output, err := check.CombinedOutput(); err != nil {
		t.Fatalf("fragment merge: %v %s", err, output)
	}
	cmd := exec.CommandContext(ctx, binaryPath, "-d", dir, "-f", config)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	ready := false
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			ready = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		t.Fatal("core listener not ready")
	}
	proxy, _ := url.Parse("http://" + address)
	transport := &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	for _, tc := range []struct {
		target string
		allow  bool
	}{
		{"a.example.invalid:443", true}, {"deep.a.example.invalid:443", true},
		{"a.example.invalid:80", false}, {"example.invalid:443", true},
		{"badexample.invalid:443", false}, {"root.invalid:8443", true},
		{"192.0.2.10:443", true}, {"192.0.2.11:443", false},
		{"192.0.2.11:80", true}, {"unknown.xmu.edu.cn:443", false},
	} {
		resp, err := client.Get("http://" + tc.target + "/")
		accepted := false
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			accepted = string(body) == "mock" || string(body) == "existing"
			if tc.target == "example.invalid:443" && string(body) != "existing" {
				t.Error("wildcard apex did not reach existing public proxy")
			}
		}
		if accepted != tc.allow {
			t.Errorf("%s: allowed=%v want %v (error %v)", tc.target, accepted, tc.allow, err)
		}
	}
}

func mockSOCKS(conn net.Conn, body string) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	var greeting [2]byte
	if _, err := io.ReadFull(conn, greeting[:]); err != nil {
		return
	}
	if _, err := io.CopyN(io.Discard, conn, int64(greeting[1])); err != nil {
		return
	}
	if _, err := conn.Write([]byte{5, 0}); err != nil {
		return
	}
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return
	}
	size := 0
	switch header[3] {
	case 1:
		size = 4
	case 3:
		var n [1]byte
		if _, err := io.ReadFull(conn, n[:]); err != nil {
			return
		}
		size = int(n[0])
	default:
		return
	}
	if _, err := io.CopyN(io.Discard, conn, int64(size)); err != nil {
		return
	}
	var port uint16
	if err := binary.Read(conn, binary.BigEndian, &port); err != nil {
		return
	}
	if _, err := conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil {
		return
	}
	// The proxy now relays an HTTP request. Read its complete headers before
	// replying to avoid an early close/RST on Windows.
	var buf [1]byte
	var headers strings.Builder
	for headers.Len() < 8192 && !strings.HasSuffix(headers.String(), "\r\n\r\n") {
		if _, err := io.ReadFull(conn, buf[:]); err != nil {
			return
		}
		headers.WriteByte(buf[0])
	}
	_, _ = fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
}
