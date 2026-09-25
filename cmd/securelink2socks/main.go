// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"

	"securelink2socks/internal/app"
	"securelink2socks/internal/gateway"
	"securelink2socks/internal/securelink"
	"securelink2socks/internal/socks"
	"securelink2socks/internal/storage"
	"securelink2socks/internal/tunnel"
)

const usage = `securelink2socks — XMU userspace SOCKS5 gateway

Usage:
	securelink2socks serve              SOCKS5 TCP on 127.0.0.1:1080
  securelink2socks login              Browser SSO / reuse or refresh session
  securelink2socks login --force      Start a fresh browser SSO login
  securelink2socks check              Authenticate, fetch config, check handshake/ACL
  securelink2socks check --aead-probe  Compatibility alias for the verified AEAD policy
  securelink2socks probe IPv4:port    Also attempt an ACL-authorized TCP handshake

All network commands require SECURELINK2SOCKS_E2E=1 during this stage.
State: SECURELINK2SOCKS_HOME or ~/.securelink2socks
Optional callback injection: SL_CALLBACK_URL

Listen override: SECURELINK2SOCKS_LISTEN (127.0.0.1:port only)
SOCKS supports NO AUTH, IPv4 TCP CONNECT only; unavailable/denied fails closed.
No host TUN, route or DNS changes are made.
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 || (len(args) == 1 && (args[0] == "--help" || args[0] == "help" || args[0] == "-h")) {
		_, err := io.WriteString(out, usage)
		return err
	}
	var target netip.AddrPort
	aeadProbe := len(args) == 2 && args[0] == "check" && args[1] == "--aead-probe"
	forceLogin := len(args) == 2 && args[0] == "login" && args[1] == "--force"
	switch args[0] {
	case "login", "check", "serve":
		if len(args) != 1 && !aeadProbe && !forceLogin {
			return errors.New("unexpected arguments; use --help")
		}
	case "probe":
		if len(args) != 2 {
			return errors.New("probe requires IPv4:port")
		}
		var err error
		target, err = netip.ParseAddrPort(args[1])
		if err != nil || !target.Addr().Is4() || target.Port() == 0 {
			return errors.New("probe requires literal IPv4 and nonzero port")
		}
	default:
		return errors.New("unknown command; use --help")
	}
	if os.Getenv("SECURELINK2SOCKS_E2E") != "1" {
		return errors.New("live network commands require SECURELINK2SOCKS_E2E=1")
	}
	home, err := storage.Home()
	if err != nil {
		return err
	}
	if args[0] == "serve" {
		return serve(ctx, home, out)
	}
	c, err := securelink.New(home)
	if err != nil {
		return err
	}
	callback := os.Getenv("SL_CALLBACK_URL")
	if callback != "" {
		err = c.Login(ctx, callback, nil)
	} else {
		if forceLogin {
			err = securelink.ErrNeedsLogin
		} else {
			err = c.EnsureSession(ctx, false)
		}
		if errors.Is(err, securelink.ErrNeedsLogin) {
			err = c.Login(ctx, "", func(ctx context.Context, loginURL string) (string, error) {
				return prompt(ctx, loginURL, out, os.Stdin)
			})
		}
	}
	if err != nil {
		return err
	}
	fmt.Fprintln(out, "SecureLink session ready.")
	if args[0] == "login" {
		return nil
	}
	config, err := c.VPNConfig(ctx)
	if errors.Is(err, securelink.ErrNeedsLogin) {
		if err = c.EnsureSession(ctx, true); err == nil {
			config, err = c.VPNConfig(ctx)
		}
	}
	if err != nil {
		return err
	}
	profile, err := c.Profile(config)
	if err != nil {
		return err
	}
	var report tunnel.Report
	if aeadProbe {
		fmt.Fprintln(out, "AEAD policy: using profile CA + serverAuth verification; no CBC fallback.")
		report, err = tunnel.CheckAEAD(ctx, profile)
	} else {
		report, err = tunnel.Check(ctx, profile, target)
	}
	if errors.Is(err, tunnel.ErrVPNAuthRejected) {
		fmt.Fprintln(out, "VPN authentication rejected; refreshing SecureLink session once...")
		if err = c.EnsureSession(ctx, true); err != nil {
			return err
		}
		config, err = c.VPNConfig(ctx)
		if err != nil {
			return err
		}
		profile, err = c.Profile(config)
		if err != nil {
			return err
		}
		if aeadProbe {
			report, err = tunnel.CheckAEAD(ctx, profile)
		} else {
			report, err = tunnel.Check(ctx, profile, target)
		}
	}
	if report.IPv4 != "" || report.Stage != "" {
		if e := json.NewEncoder(out).Encode(report); e != nil {
			return e
		}
	}
	return err
}

func serve(ctx context.Context, home string, out io.Writer) error {
	address := os.Getenv("SECURELINK2SOCKS_LISTEN")
	if address == "" {
		address = "127.0.0.1:1080"
	}
	listener, err := socks.Listen(address)
	if err != nil {
		return err
	}
	fmt.Fprintln(out, "SOCKS5 listening on", listener.Addr().String())
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	backend := &gateway.Backend{}
	notify := func(state app.State) {
		fmt.Fprintln(out, "VPN state:", state)
		if state == app.NeedsLogin {
			fmt.Fprintln(out, "Run securelink2socks login --force in another terminal using the same state directory.")
		}
	}
	supervisor := &app.Supervisor{Backend: backend, Connect: app.Connector(home, notify), Notify: notify, WaitLogin: app.WaitForLogin(home)}
	done := make(chan struct{})
	go func() { defer close(done); supervisor.Run(ctx) }()
	err = socks.Serve(ctx, listener, backend)
	cancel()
	<-done
	return err
}

func prompt(ctx context.Context, loginURL string, out io.Writer, in io.Reader) (string, error) {
	u, err := url.Parse(loginURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return "", errors.New("invalid SSO browser URL")
	}
	fmt.Fprintln(out, "Opening SecureLink SSO page...")
	if err = openBrowser(loginURL); err != nil {
		fmt.Fprintln(out, "Open this SSO URL in your browser:", loginURL)
	}
	fmt.Fprintln(out, "Finish authentication in browser.\nPaste final callback URL:")
	fmt.Fprint(out, "> ")
	type result struct {
		line string
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		s := bufio.NewScanner(in)
		s.Buffer(make([]byte, 4096), 128*1024)
		if s.Scan() {
			ch <- result{line: strings.TrimSpace(s.Text())}
		} else {
			ch <- result{err: errors.New("callback input ended")}
		}
	}()
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case r := <-ch:
		return r.line, r.err
	}
}

func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}
