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

	"securelink2socks/internal/securelink"
	"securelink2socks/internal/storage"
	"securelink2socks/internal/tunnel"
)

const usage = `securelink2socks — XMU userspace gateway (compatibility stage)

Usage:
  securelink2socks login              Browser SSO / reuse or refresh session
  securelink2socks check              Authenticate, fetch config, check handshake/ACL
  securelink2socks check --aead-probe  Explicit AEAD-only TLS compatibility experiment
  securelink2socks probe IPv4:port    Also attempt an ACL-authorized TCP handshake

All network commands require SECURELINK2SOCKS_E2E=1 during this stage.
State: SECURELINK2SOCKS_HOME or ~/.securelink2socks
Optional callback injection: SL_CALLBACK_URL

SOCKS serving is pending the plan's real-XMU compatibility and TCP gates.
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
	switch args[0] {
	case "login", "check":
		if len(args) != 1 && !aeadProbe {
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
	c, err := securelink.New(home)
	if err != nil {
		return err
	}
	callback := os.Getenv("SL_CALLBACK_URL")
	if callback != "" {
		err = c.Login(ctx, callback, nil)
	} else {
		err = c.EnsureSession(ctx, false)
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
		fmt.Fprintln(out, "AEAD-only experiment: using profile CA + serverAuth verification; no CBC fallback.")
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
