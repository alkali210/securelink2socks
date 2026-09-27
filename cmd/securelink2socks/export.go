// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"securelink2socks/internal/mihomo"
	"securelink2socks/internal/securelink"
	"securelink2socks/internal/tunnel"
)

type exportOptions struct {
	output   string
	fragment bool
	listen   netip.AddrPort
}

func parseExportOptions(args []string) (exportOptions, error) {
	var opt exportOptions
	flags := flag.NewFlagSet("export-mihomo", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&opt.output, "output", "", "output YAML path")
	flags.BoolVar(&opt.fragment, "fragment", false, "export a merge fragment without a final MATCH rule")
	if err := flags.Parse(args); err != nil {
		return opt, errors.New("export-mihomo accepts --fragment and --output file.yaml; use --help")
	}
	if flags.NArg() != 0 {
		return opt, errors.New("unexpected export-mihomo arguments; use --help")
	}
	return opt, nil
}

func (o *exportOptions) resolve(home string) error {
	if o.output == "" {
		name := "mihomo.generated.yaml"
		if o.fragment {
			name = "mihomo.fragment.yaml"
		}
		o.output = filepath.Join(home, name)
	}
	ext := strings.ToLower(filepath.Ext(o.output))
	if ext != ".yaml" && ext != ".yml" {
		return errors.New("export output must be a .yaml or .yml file")
	}
	var err error
	o.output, err = filepath.Abs(o.output)
	if err != nil {
		return err
	}
	address := os.Getenv("SECURELINK2SOCKS_LISTEN")
	if address == "" {
		address = "127.0.0.1:1080"
	}
	o.listen, err = netip.ParseAddrPort(address)
	if err != nil || o.listen.Addr() != netip.MustParseAddr("127.0.0.1") || o.listen.Port() == 0 {
		return errors.New("export requires a fixed SOCKS listener on 127.0.0.1 with a nonzero port")
	}
	return nil
}

func exportMihomo(ctx context.Context, profile securelink.Profile, opt exportOptions) (tunnel.Report, error) {
	session, report, err := tunnel.Open(ctx, profile)
	if err != nil {
		return report, err
	}
	defer session.Close()
	remote, err := netip.ParseAddrPort(report.Remote)
	if err != nil {
		return report, errors.New("invalid authenticated VPN remote")
	}
	select {
	case <-session.Done():
		return report, errors.New("VPN disconnected before export")
	default:
	}
	err = mihomo.Write(ctx, opt.output, session.ACL(), mihomo.Options{
		Remote: remote, Listen: opt.listen, GeneratedAt: time.Now(), Fragment: opt.fragment,
	})
	return report, err
}
