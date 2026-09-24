// SPDX-License-Identifier: AGPL-3.0-or-later
package securelink

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"strings"

	"github.com/n0madic/go-openvpn/pkg/ovpn"
)

// ParseAEADProbe is an explicit compatibility experiment, not normal profile
// normalization. The original profile remains unchanged. It advertises only
// implemented AEAD ciphers and never falls back to CBC or unauthenticated TLS.
func (p Profile) ParseAEADProbe() (*ovpn.Parsed, error) {
	// The authenticated XMU API supplies the trust anchor. For profiles using
	// OpenVPN's CA + server-role identity policy, require both inline CA and the
	// explicit role directive before allowing a missing hostname constraint.
	hasCA, serverRole := false, false
	block := ""
	for _, line := range strings.Split(p.Text, "\n") {
		line = strings.TrimSpace(line)
		if block != "" {
			if line == "</"+block+">" {
				block = ""
			}
			continue
		}
		if strings.HasPrefix(line, "<") && strings.HasSuffix(line, ">") {
			block = strings.Trim(line, "<>")
			if block == "ca" {
				hasCA = true
			}
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "remote-cert-tls" && fields[1] == "server" {
			serverRole = true
		}
	}
	if !hasCA || !serverRole {
		return nil, errors.New("AEAD probe requires inline CA and remote-cert-tls server from XMU profile")
	}
	text := p.Text + "\ndata-ciphers AES-128-GCM:AES-256-GCM:CHACHA20-POLY1305\n"
	parsed, err := ovpn.Parse(strings.NewReader(text), &ovpn.ParseOptions{
		Username: p.Username, Password: p.Password, AllowPlainControl: true, AllowNoServerIdentity: true,
	})
	if err != nil {
		return nil, profileParseError(err)
	}
	if parsed.Config.TLSConfig.RootCAs == nil {
		return nil, errors.New("AEAD probe has no trusted XMU CA")
	}
	verify := parsed.Config.TLSConfig.VerifyConnection
	parsed.Config.TLSConfig.VerifyConnection = func(cs tls.ConnectionState) error {
		if verify != nil {
			if err := verify(cs); err != nil {
				return err
			}
		}
		// x509.Verify treats an absent EKU extension as unrestricted. Require
		// explicit serverAuth, matching the supplied remote-cert-tls server.
		if len(cs.PeerCertificates) == 0 {
			return errors.New("missing VPN server certificate")
		}
		for _, eku := range cs.PeerCertificates[0].ExtKeyUsage {
			if eku == x509.ExtKeyUsageServerAuth {
				return nil
			}
		}
		return errors.New("VPN certificate lacks explicit serverAuth usage")
	}
	return parsed, nil
}
