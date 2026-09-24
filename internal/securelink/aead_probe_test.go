package securelink

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func probeProfile(t *testing.T) (Profile, *ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Probe test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	text := "client\ndev tun\nproto tcp\nremote 192.0.2.1 10000\nremote-cert-tls server\ncipher AES-256-CBC\n<ca>\n" + string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})) + "</ca>\n"
	return Profile{Text: text}, key, ca
}

func TestAEADProbeExplicitPolicy(t *testing.T) {
	p, _, _ := probeProfile(t)
	original := p.Text
	if _, err := p.Parse(); err == nil {
		t.Fatal("ordinary parser enabled experiment")
	}
	parsed, err := p.ParseAEADProbe()
	if err != nil {
		t.Fatal(err)
	}
	if p.Text != original {
		t.Fatal("probe changed original profile")
	}
	if !parsed.Config.AllowPlainControl || len(parsed.Config.Ciphers) != 3 {
		t.Fatal("probe policy missing")
	}
	for _, c := range parsed.Config.Ciphers {
		if c != "AES-128-GCM" && c != "AES-256-GCM" && c != "CHACHA20-POLY1305" {
			t.Fatal("non-AEAD advertised")
		}
	}
	if parsed.Config.TLSConfig.VerifyConnection == nil || parsed.Config.TLSConfig.RootCAs == nil {
		t.Fatal("missing certificate verification")
	}
	p.Text = strings.ReplaceAll(p.Text, "remote-cert-tls server\n", "")
	if _, err := p.ParseAEADProbe(); err == nil {
		t.Fatal("probe accepted missing server role")
	}
}

func TestAEADProbeVerifiesChainAndServerRole(t *testing.T) {
	p, key, ca := probeProfile(t)
	parsed, err := p.ParseAEADProbe()
	if err != nil {
		t.Fatal(err)
	}
	verify := parsed.Config.TLSConfig.VerifyConnection
	for _, tc := range []struct {
		name                    string
		eku                     []x509.ExtKeyUsage
		wrongCA, expired, allow bool
	}{
		{"server", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, false, false, true},
		{"client", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, false, false, false},
		{"no EKU", nil, false, false, false},
		{"wrong CA", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, true, false, false},
		{"expired", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			issuerKey, issuer := key, ca
			if tc.wrongCA {
				_, issuerKey, issuer = probeProfile(t)
			}
			leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "test gateway"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: tc.eku, KeyUsage: x509.KeyUsageDigitalSignature}
			if tc.expired {
				leaf.NotBefore = time.Now().Add(-2 * time.Hour)
				leaf.NotAfter = time.Now().Add(-time.Hour)
			}
			der, err := x509.CreateCertificate(rand.Reader, leaf, issuer, &leafKey.PublicKey, issuerKey)
			if err != nil {
				t.Fatal(err)
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			err = verify(tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}})
			if (err == nil) != tc.allow {
				t.Fatalf("verification allowed=%v; want %v", err == nil, tc.allow)
			}
		})
	}
}
