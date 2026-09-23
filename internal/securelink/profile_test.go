package securelink

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/n0madic/go-openvpn/pkg/ovpn"
)

func profileFixture(t *testing.T) (*Client, json.RawMessage) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	b, err := os.ReadFile("../../testdata/securelink/vpn-config.json")
	if err != nil {
		t.Fatal(err)
	}
	b = []byte(strings.ReplaceAll(string(b), "{{TEST_CA}}", url.QueryEscape(string(cert))))
	// A synthetic tls-auth static key satisfies upstream's mandatory protected
	// control channel. This all-zero test key is never used on a live endpoint.
	b = []byte(strings.ReplaceAll(string(b), "%3C%2Fca%3E", "%3C%2Fca%3E"+url.QueryEscape("\nkey-direction 1\n<tls-auth>\n-----BEGIN OpenVPN Static key V1-----\n"+strings.Repeat("0", 512)+"\n-----END OpenVPN Static key V1-----\n</tls-auth>")))
	c, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c.session = Session{AccessToken: testJWT(`{"username":"student-test","userId":12,"deviceId":"device-test","exp":4102444800}`), ServerType: "synthetic-server-type"}
	return c, b
}

func TestProfileParsesPinnedDependencyAndPeerInfo(t *testing.T) {
	c, b := profileFixture(t)
	p, err := c.Profile(b)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := p.Parse()
	if err != nil {
		_, detail := ovpn.Parse(strings.NewReader(p.Text), nil)
		t.Fatalf("synthetic profile parse: %v (%v)", err, detail)
	}
	if parsed.Config.Network != "tcp" || parsed.Config.RemoteAddr != "192.0.2.1:10000" {
		t.Fatal("wrong VPN transport/remote")
	}
	if parsed.Config.Username != "student-test" || parsed.Config.Password != managementPassword("student-test") {
		t.Fatal("wrong VPN credentials")
	}
	if parsed.Config.PeerInfoExtra["UV_CODE"] != c.session.AccessToken || parsed.Config.PeerInfoExtra["UV_USERID"] != "12" || len(parsed.Config.PeerInfoExtra) != 17 {
		t.Fatal("peer-info not forwarded through ovpn parser")
	}
	if len(parsed.Config.Ciphers) != 1 || parsed.Config.Ciphers[0] != "AES-256-GCM" {
		t.Fatal("cipher policy changed")
	}
}

func TestNormalizationPreservesCertificateAndCipher(t *testing.T) {
	p, err := normalizeProfile("client\nproto+tcp-client\nauth-user-pass\ndev-node+ignored\nfragment+1300\nmssfix+0\ncipher+AES-256-CBC\n<ca>\nabc+def/==\n</ca>\n")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(p, "abc+def/==") || !strings.Contains(p, "cipher AES-256-CBC") || !strings.Contains(p, "proto tcp-client") || strings.Contains(p, "dev-node") {
		t.Fatal("normalization changed protected content")
	}
	for _, line := range []string{"ca file.pem", "auth-user-pass file.txt\nconfig other.ovpn", "<connection>\nremote x\n</connection>", "<ca>\nunclosed", "setenv UV_CODE injected"} {
		if _, err := normalizeProfile(line); err == nil {
			t.Fatalf("accepted unsupported profile %q", line)
		}
	}
}

func TestProfileRejectsCBCWithoutLiveProof(t *testing.T) {
	c, b := profileFixture(t)
	b = []byte(strings.ReplaceAll(string(b), "AES-256-GCM", "AES-256-GCM:AES-256-CBC"))
	p, err := c.Profile(b)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.Parse(); err == nil {
		t.Fatal("silently stripped unsupported CBC")
	}
}

func TestProfileRejectsDNSAndInjection(t *testing.T) {
	c, b := profileFixture(t)
	if _, err := c.Profile([]byte(strings.ReplaceAll(string(b), "192.0.2.1", "vpn.example"))); err == nil {
		t.Fatal("accepted remote requiring DNS")
	}
	c.session.ServerType = "injected\nremote 198.51.100.1 443"
	if _, err := c.Profile(b); err == nil {
		t.Fatal("accepted peer-info line injection")
	}
}

func TestProfileRequiresServerIdentity(t *testing.T) {
	c, b := profileFixture(t)
	b = []byte(strings.ReplaceAll(string(b), "verify-x509-name+gateway.example+name%0A", ""))
	p, err := c.Profile(b)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.Parse(); err == nil {
		t.Fatal("relaxed TLS identity verification")
	}
}
