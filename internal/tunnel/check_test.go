package tunnel

import (
	"context"
	"net/netip"
	"os"
	"testing"
	"time"

	"securelink2socks/internal/securelink"
	"securelink2socks/internal/storage"
)

func TestCheckRejectsInvalidProfile(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	report, err := Check(ctx, securelink.Profile{}, netip.AddrPort{})
	if err == nil || report.IPv4 != "" || report.TCPConnected {
		t.Fatal("invalid profile accepted")
	}
}

// Deliberately does not prompt or send application payloads. Obtain a cached
// session with the login command before explicitly opting in.
func TestLiveXMU(t *testing.T) {
	if os.Getenv("SECURELINK2SOCKS_E2E") != "1" {
		t.Skip("live XMU test requires SECURELINK2SOCKS_E2E=1")
	}
	home, err := storage.Home()
	if err != nil {
		t.Fatal(err)
	}
	c, err := securelink.New(home)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if err = c.EnsureSession(ctx, false); err != nil {
		t.Fatalf("cached session unavailable; run login: %v", err)
	}
	content, err := c.VPNConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := c.Profile(content)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Check(ctx, profile, netip.AddrPort{})
	if err != nil {
		t.Fatal(err)
	}
}
