// SPDX-License-Identifier: AGPL-3.0-or-later
package openvpn

import "testing"

func TestPlainControlRequiresOptIn(t *testing.T) {
	if err := validateControlChannel(&Config{}); err == nil {
		t.Fatal("default accepts missing control key")
	}
	cfg := &Config{AllowPlainControl: true}
	if err := validateControlChannel(cfg); err != nil {
		t.Fatal(err)
	}
	if !sessionCfg(cfg).AllowPlainControl {
		t.Fatal("plain control opt-in lost")
	}
	cfg.TLSAuth = []byte{1}
	cfg.TLSCryptV1 = []byte{1}
	if err := validateControlChannel(cfg); err == nil {
		t.Fatal("opt-in bypasses conflicting-key validation")
	}
}
