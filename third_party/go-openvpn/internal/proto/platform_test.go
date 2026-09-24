// SPDX-License-Identifier: AGPL-3.0-or-later
package proto

import "testing"

func TestOpenVPNPlatformNames(t *testing.T) {
	for goos, want := range map[string]string{"windows": "win", "darwin": "mac", "linux": "linux"} {
		if got := platformName(goos); got != want {
			t.Errorf("%s: %s != %s", goos, got, want)
		}
	}
}
