package main

import (
	"context"
	"io"
	"path/filepath"
	"testing"
)

func TestExportOptions(t *testing.T) {
	t.Setenv("SECURELINK2SOCKS_LISTEN", "127.0.0.1:12345")
	home := t.TempDir()
	opt, err := parseExportOptions([]string{"--fragment"})
	if err != nil {
		t.Fatal(err)
	}
	if err = opt.resolve(home); err != nil {
		t.Fatal(err)
	}
	if opt.output != filepath.Join(home, "mihomo.fragment.yaml") || opt.listen.Port() != 12345 {
		t.Fatal("incorrect export defaults")
	}
	for _, args := range [][]string{{"--unknown"}, {"--output"}, {"extra"}} {
		if _, err := parseExportOptions(args); err == nil {
			t.Fatal("invalid args accepted")
		}
	}
	t.Setenv("SECURELINK2SOCKS_HOME", home)
	if err := run(context.Background(), []string{"export-mihomo", "--output", "session.json"}, io.Discard); err == nil {
		t.Fatal("invalid extension accepted")
	}
	t.Setenv("SECURELINK2SOCKS_LISTEN", "0.0.0.0:1080")
	if err := run(context.Background(), []string{"export-mihomo"}, io.Discard); err == nil {
		t.Fatal("invalid listener accepted")
	}
}
