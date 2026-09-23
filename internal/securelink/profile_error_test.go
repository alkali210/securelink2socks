package securelink

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestProfileErrorDiagnostics(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"missing control-channel protection: provide tls-crypt, tls-crypt-v2 or tls-auth (this library requires a protected control channel)", "missing tls-auth/tls-crypt"},
		{"comp-lzo is not supported (compression is disabled)", "unsupported LZO compression"},
		{`cipher "AES-256-CBC" is not supported (AEAD only: AES-256-GCM, AES-128-GCM, CHACHA20-POLY1305)`, "unsupported non-AEAD cipher"},
		{"ca[0]: no certificates parsed (PEM malformed?)", "no valid PEM certificates"},
	} {
		got := profileParseError(errors.New(tc.input)).Error()
		if !strings.Contains(got, tc.want) {
			t.Errorf("diagnostic = %q, want %q", got, tc.want)
		}
	}
}

func TestProfileErrorDoesNotReflectSecretValues(t *testing.T) {
	for _, source := range []error{
		fmt.Errorf("line 17 (secret-token): %w", errors.New("proto: unsupported value secret-token")),
		errors.New("compress secret-token is not supported"),
		errors.New(`cipher "secret-token" is not supported (AEAD only: AES-256-GCM, AES-128-GCM, CHACHA20-POLY1305)`),
		errors.New("client cert/key pair: secret-token"),
	} {
		got := profileParseError(source).Error()
		if strings.Contains(got, "secret-token") {
			t.Fatal("upstream profile value leaked")
		}
	}
	got := profileParseError(fmt.Errorf("line 17 (compress): %w", errors.New("compress secret-token is not supported"))).Error()
	if !strings.Contains(got, "at line 17") || !strings.Contains(got, "unsupported compression mode") {
		t.Fatal("lost safe location/reason")
	}
}
