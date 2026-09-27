package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"securelink2socks/internal/securelink"
)

func TestOfflineCLI(t *testing.T) {
	for _, arg := range []string{"--help", "help", "-h"} {
		var out bytes.Buffer
		if err := run(context.Background(), []string{arg}, &out); err != nil || !strings.Contains(out.String(), "Login if needed") {
			t.Fatal("missing help", err)
		}
	}
	for _, args := range [][]string{{"unknown"}, {"serve", "extra"}, {"login", "bad"}, {"probe"}, {"probe", "example.com:443"}, {"probe", "[::1]:443"}, {"probe", "192.0.2.1:0"}} {
		if err := run(context.Background(), args, io.Discard); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}

func TestStartupDispatch(t *testing.T) {
	t.Setenv("SECURELINK2SOCKS_E2E", "")
	home := t.TempDir()
	t.Setenv("SECURELINK2SOCKS_HOME", home)
	for _, tc := range []struct {
		name string
		args []string
		want []string
	}{
		{"automatic", nil, []string{"login", "serve"}},
		{"serve", []string{"serve"}, []string{"serve"}},
		{"login", []string{"login"}, []string{"login"}},
		{"forced", []string{"login", "--force"}, []string{"force"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls []string
			svc := services{
				login: func(ctx context.Context, got string, force bool, out io.Writer) error {
					if got != home {
						t.Fatal("wrong state directory")
					}
					if force {
						calls = append(calls, "force")
					} else {
						calls = append(calls, "login")
					}
					return nil
				},
				serve: func(ctx context.Context, got string, out io.Writer) error {
					if got != home {
						t.Fatal("wrong state directory")
					}
					calls = append(calls, "serve")
					return nil
				},
			}
			if err := runWithServices(context.Background(), tc.args, io.Discard, svc); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(calls, tc.want) {
				t.Fatalf("calls %v, want %v", calls, tc.want)
			}
		})
	}
}

func TestAutomaticStartupStopsOnLoginFailureOrCancellation(t *testing.T) {
	t.Setenv("SECURELINK2SOCKS_HOME", t.TempDir())
	failed := errors.New("login failed")
	for _, cancelLogin := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		svc := services{
			login: func(context.Context, string, bool, io.Writer) error {
				if cancelLogin {
					cancel()
					return nil
				}
				return failed
			},
			serve: func(context.Context, string, io.Writer) error {
				t.Fatal("service started after failed/canceled login")
				return nil
			},
		}
		err := runWithServices(ctx, nil, io.Discard, svc)
		cancel()
		want := failed
		if cancelLogin {
			want = context.Canceled
		}
		if !errors.Is(err, want) {
			t.Fatalf("got %v, want %v", err, want)
		}
	}
}

type fakeSession struct {
	ensureErr       error
	ensured, logged bool
}

func (s *fakeSession) EnsureSession(context.Context, bool) error {
	s.ensured = true
	return s.ensureErr
}
func (s *fakeSession) Login(context.Context, string, securelink.CallbackPrompt) error {
	s.logged = true
	return nil
}

func TestAuthenticationOnlyPromptsWhenNeeded(t *testing.T) {
	t.Setenv("SL_CALLBACK_URL", "")
	offline := errors.New("network unavailable")
	for _, tc := range []struct {
		name                         string
		sessionErr                   error
		force, wantEnsure, wantLogin bool
	}{
		{"cached", nil, false, true, false},
		{"expired", securelink.ErrNeedsLogin, false, true, true},
		{"network failure", offline, false, true, false},
		{"forced", nil, true, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &fakeSession{ensureErr: tc.sessionErr}
			err := authenticate(context.Background(), s, tc.force, io.Discard)
			if tc.sessionErr == offline {
				if !errors.Is(err, offline) {
					t.Fatal(err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if s.ensured != tc.wantEnsure || s.logged != tc.wantLogin {
				t.Fatalf("ensure=%v login=%v", s.ensured, s.logged)
			}
		})
	}
}

func TestCanceledCommandsRemainOffline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, args := range [][]string{nil, {"serve"}, {"login"}, {"check"}, {"check", "--aead-probe"}, {"probe", "192.0.2.1:443"}} {
		if err := run(ctx, args, io.Discard); !errors.Is(err, context.Canceled) {
			t.Fatalf("%v: %v", args, err)
		}
	}
}
