package securelink

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func mockClient(t *testing.T, handler func(*http.Request, map[string]any) string) *Client {
	t.Helper()
	c, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	key := []byte("0123456789abcdef")
	c.entropy = bytes.NewReader(bytes.Repeat(key, 100))
	c.http.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Scheme != "https" || r.URL.Host != "svpnlink.xmu.edu.cn" {
			t.Fatal("API origin changed")
		}
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		if r.Header.Get("sheetaSign") != sheetaSign(r.Header.Get("reqTimestamp"), r.Header.Get("nonce"), string(b)) {
			t.Fatal("signature not computed over transmitted body")
		}
		wrapped, err := base64.StdEncoding.DecodeString(r.Header.Get("secret"))
		if err != nil || len(wrapped) != 128 {
			t.Fatal("missing wrapped secret")
		}
		enc, err := base64.StdEncoding.DecodeString(string(b))
		if err != nil {
			t.Fatal(err)
		}
		plain, err := decryptCBC(key, bodyIV, enc)
		if err != nil {
			t.Fatal(err)
		}
		var payload map[string]any
		if err = json.Unmarshal(plain, &payload); err != nil {
			t.Fatal(err)
		}
		reply := handler(r, payload)
		enc, err = encryptCBC(key, bodyIV, []byte(reply))
		if err != nil {
			t.Fatal(err)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(base64.StdEncoding.EncodeToString(enc))), Header: make(http.Header)}, nil
	})
	return c
}

func TestSSORefreshAndConfig(t *testing.T) {
	token := testJWT(`{"username":"student-test","userId":12,"deviceId":"device-test","exp":4102444800}`)
	var paths []string
	c := mockClient(t, func(r *http.Request, p map[string]any) string {
		paths = append(paths, r.URL.Path)
		switch r.URL.Path {
		case "/authApi/sso/authConfig/getAuthConfig":
			if p["org"] != "xmu" || r.Header.Get("apiVersion") != "5.14.0.0" {
				t.Fatal("wrong discovery identity")
			}
			b, e := os.ReadFile("../../testdata/securelink/auth-config.json")
			if e != nil {
				t.Fatal(e)
			}
			return string(b)
		case "/authApi/sso/authConfig/getAuthUrl":
			return `{"returnCode":1,"content":{"loginUrl":"https://example.invalid/sso"}}`
		case "/authApi/sso/authConfig/validateCode":
			if p["code"] != "test+code" || p["name"] != "test-sso" {
				t.Fatal("bad code/provider")
			}
			return `{"returnCode":1,"content":{"token":"synthetic-two-factor"}}`
		case "/authApi/is/sso/login":
			if r.Header.Get("Authorization") != "Bearer synthetic-two-factor" || p["version"] != "3.8.1" || len(p["deviceId"].(string)) != 32 {
				t.Fatal("wrong login identity")
			}
			return `{"returnCode":1,"content":{"loginMessage":{"accessToken":"` + token + `","refreshToken":"refresh-one","accessTokenExpire":4102444800000}}}`
		case "/authApi/is/code/refreshToken":
			if r.Header.Get("Authorization") != "Bearer refresh-one" || r.Header.Get("apiVersion") != "4.26.0.0" {
				t.Fatal("bad refresh headers")
			}
			return `{"returnCode":"1","content":{"token":"` + testJWT(`{"exp":4102445800}`) + `","refreshToken":"refresh-two"}}`
		case "/networkApi/is/network/initConfig":
			if r.Header.Get("SlServerType") == "" || r.Header.Get("apiVersion") != "5.0.0.0" || p["dns"] != "" {
				t.Fatal("bad network configuration request")
			}
			return `{"returnCode":1,"content":{"networkConfig":{"clientConf":"synthetic"}}}`
		default:
			t.Fatalf("unexpected API %s", r.URL.Path)
			return ""
		}
	})
	if err := c.Login(context.Background(), "securelink://callback?code=test%2Bcode", nil); err != nil {
		t.Fatal(err)
	}
	if len(paths) != 4 || !c.session.Valid(time.Now()) {
		t.Fatal("login failed")
	}
	loaded, err := New(c.dir)
	if err != nil || loaded.session.AccessToken != token {
		t.Fatal("session roundtrip failed")
	}
	if err = c.EnsureSession(context.Background(), false); err != nil || len(paths) != 4 {
		t.Fatal("valid session should not use API")
	}
	if err = c.EnsureSession(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if c.session.AccessTokenExpire != 4102445800 || c.session.RefreshToken != "refresh-two" {
		t.Fatal("refresh retained stale expiry/token")
	}
	if _, err = c.VPNConfig(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestSessionExpiryAndMalformedStorage(t *testing.T) {
	now := time.Unix(1000, 0)
	for _, tc := range []struct {
		s     Session
		valid bool
	}{{Session{}, false}, {Session{AccessToken: "opaque", AccessTokenExpire: 1300}, false}, {Session{AccessToken: "opaque", AccessTokenExpire: 1301}, true}, {Session{AccessToken: testJWT(`{"exp":2000}`)}, true}} {
		if tc.s.Valid(now) != tc.valid {
			t.Fatal("expiry boundary")
		}
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "session.json"), []byte("secret-invalid-json"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(dir); err == nil || strings.Contains(err.Error(), "secret-invalid-json") {
		t.Fatal("invalid session leaked/accepted")
	}
}

func TestAPIRejectsFailureWithoutLeaking(t *testing.T) {
	c := mockClient(t, func(*http.Request, map[string]any) string { return `{"returnCode":0,"returnMsg":"secret-token"}` })
	_, err := c.post(context.Background(), "/test", "1", "", map[string]any{})
	if !errors.Is(err, ErrNeedsLogin) || strings.Contains(err.Error(), "secret-token") {
		t.Fatal("server error leaked")
	}
	c.http.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 403, Body: io.NopCloser(strings.NewReader("secret"))}, nil
	})
	_, err = c.post(context.Background(), "/test", "1", "", map[string]any{})
	if !errors.Is(err, ErrNeedsLogin) {
		t.Fatal("403 should require login")
	}
}

func TestInvalidRefreshRetainsSession(t *testing.T) {
	c := mockClient(t, func(*http.Request, map[string]any) string { return `{"returnCode":1,"content":{"refreshToken":"bad"}}` })
	c.session = Session{AccessToken: "old", RefreshToken: "old-refresh", AccessTokenExpire: 1}
	if err := c.EnsureSession(context.Background(), false); err == nil {
		t.Fatal("accepted refresh without new access token")
	}
	if c.session.AccessToken != "old" || c.session.RefreshToken != "old-refresh" {
		t.Fatal("invalid response mutated session")
	}
}
