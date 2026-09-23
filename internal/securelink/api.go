// SPDX-License-Identifier: AGPL-3.0-or-later
package securelink

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"securelink2socks/internal/storage"
)

const apiBase = "https://svpnlink.xmu.edu.cn"

var ErrNeedsLogin = errors.New("SecureLink login required")

type Session struct {
	AccessToken       string `json:"access_token,omitempty"`
	RefreshToken      string `json:"refresh_token,omitempty"`
	AccessTokenExpire int64  `json:"access_token_expire,omitempty"`
	ServerType        string `json:"sl_server_type,omitempty"`
}

func (s Session) Valid(now time.Time) bool {
	exp := s.AccessTokenExpire
	if exp == 0 {
		if c, err := claims(s.AccessToken); err == nil {
			_ = json.Unmarshal(c["exp"], &exp)
		}
	}
	return s.AccessToken != "" && exp > now.Unix()+300
}

// Client is used serially by the application supervisor.
type Client struct {
	http    *http.Client
	dir     string
	session Session
	nonce   atomic.Uint32
	entropy io.Reader
}

func New(dir string) (*Client, error) {
	jar, _ := cookiejar.New(nil)
	c := &Client{dir: dir, entropy: rand.Reader, http: &http.Client{Timeout: 30 * time.Second, Jar: jar,
		// Never forward request secrets or bearer tokens through redirects.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
	var seed [4]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, err
	}
	c.nonce.Store(binary.BigEndian.Uint32(seed[:]))
	b, err := os.ReadFile(filepath.Join(dir, "session.json"))
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return nil, errors.New("cannot read session file")
	}
	if len(b) > 1024*1024 || json.Unmarshal(b, &c.session) != nil {
		return nil, errors.New("invalid session file")
	}
	return c, nil
}

type response struct {
	ReturnCode json.RawMessage `json:"returnCode"`
	Content    json.RawMessage `json:"content"`
}

func (c *Client) post(ctx context.Context, path, version, token string, payload any) (json.RawMessage, error) {
	// encoding/json sorts map keys, matching Rust's sorted_json.
	var plain bytes.Buffer
	e := json.NewEncoder(&plain)
	e.SetEscapeHTML(false)
	if err := e.Encode(payload); err != nil {
		return nil, err
	}
	key := make([]byte, 16)
	if _, err := io.ReadFull(c.entropy, key); err != nil {
		return nil, err
	}
	encrypted, err := encryptCBC(key, bodyIV, bytes.TrimSuffix(plain.Bytes(), []byte{'\n'}))
	if err != nil {
		return nil, err
	}
	body := base64.StdEncoding.EncodeToString(encrypted)
	secret, err := rsaWrap(key)
	if err != nil {
		return nil, err
	}
	ts, nonce := strconv.FormatInt(time.Now().UnixMilli(), 10), strconv.FormatUint(uint64(c.nonce.Add(1)), 10)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiBase+path, strings.NewReader(body))
	if err != nil {
		return nil, errors.New("cannot construct API request")
	}
	for k, v := range map[string]string{"Accept": "application/json", "Content-Type": "application/json", "User-Agent": "SecureLink/3.8.1 (Windows NT 10.0; Win64; x64)", "apiVersion": version, "certId": "secureLink", "reqTimestamp": ts, "nonce": nonce, "sheetaSign": sheetaSign(ts, nonce, body), "secret": secret} {
		req.Header.Set(k, v)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if c.session.ServerType != "" {
		req.Header.Set("SlServerType", c.session.ServerType)
	}
	res, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("SecureLink API transport failed")
	}
	defer res.Body.Close()
	if res.StatusCode == 401 || res.StatusCode == 403 {
		return nil, ErrNeedsLogin
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("SecureLink HTTP status %d", res.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, 4*1024*1024+1))
	if err != nil || len(b) > 4*1024*1024 {
		return nil, errors.New("invalid API response size")
	}
	if enc, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b))); err == nil {
		b, err = decryptCBC(key, bodyIV, enc)
		if err != nil {
			return nil, errors.New("invalid encrypted API response")
		}
	}
	var result response
	if json.Unmarshal(b, &result) != nil {
		return nil, errors.New("invalid API response JSON")
	}
	if string(result.ReturnCode) != "1" && string(result.ReturnCode) != `"1"` {
		return nil, ErrNeedsLogin
	}
	if len(result.Content) == 0 || string(result.Content) == "null" {
		return nil, errors.New("API response content missing")
	}
	return result.Content, nil
}

func (c *Client) save() error {
	return storage.SaveJSON(filepath.Join(c.dir, "session.json"), c.session)
}

func (c *Client) capture(content json.RawMessage, refreshing bool) error {
	var outer map[string]json.RawMessage
	if json.Unmarshal(content, &outer) != nil {
		return errors.New("invalid login content")
	}
	var inner map[string]json.RawMessage
	_ = json.Unmarshal(outer["loginMessage"], &inner)
	get := func(keys ...string) json.RawMessage {
		for _, m := range []map[string]json.RawMessage{inner, outer} {
			for _, k := range keys {
				if v := m[k]; len(v) > 0 && string(v) != "null" {
					return v
				}
			}
		}
		return nil
	}
	var access, refresh, serverType string
	_ = json.Unmarshal(get("accessToken", "token"), &access)
	if access == "" {
		return errors.New("login response missing access token")
	}
	_ = json.Unmarshal(get("refreshToken"), &refresh)
	_ = json.Unmarshal(get("slServerType", "serverType"), &serverType)
	var exp int64
	rawExp := get("accessTokenExpire")
	if len(rawExp) > 0 {
		if json.Unmarshal(rawExp, &exp) != nil {
			var s string
			_ = json.Unmarshal(rawExp, &s)
			exp, _ = strconv.ParseInt(s, 10, 64)
		}
		exp /= 1000
	}
	// Never retain the expiry of the previous access token after refresh.
	if exp == 0 {
		if v, err := claims(access); err == nil {
			_ = json.Unmarshal(v["exp"], &exp)
		}
	}
	next := Session{AccessToken: access, RefreshToken: refresh, AccessTokenExpire: exp, ServerType: serverType}
	if next.RefreshToken == "" && refreshing {
		next.RefreshToken = c.session.RefreshToken
	}
	if next.ServerType == "" {
		next.ServerType = c.session.ServerType
	}
	c.session = next
	return c.save()
}

// EnsureSession reuses/refreshes cached credentials; it never prompts.
func (c *Client) EnsureSession(ctx context.Context, forceRefresh bool) error {
	if !forceRefresh && c.session.Valid(time.Now()) {
		return nil
	}
	if c.session.RefreshToken == "" {
		return ErrNeedsLogin
	}
	r, err := c.post(ctx, "/authApi/is/code/refreshToken", "4.26.0.0", c.session.RefreshToken, map[string]any{"org": "xmu", "type": 1})
	if err != nil {
		return err
	}
	return c.capture(r, true)
}

type CallbackPrompt func(context.Context, string) (string, error)

func (c *Client) Login(ctx context.Context, callback string, prompt CallbackPrompt) error {
	const query = "?locale=zh_CN&locale=zh_CN"
	r, err := c.post(ctx, "/authApi/sso/authConfig/getAuthConfig"+query, "5.14.0.0", "", map[string]any{"authConfigId": nil, "org": "xmu", "version": 0})
	if err != nil {
		return err
	}
	var config struct {
		List []struct {
			Name string `json:"name"`
			Type int    `json:"type"`
		} `json:"list"`
	}
	if json.Unmarshal(r, &config) != nil || len(config.List) == 0 {
		return errors.New("no SSO provider")
	}
	name := config.List[0].Name
	for _, p := range config.List {
		if p.Type == 1 {
			name = p.Name
			break
		}
	}
	if name == "" {
		return errors.New("SSO provider name missing")
	}
	r, err = c.post(ctx, "/authApi/sso/authConfig/getAuthUrl"+query, "5.14.0.0", "", map[string]any{"authConfigId": nil, "name": name, "org": "xmu"})
	if err != nil {
		return err
	}
	var authURL struct {
		LoginURL string `json:"loginUrl"`
	}
	if json.Unmarshal(r, &authURL) != nil || authURL.LoginURL == "" {
		return errors.New("SSO login URL missing")
	}
	if callback == "" {
		if prompt == nil {
			return ErrNeedsLogin
		}
		callback, err = prompt(ctx, authURL.LoginURL)
		if err != nil {
			return err
		}
	}
	code, err := CallbackCode(callback)
	if err != nil {
		return err
	}
	r, err = c.post(ctx, "/authApi/sso/authConfig/validateCode"+query, "5.14.0.0", "", map[string]any{"authConfigId": nil, "code": code, "name": name, "org": "xmu", "system": "0"})
	if err != nil {
		return err
	}
	var validated struct {
		Token string `json:"token"`
	}
	if json.Unmarshal(r, &validated) != nil || validated.Token == "" {
		return errors.New("SSO validation token missing")
	}
	id, err := storage.DeviceID(c.dir)
	if err != nil {
		return err
	}
	r, err = c.post(ctx, "/authApi/is/sso/login?locale=zh_CN", "5.14.0.0", validated.Token, map[string]any{
		"archType": 0, "deviceId": id, "deviceMac": "00:00:00:00:00:00", "deviceModel": "x86_64", "deviceName": "PC", "org": "xmu", "password": "ZXJyb3I=", "system": "0", "systemBits": "64", "systemModel": "Windows 10", "systemName": "Windows 10", "version": "3.8.1",
	})
	if err != nil {
		return err
	}
	return c.capture(r, false)
}

func (c *Client) VPNConfig(ctx context.Context) (json.RawMessage, error) {
	if err := c.EnsureSession(ctx, false); err != nil {
		return nil, err
	}
	if c.session.ServerType == "" {
		b, _ := json.Marshal(map[string]string{"serverType": "SDP", "timestamp": strconv.FormatInt(time.Now().UnixMilli(), 10)})
		s, err := rsaWrap(b)
		if err != nil {
			return nil, err
		}
		c.session.ServerType = s
		if err = c.save(); err != nil {
			return nil, err
		}
	}
	return c.post(ctx, "/networkApi/is/network/initConfig?locale=zh_CN", "5.0.0.0", c.session.AccessToken, map[string]any{"dns": "", "intranetIp": "127.0.0.1", "system": 0, "wifiSsid": nil})
}
