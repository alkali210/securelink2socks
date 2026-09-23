// SPDX-License-Identifier: AGPL-3.0-or-later
package securelink

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/n0madic/go-openvpn/pkg/ovpn"
)

// Profile contains credentials. Never log it or persist its Text.
type Profile struct{ Text, Username, Password string }

func scalar(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var n json.Number
	if json.Unmarshal(raw, &n) == nil {
		return n.String()
	}
	return ""
}

func (c *Client) Profile(content json.RawMessage) (Profile, error) {
	var envelope map[string]json.RawMessage
	if json.Unmarshal(content, &envelope) != nil {
		return Profile{}, errors.New("invalid VPN configuration")
	}
	network := envelope["networkConfig"]
	if len(network) == 0 {
		network = envelope["NetworkConfig"]
	}
	var config struct {
		ClientConf string         `json:"clientConf"`
		Prior      []remoteConfig `json:"priorServers"`
		Alternate  []remoteConfig `json:"alternateServers"`
		Appa       remoteConfig   `json:"appaAccConf"`
	}
	if json.Unmarshal(network, &config) != nil || config.ClientConf == "" {
		return Profile{}, errors.New("networkConfig.clientConf missing")
	}
	decoded, err := url.PathUnescape(config.ClientConf)
	if err != nil {
		return Profile{}, errors.New("invalid clientConf encoding")
	}
	text, err := normalizeProfile(decoded)
	if err != nil {
		return Profile{}, err
	}
	var remotes []netip.AddrPort
	seen := map[netip.AddrPort]bool{}
	for _, r := range append(append(config.Prior, config.Alternate...), config.Appa) {
		host := r.IP
		if host == "" {
			host = r.Host
		}
		if host == "" {
			continue
		}
		ip, err := netip.ParseAddr(host)
		if err != nil || !ip.Is4() {
			return Profile{}, errors.New("VPN remote must be an IPv4 literal; DNS is disabled")
		}
		ports := r.Ports
		if ports == nil {
			ports = []int{10000}
		}
		for _, port := range ports {
			if port < 1 || port > 65535 {
				return Profile{}, errors.New("invalid VPN remote port")
			}
			ap := netip.AddrPortFrom(ip, uint16(port))
			if !seen[ap] {
				remotes = append(remotes, ap)
				seen[ap] = true
			}
		}
	}
	if len(remotes) == 0 {
		return Profile{}, errors.New("no VPN remotes")
	}
	for _, r := range remotes {
		text += fmt.Sprintf("\nremote %s %d", r.Addr(), r.Port())
	}
	cl, err := claims(c.session.AccessToken)
	if err != nil {
		return Profile{}, err
	}
	var username string
	if json.Unmarshal(cl["username"], &username) != nil || username == "" {
		return Profile{}, errors.New("JWT username missing")
	}
	if c.session.ServerType == "" {
		return Profile{}, errors.New("SecureLink server type missing")
	}
	peer := map[string]string{
		"UV_CODE": c.session.AccessToken, "UV_ENCPASS": "1", "UV_AUTH_TYPE": "2", "UV_SL_VERSION": "3.8.1", "UV_VERSION": "3.8.1", "UV_LOCALE": "zh_CN",
		"UV_SYSTEM_NAME": "V2luZG93cyAxMA==", "UV_SYSTEM_MODEL": "V2luZG93cyAxMA==", "UV_SYSTEM_BITS": "NjQ=", "UV_DEVICE_MODEL": "eDg2XzY0", "UV_DEVICE_NAME": "UEM=",
		"UV_USERID": scalar(cl["userId"]), "UV_DEVICEID": scalar(cl["deviceId"]), "UV_SL_SERVERTYPE": c.session.ServerType,
		"UV_EXTRA_PARAM_1": base64.StdEncoding.EncodeToString([]byte(`{"system":0}`)), "UV_EXTRA_PARAM_2": base64.StdEncoding.EncodeToString([]byte(`{"authType":5}`)), "UV_SERVER_IP": remotes[0].Addr().String(),
	}
	text += "\nauth-user-pass\npush-peer-info\nignore-unknown-option app ctrl\n"
	keys := make([]string, 0, len(peer))
	for k := range peer {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := peer[k]
		if v == "" || strings.ContainsAny(v, "\x00\r\n\t \"\\") {
			return Profile{}, errors.New("invalid peer-info value")
		}
		text += "setenv " + k + " " + v + "\n"
	}
	if strings.ContainsAny(username, "\x00\r\n") {
		return Profile{}, errors.New("invalid VPN username")
	}
	return Profile{Text: text, Username: username, Password: managementPassword(username)}, nil
}

type remoteConfig struct {
	IP    string `json:"ip"`
	Host  string `json:"host"`
	Ports []int  `json:"ports"`
}

// normalizeProfile keeps the upstream compatibility edits, but never changes
// cipher policy. CBC removal needs evidence of a real XMU AEAD negotiation.
func normalizeProfile(decoded string) (string, error) {
	if len(decoded) > 2*1024*1024 || strings.ContainsRune(decoded, '\x00') {
		return "", errors.New("invalid clientConf")
	}
	var lines []string
	block := ""
	for _, line := range strings.Split(decoded, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if block != "" {
			if strings.Contains(line, "-----BEGIN") || strings.Contains(line, "-----END") {
				line = strings.ReplaceAll(line, "+", " ")
			}
			if strings.TrimSpace(line) == "</"+block+">" {
				block = ""
			}
			lines = append(lines, line)
			continue
		}
		line = strings.ReplaceAll(line, "+", " ")
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		directive := fields[0]
		if strings.HasPrefix(directive, "#") || strings.HasPrefix(directive, ";") {
			continue
		}
		if strings.HasPrefix(directive, "<") {
			switch directive {
			case "<ca>", "<cert>", "<key>", "<tls-auth>", "<tls-crypt>", "<tls-crypt-v2>":
				block = strings.Trim(directive, "<>")
			default:
				return "", errors.New("unsupported inline profile block")
			}
			lines = append(lines, line)
			continue
		}
		switch directive {
		case "auth-user-pass", "auth-nocache", "dev-node", "fragment", "enable-confusion-proto", "remote", "push-peer-info":
			continue
		case "mssfix":
			if len(fields) == 2 && fields[1] == "0" {
				continue
			}
		case "ignore-unknown-option":
			if strings.Contains(line, "enable-confusion-proto") {
				continue
			}
		case "ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2", "pkcs12", "config", "secret":
			return "", errors.New("external file references are forbidden in clientConf")
		case "setenv":
			return "", errors.New("server-supplied setenv is not supported")
		}
		lines = append(lines, line)
	}
	if block != "" {
		return "", errors.New("unterminated profile block")
	}
	return strings.Join(lines, "\n"), nil
}

func (p Profile) Parse() (*ovpn.Parsed, error) {
	parsed, err := ovpn.Parse(strings.NewReader(p.Text), &ovpn.ParseOptions{Username: p.Username, Password: p.Password})
	if err != nil {
		if errors.Is(err, ovpn.ErrNoServerIdentity) {
			return nil, errors.New("profile lacks server identity verification; live compatibility investigation required")
		}
		// Upstream parser errors can include raw profile lines and secrets.
		return nil, errors.New("profile is not supported by pinned go-openvpn; check cipher and directive compatibility")
	}
	for _, r := range parsed.Remotes {
		ip, e := netip.ParseAddr(r.Host)
		port, e2 := strconv.Atoi(r.Port)
		if e != nil || !ip.Is4() || e2 != nil || port < 1 || port > 65535 {
			return nil, errors.New("invalid literal IPv4 remote")
		}
	}
	return parsed, nil
}
