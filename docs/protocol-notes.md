# Protocol investigation and implementation status

Investigated 2026-09-24 by reading independent reference checkouts. No live XMU
credentials, session, or authorized TCP endpoint were available. The user
explicitly selected offline implementation/testing. Nothing below should be
read as a successful real-XMU acceptance result.

### Live follow-up: first authenticated profile

After the initial offline stage, the user successfully completed browser SSO
and ran `check`. Reusing that local session reproduced the parser failure.
The API returned a TCP profile with an inline CA, `remote-cert-tls server`, and
`cipher AES-256-CBC`; it contains no tls-auth/tls-crypt key, no data-ciphers list,
and no verify-x509-name. Only those compatibility facts were inspected; no
tokens, CA bytes or profile were written to logs/fixtures.

The immediate rejection is **missing control-channel protection**, before
certificate-identity or cipher validation. This is a limitation of the pinned
library, not a failed SSO login. Ordinary TLS-mode OpenVPN without the optional
tls-auth/tls-crypt outer layer is not implemented by this upstream revision.
Removing its parser check alone would still fail the core client's key
validation/wrapper construction and is not a fix.

The profile's legacy `cipher AES-256-CBC` is not evidence of the actually
negotiated data cipher. AEAD support remains unknown. Implementing a TLS-only
control packet wrapper, deciding the CA/server-role identity compatibility
policy, and a controlled AEAD negotiation experiment are needed before this
endpoint can be checked end to end. No cipher or certificate policy was changed
by the diagnostic fix. Errors now expose only allowlisted reason descriptions
and numeric profile line numbers, never raw upstream error values.

The remaining sections describe the original offline findings unless updated
explicitly; real transport handshake, ACL and data-plane acceptance are still
outstanding.

## Exact references

| Repository | Revision | Use |
| --- | --- | --- |
| [xmu_secure_link](https://github.com/XMU-MoYu-Club/xmu_secure_link) | `b4dfa7314aa0d9e36b2c43c87a78a5be59a98b36` | Primary crypto, API, profile and ACL documentation |
| [MySecureLink](https://github.com/XMU-MoYu-Club/MySecureLink) | `cf3f9ec47e92ada831e658a386db15b648836351` | Secondary request signing/encryption reference |
| [go-openvpn](https://github.com/n0madic/go-openvpn) | `12597991e31263f9309a6589dfd63a304349bafc` | Pure-Go transport, profile parser, userspace adapter |

Both OpenVPN modules are pinned to
`v0.0.0-20260704073850-12597991e312`; the root module uses a local, source-preserving
copy with a small documented patch. The netstack module comes from the module
proxy, verified by go.sum. It delegates to go-tun2net/gVisor, not a kernel TUN.
Go minimum is 1.26.3; development verification used Windows/amd64 Go 1.26.4.

Reference clones are in the user's temporary directory, outside this repository.
No reference credentials, native executable, or private key material is used.

## Control-plane sequence

Fixed origin: `https://svpnlink.xmu.edu.cn`; organization: `xmu`.
Fixed User-Agent: `SecureLink/3.8.1 (Windows NT 10.0; Win64; x64)`.

All requests are POST. Objects use sorted-key compact JSON, encrypted with a
fresh random AES-128-CBC key, PKCS#7 padding, and IV `securelink666666`.
The transmitted body is the ciphertext in standard base64 (not a JSON string).
The `secret` header wraps the AES key with the reference public RSA key using
PKCS#1 v1.5. This is protocol compatibility, not a newly designed cryptosystem.

Headers include `certId=secureLink`, millisecond `reqTimestamp`, incrementing
uint32 `nonce`, `apiVersion`, and `sheetaSign`:

```text
uppercase(base64(lowercase_hex(SHA1(
  "secureLink" + "-" + timestamp + "-" + nonce + "-" + transmitted_body
))))
```

Responses are either base64 AES-CBC using the same request key/IV or plain JSON.
`returnCode` accepts numeric/string 1. Non-success codes currently produce a
generic login-required error without reflecting arbitrary server text. HTTP
failures and transport errors are separately reported. Redirects are refused.

| Step | Path | API version | Notes |
| --- | --- | --- | --- |
| Discover SSO | `/authApi/sso/authConfig/getAuthConfig?locale=zh_CN&locale=zh_CN` | `5.14.0.0` | `{authConfigId:null,org:xmu,version:0}`; prefer provider type 1 |
| Get browser URL | `/authApi/sso/authConfig/getAuthUrl?locale=zh_CN&locale=zh_CN` | `5.14.0.0` | `{authConfigId:null,name,org:xmu}` → `content.loginUrl` |
| Validate callback | `/authApi/sso/authConfig/validateCode?locale=zh_CN&locale=zh_CN` | `5.14.0.0` | `{authConfigId:null,code,name,org:xmu,system:"0"}` → temporary token |
| Login | `/authApi/is/sso/login?locale=zh_CN` | `5.14.0.0` | Temporary token as Bearer; reference Windows/device identity body |
| Refresh | `/authApi/is/code/refreshToken` | `4.26.0.0` | Refresh token as Bearer; `{org:xmu,type:1}` |
| VPN config | `/networkApi/is/network/initConfig?locale=zh_CN` | `5.0.0.0` | Access token as Bearer; `{dns:"",intranetIp:"127.0.0.1",system:0,wifiSsid:null}` |

Login/refresh capture `content.loginMessage` first, then `content`;
`accessToken`/`token`, `refreshToken`, `accessTokenExpire` (milliseconds),
`slServerType`/`serverType`. Every token replacement recalculates expiry; it does
not retain the previous token's expiry as the reference implementation can.
If explicit expiry is absent, inspect JWT `exp`. JWT decoding is metadata
inspection only, not signature verification or an authorization decision.

Session reuse requires more than 300 seconds of validity. The temporary SSO
token is not persisted. Server type defaults to RSA-wrapped sorted JSON
`{serverType:"SDP",timestamp:"<milliseconds>"}` and is cached. Cached origin/org
fields from other implementations are ignored so they cannot redirect secrets.

## Profile and peer-info boundary

`content.networkConfig` / `NetworkConfig` contains URL-encoded `clientConf` and
`priorServers`, `alternateServers`, optionally `appaAccConf`.

Normalization decodes percent escapes, changes `+` to spaces in directives and
PEM markers, and preserves base64 `+` in PEM bodies. It removes reference-only
dev-node/fragment/confusion directives, duplicate auth directives and old
remotes. External file references and server-supplied setenv are rejected.
Remotes are deduplicated IPv4:port tuples; absent port lists default to 10000.
No endpoint DNS lookup is performed by the VPN/profile or target path. The
fixed HTTPS control-plane origin still requires ordinary HTTP name resolution.

Username comes from JWT `username`. The management password is percent-encoded
base64 AES-CBC of that username with the fixed reference key/IV. No user password
or example credentials from reference repositories are used.

The generated representation appends `auth-user-pass`, `push-peer-info`,
`ignore-unknown-option app ctrl`, and the reference's 17 `setenv UV_*` values.
Upstream `pkg/ovpn.addSetenv` copies UV keys into `Config.PeerInfoExtra`.
`internal/control` forwards them into KEY_METHOD_2 peer-info; `internal/session`
does the same on rekey. The dependency test verifies all 17 values survive the
profile parser. No manual peer-info injection, log scraping or native plugin is
required.

### Verified XMU compatibility (2026-09-24)

Real API login/refresh/config, verified TLS, AES-128-GCM, assigned IPv4 and
structured ACL acquisition now work. XMU uses ordinary outer control framing
(no tls-auth/tls-crypt), with inner TLS verified against profile CA and explicit
serverAuth EKU. The CLI applies this verified AEAD-only policy by default.

Three interoperability defects were established: adaptive Go TLS records split
KEY_METHOD 2 peer-info; PUSH configuration arrives in continuation bundles;
and this gateway uses OpenVPN PRF rather than TLS-EKM for AEAD key derivation.
After correcting them, 14 authenticated gateway keepalives were received in
15 seconds with zero AEAD-open failures. See live-validation.md for limits.

The Rust executable was not run: its entry point elevates and modifies host
adapters/routes. References were used as source material outside this repository.

## Structured ACL acquisition

The public PushReply.Raw preserves the fully assembled PUSH body. The app layer
parses it directly, without scraping human-readable logs. Observed raw syntax:

```
app [addr:<IPv4 CIDR>][proto:any port:any]
app [addr:<IPv4 CIDR>][proto:tcp port:<decimal>;<decimal>]
app [domain:<domain>][proto:any port:<decimal>]
```

TCP/any rules support decimal single ports and semicolon lists; domain entries
never grant IPv4 access and never trigger DNS. Unknown/malformed app syntax,
unknown protocols and port ranges invalidate the snapshot. Empty ACL denies
traffic. Prefixes normalize and individual prefix/port grants deduplicate; the
observed account produced 66 grants. This count need not match raw app entries.
The older separated-bracket reference fixtures remain supported.

PUSH fragments are bounded and combined before ACL publication. A runtime
PUSH_REPLY/PUSH_UPDATE triggers fail-closed session teardown and complete
reauthentication/config acquisition, rather than applying partial updates.
Backend generations pair the immutable ACL with exactly one tunnel; replacing
them cancels pending dials and closes all old connections. Raw PUSH may contain
tokens and is never printed or persisted.

## Status against milestones

| Milestone | Status |
| --- | --- |
| 0 investigation | Actual AEAD/transport and raw ACL/UV path verified; native baseline not run |
| 1 control plane | Real login, refresh and config verified |
| 2 profile/handshake | TLS, authentication, AES-128-GCM, IPv4 and AEAD keepalive verified |
| 3 ACL | Real nonempty structured snapshot verified |
| 4 userspace TCP | User-provided endpoint connects through netstack; direct-host failure unverified because another VPN is active |
| 5 SOCKS | IPv4 CONNECT/relay, refusals and half-close implemented and tested |
| 6 lifecycle | Generations, revocation, backoff, NeedsLogin and cancellation implemented |
| 7 Mihomo | Isolated official portable client reaches the target through this SOCKS node |
| Performance | Not measured |

No credential or raw live profile/PUSH fixture is committed. Local cached user
sessions are used only by explicitly enabled live diagnostics.
