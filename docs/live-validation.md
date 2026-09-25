# XMU compatibility investigation — 2026-09-24

The user authorized live diagnostics and provided browser SSO in their own
session directory. No credentials or raw profiles/PUSH are kept in this report.

## Current results

- Real login, API refresh and config succeed.
- TLS chain and explicit serverAuth verification succeed using profile CA.
- TCP gateway handshake selects AES-128-GCM and assigns an IPv4 address.
- Multi-part PUSH provides app ACLs. Parsing yields 66 deduplicated IPv4 TCP
  grants for this account; domain rules are ignored without DNS.
- The gateway does not select TLS-EKM. Standard OpenVPN KEY_METHOD 2 PRF
  produces working AEAD keys: 14 authenticated keepalives in 15 seconds,
  zero AEAD-open failures. Previously the incorrect EKM path produced zero
  authenticated pings and an AEAD-open failure.
- A read-only before/after comparison of adapter identity/status, IPv4 routes
  and DNS configuration was unchanged during a diagnostic run.

## Causes and corrections

Fresh browser login and disconnecting official SecureLink did not resolve
AUTH_FAILED. The actual authentication failure was removed by disabling Go's
adaptive TLS record sizing: it split a long KEY_METHOD 2 write, whereas native
OpenVPN parses peer-info from a single SSL_read. A synthetic long-token test
failed before and passed after the correction.

The next failure, missing cipher, was a partially read PUSH bundle. Bounded
push-continuation assembly exposed the final cipher/IP fields. The following
ACL failure was the difference between reference log formatting and real raw
syntax: proto and port share brackets, with semicolon-separated port lists.
Finally, data-key derivation had to follow the negotiated PRF/EKM policy.

Earlier fixes include ordinary control framing, complete NUL-terminated
control-message writes, correct transport/key-size options and platform names.
All retain verified TLS and AEAD-only data encryption; none enable CBC.

## SOCKS and lifecycle acceptance — 2026-09-24/25

The reference project's two documented endpoints were checked against the
current account's ACL. Neither was authorized, so no direct or tunneled TCP
connection was attempted to either target. There was no address/port scan and
no use of reference credentials. The user subsequently supplied an authorized
test endpoint and independently confirmed userspace TCP success.

The same endpoint passed the implemented SOCKS path, and an isolated official
Mihomo v1.19.31 portable instance connected through this SOCKS node. A single
read-only HTTP HEAD through that chain returned status 301, proving application
bytes in both directions. The temporary Mihomo used loopback ports, no TUN,
no DNS service, and a reject-all fallback. Both test processes were stopped.
The official release archive SHA256 was
`93d14e9a13b49b2f2d256202d02cc8d14a7c4695edf084cae0f941986bc9c218`.
No existing VPN configuration was changed.

The opt-in `TestLiveSOCKS` also passed: allowed CONNECT; DOMAIN/UDP rejection;
an ACL-denied documentation-range target; forced closure of this application's
own VPN session; old client connection revocation; and recovery through the
same SOCKS listener. Offline tests cover policy updates, half-close, pending
dial cancellation, generation replacement, bounded backoff and NeedsLogin.

Adapter/IPv4-route/DNS snapshots were identical before and after the isolated
Mihomo test. Host direct TCP also succeeded; the user confirmed another VPN
was active. Thus the initial plan's direct-host-failure comparison remains
unverified, with the user's authorization to proceed recorded in conversation.
The implementation's data dial is exclusively netstack and never falls back
to a host connection. No other VPN was stopped or altered.

Remaining acceptance: physical network loss/recovery, long-duration stability,
direct-host comparison without another VPN, and the >=100 Mbps performance
target. No throughput claim is made for the supplied HTTP service.

To repeat the opt-in real test with an authorized literal target:

```powershell
$env:SECURELINK2SOCKS_E2E = '1'
$env:SECURELINK2SOCKS_TEST_TARGET = '<authorized-IPv4>:<port>'
go test ./internal/app -run '^TestLiveSOCKS$' -count=1 -v
```

## Offline checks

Project tests, go vet, dependency serial tests and Windows build pass. Tests
include an independent Python HMAC PRF vector, EKM and legacy-PRF memory AEAD
echo, long peer-info record boundaries, continuation assembly/fail-closed
behavior, certificate policy and ACL port/domain restrictions. Test fixtures
contain synthetic values only. Live checks remain opt-in. `go test -race` was
not available in this environment: cgo is disabled and no C compiler was found
on PATH. Ordinary concurrency/cleanup tests pass; race-detector coverage is not
claimed.
