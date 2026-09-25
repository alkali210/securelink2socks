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

## Mihomo split-routing correction — 2026-09-25

The original example's `MATCH,XMU` incorrectly sent ordinary internet and
potential VPN bootstrap traffic into the campus gateway. Fail-closed behavior
belongs to campus requests; it does not require routing all public traffic
through SecureLink. The updated configuration routes the SecureLink process,
control-plane hosts and observed gateway directly, sends XMU domains and the
explicit campus IP targets through SOCKS, and uses DIRECT for other traffic.
Campus UDP is rejected explicitly.

The user's existing FlClash API on 127.0.0.1:9090 reported an active TUN despite
the example disabling TUN. Tests preserved that active TUN configuration,
temporarily loaded the corrected profile via the API, and restored the original
full profile afterward. No persistent FlClash profile file was edited. Test VPN
processes were stopped afterward.

The configuration passes official Mihomo v1.19.31 `-t` and was accepted by the
user's running core (API version string `1.10.0`). Both the isolated official
core and the user's core produced these results:

- Ordinary HTTPS internet request: HTTP 200 through DIRECT.
- User-supplied campus HTTP endpoint: HTTP 301 through XMU (redirects not followed).
- The live core test held the VPN Ready for a further 30 seconds without a
  Reconnecting transition. This is a short regression check, not a stability test.
- After stopping only the test VPN, ordinary HTTPS still returned 200 and the
  campus request failed, confirming there was no campus-to-DIRECT fallback.

`hosts` entries map `ip.xmu.edu.cn` and `ip4.xmu.edu.cn` to their public A record
210.34.0.61, queried on this date. Mihomo's hosts handling removes the domain
from SOCKS dial metadata while preserving the application's TLS hostname.
Other campus domains need equivalent real IPv4 mappings until domain handling
is implemented elsewhere; ordinary DNS configuration alone is insufficient.
Do not substitute a `type: direct` node with `dialer-proxy`: v1.19.31 accepted
that experiment's configuration but did not use the intended SOCKS path.

Campus detector acceptance remains blocked by the IPv4-only ACL policy, not
an established remote TLS problem. The user confirmed that the official client
opens the detector and reports campus access. Inspecting only relevant server
options showed `app [domain:ip.xmu.edu.cn][proto:tcp port:443]`. The current
parser deliberately ignores domain grants, and 210.34.0.61:443 is not allowed
by its IPv4 snapshot. A raw SOCKS test returned `05 02 00 01 00 00 00 00 00 00`
(reply 0x02, ACL denied). Mihomo's early HTTP CONNECT response had obscured this
local refusal as a subsequent TLS EOF; that response did not prove a VPN TCP
connection to the detector. Static hosts cannot add the missing authorization.

The detector page uses ip4.xmu.edu.cn for its IPv4 result. Its direct-path
baseline returned `is_in_xmu: false`; there is no tunneled detector result.
Server-pushed DNS resolvers were inspected, but the current TCP ACL did not
authorize DNS queries to them, so none were sent. Domain ACL/DNS support is
explicitly outside the initial MVP scope and requires a scope decision before
implementation. IPv6 detection remains outside the gateway scope.
