# XMU compatibility investigation — 2026-09-24

The user authorized live diagnostics and provided browser SSO in their own
session directory. No credentials or raw profiles/PUSH are kept in this report.

## Current results

- Real login, API refresh and config succeed.
- TLS chain and explicit serverAuth verification succeed using profile CA.
- TCP gateway handshake selects AES-128-GCM and assigns an IPv4 address.
- Multi-part PUSH provides app ACLs. Parsing yields 66 deduplicated IPv4 TCP
  grants in the initial IPv4-only implementation. Domain grants and VPN-only
  DNS were subsequently added with user authorization (see the extension below).
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

## Mihomo split-routing correction — initial IPv4-only findings, 2026-09-25

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


## Domain ACL/DNS extension acceptance — 2026-09-25

The user explicitly authorized expanding the MVP to domain ACL/DNS support.
The earlier detector refusal is now resolved. Current SOCKS DOMAIN handling
uses exact/wildcard domain-and-port authorization or the existing IPv4-and-port
ACL after resolution. DNS A/CNAME queries go directly through netstack to the
current authenticated PUSH DNS servers. There is no host DNS/hosts lookup or
external fallback, no shared DNS-derived IP authorization, and no cache.
Internal DNS may use UDP/TCP port 53, but SOCKS UDP remains unsupported.

The detector's page grants use ip.xmu.edu.cn, while its IPv4 JSONP script uses
ip4.xmu.edu.cn. The sample Mihomo configuration maps the latter to the former
as a domain alias for the same service, retaining the original TLS hostname
and normal certificate verification. Static IP hosts entries were removed.

Both an isolated official Mihomo v1.19.31 and the user's active FlClash core
at 127.0.0.1:9090 passed:

- https://ip.xmu.edu.cn/: HTTP 200.
- https://ip4.xmu.edu.cn/ip/checkip.js?callback=getIP_xmu: HTTP 200;
  `is_in_xmu` was true, and the reported source was the VPN-assigned IPv4.
- Ordinary public HTTPS: HTTP 200 via DIRECT.
- User-provided campus endpoint: HTTP 301 through XMU, redirects not followed.
- Live-core VPN remained Ready for another 30 seconds. After stopping the test
  VPN, public HTTPS still returned 200 and campus requests failed closed.

The live test restored the original full Clash profile and stopped its test
processes. Users should restart the rebuilt executable and reload mihomo.yaml.
Offline tests cover exact/wildcard/port boundaries, numeric-domain grants,
SOCKS DOMAIN decoding, per-request authorization, DNS response ownership,
CNAME loops, TCP retry, mismatched questions, no-system-hosts lookup, missing
DNS fail-closed behavior, and cancellation on session replacement. The earlier
statement that the detector's TLS EOF was a remote-path problem was disproved
by a raw SOCKS reply 0x02 before this extension; it is not a remaining TLS bug.

Final validation also passed `go test ./...`, `go vet ./...`, Windows binary
build, and the opt-in `TestLiveSOCKS` revocation/reconnect regression against
the user-supplied endpoint. No long-duration or throughput claim is added.

### Full redirect/TUN verification after the user's follow-up

The original 301 check was insufficient to establish normal website access.
Tracing the supplied HTTP endpoint followed `/resouces/pc`, `/cas/login/`, then
`https://ids.xmu.edu.cn/authserver/login`. The public SSO endpoint had been
incorrectly caught by the broad XMU proxy rule. An explicit DIRECT rule for
ids.xmu.edu.cn now precedes that rule. This is intentional public-auth routing,
not failure-triggered fallback for campus destinations.

With a normal browser User-Agent, the complete chain reaches the unified
login page with HTTP 200 through both the explicit 7890 proxy and the user's
active TUN. The default Python User-Agent produced HTTP 404 at the public SSO
page, so browser-like request headers were used for this comparison. No login
form was submitted; post-login application content has not been validated.
The detector simultaneously returned HTTP 200 and `is_in_xmu: true` on both
paths. The original Clash profile was restored and test VPN processes stopped.
Both the rebuilt executable and updated YAML are needed; a running old process
does not acquire domain support when only the YAML is replaced.
