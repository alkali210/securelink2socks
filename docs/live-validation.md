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

## Remaining acceptance gate

The reference project's two documented endpoints were checked against the
current account's ACL. Neither was authorized, so no direct or tunneled TCP
connection was attempted to either target. There was no address/port scan and
no use of reference credentials. A known authorized XMU-internal TCP endpoint
is still needed to prove direct-host failure versus userspace success.

The initial plan explicitly requires that proof before SOCKS implementation.
SOCKS, reconnect, Mihomo and throughput acceptance therefore remain incomplete.
The successful handshake/keepalive results are not full proxy acceptance.

## Offline checks

Project tests, go vet, dependency serial tests and Windows build pass. Tests
include an independent Python HMAC PRF vector, EKM and legacy-PRF memory AEAD
echo, long peer-info record boundaries, continuation assembly/fail-closed
behavior, certificate policy and ACL port/domain restrictions. Test fixtures
contain synthetic values only. Live checks remain opt-in.
