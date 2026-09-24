# XMU compatibility investigation — 2026-09-24

The user authorized the AEAD-only experiment and supplied their own SSO login.
No tokens, usernames, passwords, raw profiles or raw server messages are kept
in this report. References were cloned outside this repository.

Confirmed observations:

- Browser SSO, cached-session loading, API refresh and VPN configuration work.
- The supplied profile uses TCP, AES-256-CBC, inline CA and
  `remote-cert-tls server`, without tls-auth/tls-crypt or a hostname constraint.
  The normal strict parser therefore rejects it.
- The opt-in experiment retains CA chain verification and requires explicit
  serverAuth EKU. It advertises only implemented AEAD ciphers.
- The experimental connection completes the verified inner TLS handshake and
  receives server KEY_METHOD 2. The gateway rejects PUSH_REQUEST with
  AUTH_FAILED and no reason. One forced API refresh and retry has the same
  result. No cipher, assigned IPv4 or app ACL has been received.
- The user reports official SecureLink works and confirmed it was disconnected
  before the latest trial; rejection persists with it disconnected.
- The final build with corrected AES-128-GCM key-size advertisement still
  receives the same rejection, including after the bounded refresh/retry.

Validation completed: project `go test ./...`, `go vet ./...`, dependency
`go test -parallel 1 ./...`, and Windows CLI build. After the final rekey
key-size change, the session package passed again. Error-redaction tests and
the original opt-in live-test guard are retained; offline tests use synthetic
credentials only.

Dependency defects corrected during investigation: missing ordinary outer
control framing; split TLS writes for control commands and their NUL terminator;
UDP options advertised over TCP; non-native Windows platform name; and 256-bit
key size advertised for AES-128-GCM. See upstream-patch.md for details/tests.
These corrections alone do not establish the cause of XMU authentication
rejection.

Credential construction was compared to both reference implementations. Their
actual config builders use the access token for UV_CODE and the same encrypted,
URL-encoded management password and UV fields. MySecureLink also contains an
older TMP-token helper, but its config builder does not use that helper; there
is insufficient evidence to switch this implementation to a TMP token.

The experiment opens only the API and gateway sockets. It creates no host VPN
interface, route, DNS setting or SOCKS listener, and performs no private-address
scan. Full host-state invariance and real userspace TCP have not been accepted.

Remaining gate: explain AUTH_FAILED using fresh-session or native-client
comparison evidence, then verify AEAD, exact raw app grammar, nonempty ACL and
an authorized userspace TCP target. SOCKS/reconnect and throughput work remain
blocked by the implementation plan's real-handshake gate.
