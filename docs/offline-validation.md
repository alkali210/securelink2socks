# Offline validation — 2026-09-24

Environment: Windows/amd64, Go 1.26.4. No real XMU requests were made.

| Check | Result |
| --- | --- |
| `go test -cover ./...` | Passed all project packages |
| `go vet ./...` | Passed |
| Windows CLI build and `--help` | Passed |
| Live-test guard | `TestLiveXMU` skipped without `SECURELINK2SOCKS_E2E=1` |
| Pinned dependency profile parse | Passed with synthetic CA, tls-auth and AEAD profile |
| Custom PUSH preservation regression | Passed: parse → public view → reconnect callback |
| Dependency source comparison | Only conn.go/openvpn.go modified; raw_push_test.go added |

Project tests cover independent crypto goldens, encrypted mocked SSO/refresh/API
flows, stale token-expiry replacement, callback/JWT parsing, state replacement,
device persistence, PEM encoding, peer-info forwarding, unsupported CBC and
missing server identity rejection, no target/remote DNS, and malformed ACLs.
The tests do not prove the actual endpoint speaks the modeled protocol.

Statement coverage: securelink 81.4%, ACL 94.6%, storage 62.5%, CLI 15.9%, tunnel
8.7%. Browser interaction and real tunnel/network branches were not executed.

The full upstream dependency test run passed all packages except
`internal/session`, where `TestFirstPingAES128GCM` timed out under concurrent test
load. That test passed in isolation, and the entire session package then passed
with `-parallel 1 -count=1` (33.5 seconds). The initial concurrent runs also
encountered Windows sandbox/cache access failures. No upstream protocol logic
was changed to mask the failures. The complete default-parallel suite cannot
therefore be claimed consistently green in this environment.

Pending live evidence: real login/refresh/config, negotiated transport/cipher,
server identity/control protection, exact raw app grammar, nonempty ACL, real
authorized TCP reachability and host-network invariance. SOCKS, reconnect,
Mihomo acceptance and throughput measurements have not yet been implemented or
performed at this gated stage.
