# Offline validation — 2026-09-24

Environment: Windows/amd64, Go 1.26.4. This records the initial offline phase;
subsequent authorized real XMU requests are recorded in live-validation.md.

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

Initially pending live evidence: real login/refresh/config, negotiated transport/cipher,
server identity/control protection, exact raw app grammar, nonempty ACL, real
authorized TCP reachability and host-network invariance. SOCKS, reconnect,
Mihomo acceptance and throughput measurements have not yet been implemented or
performed at this gated stage.

## Fork/submodule migration — 2026-09-25

Environment: Windows/amd64, Go 1.27.0. This validates repository and dependency
packaging; no live XMU requests or system VPN changes were made.

- Fork `alkali210/go-openvpn`, branch `patched`, is based on upstream
  `12597991e31263f9309a6589dfd63a304349bafc`.
- Final submodule pin: `d20ba6de22b44faed37c5b079e0da7561179bceb`.
- Four historical dependency changes were migrated as independent commits.
  All 79 original files matched Git blobs before adding fork documentation.
  Existing production code and tests remain unchanged in the final checkout.
- The full upstream tree restores an additional reconnect test fixture.
  Its mock peer already used TLS-EKM but did not advertise it; adding the
  explicit PUSH option fixed the stalled echo test. Both restored reconnect
  tests and the complete root suite then passed.
- `go test -timeout 5m ./...` and `go vet ./...` passed for securelink2socks.
- Fork `go test -parallel 1 -timeout 5m ./...`, `go vet ./...`, and separate
  `go -C pkg/netstack test -timeout 5m ./...` passed.
- `go mod tidy -diff` reported no changes. Module inspection confirmed the
  root uses the local submodule and netstack retains its upstream version.
- A fresh recursive clone of the local main-project commit fetched the pinned
  submodule from GitHub and built all six Windows/Linux/macOS amd64/arm64
  targets with `CGO_ENABLED=0` and `-trimpath`.
- Fork [CI run 36139081871](https://github.com/alkali210/go-openvpn/actions/runs/36139081871)
  passed on both Ubuntu and Windows for the final pin. The main-project
  workflows were updated locally; their hosted runs await publishing this commit.
- The standalone license copy matches the submodule license. Local document
  links and Git whitespace checks passed.

Docker integration tests and live connectivity were not rerun. Cross-compilation
is not runtime validation on Linux, macOS or Windows arm64.
