# Minimal go-openvpn patch

Base: `12597991e31263f9309a6589dfd63a304349bafc`.

The dependency is now a Git submodule at `third_party/go-openvpn`, sourced
from [alkali210/go-openvpn](https://github.com/alkali210/go-openvpn/tree/patched).
The main repository pins its exact commit; `patched` is the development branch.
The full upstream tree is retained. The upstream module path and license are
unchanged; the local `replace` still selects the patched root module. The
separate netstack module remains an ordinary pinned upstream dependency.

Migration preserved the four original dependency changes as separate commits:

| Fork commit | Original project commit | Scope |
| --- | --- | --- |
| `40494e2` | `a6b0883` | Raw PUSH options |
| `ef45132` | `f5cd271` | Plain control and native framing |
| `85562b3` | `22f39ef` | Handshake records, PUSH assembly and key derivation |
| `41852ac` | `226fcea` | Session lifecycle and policy revocation |

All 79 previously tracked dependency files matched the migrated Git blobs
before the fork documentation/CI commit. The fork adds a README notice,
[PATCHES.md](../third_party/go-openvpn/PATCHES.md) and standalone CI; protocol
code and regression tests are unchanged by this migration.

The final migration pin is `d20ba6de22b44faed37c5b079e0da7561179bceb`.
Commit `401bb45` adds fork documentation and CI; `d20ba6d` corrects the
restored upstream reconnect fixture to explicitly advertise TLS-EKM, which
its mock server already uses. This extra test was absent from the old snapshot.
The complete root test suite, `go vet` and separate netstack tests passed on
Windows after that correction. Docker integration tests remain opt-in and
were not run for this migration. Fresh-clone and six-target build results are
recorded in [offline validation](offline-validation.md#forksubmodule-migration--2026-09-25).

See [development instructions](development.md) for clone and update procedures.

Production delta:

1. Add `Raw string` to public `openvpn.PushReply`, documenting that it excludes
   the `PUSH_REPLY,` prefix and trailing NUL.
2. Copy internal `proto.PushReply.Raw` into that field in PushedOptions.
3. Extract the conversion into private `publicPushReply` for a regression test.
4. Add explicit `AllowPlainControl` config/parser opt-in for OpenVPN control
   framing without tls-auth/tls-crypt. Default parsing still rejects missing
   control protection. The inner TLS certificate policy is independent.
5. Write each NUL-terminated control command with one TLS Write, so native
   OpenVPN's per-record command reader sees a complete command.
6. Advertise the actual TCP/UDP transport and cipher key size in both initial
   and rekey option strings, instead of always UDPv4 and 256 bits.
7. Use native OpenVPN platform names (`win`/`mac`) and advertise `IV_TCPNL=1`,
   consistent with the existing AEAD replay window.
8. Disable Go adaptive TLS record sizing on initial/rekey client connections
   without mutating caller TLS configs; cap KEY_METHOD 2 at one 16 KiB record.
   Native OpenVPN parses peer-info within a single SSL_read result. Long
   synthetic provider fields reproduce the failure before this correction.
9. Assemble bounded PUSH continuation bundles (2 = more, 1 = final) before
   interpreting cipher/IP/ACL. Reject incomplete or malformed sequences.
10. Select TLS-EKM only when pushed via key-derivation/protocol-flags;
    otherwise use the standard OpenVPN KEY_METHOD 2 PRF for AEAD keys.
    Retain/clear pre_master at the correct lifetime and apply the same policy
    during rekey. Add an independent Python HMAC golden and memory AEAD echo
    coverage for PRF; EKM test peers now explicitly advertise their policy.
11. Expose current-session completion/cause for an application-owned supervisor
    with AutoReconnect disabled. Add opt-in RestartOnPush: post-handshake
    PUSH_REPLY/PUSH_UPDATE and loss of the active control stream close the
    session, forcing authorization revocation before a fresh full handshake.
    Old TLS readers closed during rekey are excluded from this restart rule.

`raw_push_test.go` verifies that an unknown `app` option survives the internal
parser, public conversion and reconnect callback dispatch. Additional tests
cover plain-control golden bytes, opt-in validation, an in-memory TLS/AEAD ping,
TLS command record boundaries, transport/key-size options and platform names.
These tests do not prove XMU accepts AEAD or that its raw ACL is compatible.

Protocol references used for these corrections:
- [OpenVPN control packet format](https://build.openvpn.net/doxygen/network_protocol.html)
- [OpenVPN 2.6.14 control message reader](https://github.com/OpenVPN/openvpn/blob/v2.6.14/src/openvpn/forward.c)
- [OpenVPN 2.6.14 options string](https://github.com/OpenVPN/openvpn/blob/v2.6.14/src/openvpn/options.c)
- [OpenVPN 2.6.14 peer info](https://github.com/OpenVPN/openvpn/blob/v2.6.14/src/openvpn/ssl.c)

Run the dependency tests separately because `go test ./...` at the repository
root does not descend into nested Go modules:

```powershell
go -C third_party/go-openvpn test -parallel 1 -timeout 5m ./...
```

The patches are maintained in the fork; no pull request to the original
upstream has been submitted. Removing the replacement requires an upstream
version containing all compatibility and lifecycle changes used by this app.
