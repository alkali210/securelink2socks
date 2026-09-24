# Minimal go-openvpn patch

Base: `12597991e31263f9309a6589dfd63a304349bafc`.

The checked-in dependency contains upstream root Go files/tests, internal
packages/tests, pkg/ovpn, go.mod/go.sum, README and LICENSE. Other nested modules,
examples, CI files and the reference .git directory are omitted. The separate
netstack module remains an ordinary pinned dependency; its root import resolves
to this local replacement.

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
go -C third_party/go-openvpn test ./...
```

Upstreaming this additive API would allow removing the local replace after
pinning a release containing it. No upstream publication has been performed.
