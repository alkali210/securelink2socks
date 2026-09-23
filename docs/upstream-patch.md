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

`raw_push_test.go` verifies that an unknown `app` option survives the internal
parser, public conversion and reconnect callback dispatch. The wire protocol,
cipher policy, peer-info, sessions and netstack behavior are unchanged.

Run the dependency tests separately because `go test ./...` at the repository
root does not descend into nested Go modules:

```powershell
go -C third_party/go-openvpn test ./...
```

Upstreaming this additive API would allow removing the local replace after
pinning a release containing it. No upstream publication has been performed.
