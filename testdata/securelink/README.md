All files are synthetic offline fixtures, **not captured XMU responses**.
Addresses use documentation ranges and identities use test-only values.

- `crypto.json`: independently cross-checked AES/signature vectors (.NET).
- `auth-config.json`: provider discovery shape from the Rust implementation.
- `vpn-config.json`: networkConfig/clientConf shape from Rust; the test inserts
  a generated public CA at `{{TEST_CA}}` and a synthetic all-zero tls-auth key.
  No real private key is stored here.
- `app.push.txt`: candidate raw serialization of the three bracketed app
  examples in the Rust reference's `docs/split-tunnel-routing.md`, with addresses
  replaced. The docs contain OpenVPN3 **log formatting**, not a raw capture.
- `app-live-shape.push.txt`: synthetic values in the raw bracket/semicolon
  grammar verified against XMU on 2026-09-24. No real address, domain or token
  is retained. Both observed TCP and any rules are supported; domain grants
  cannot authorize IPv4 literals.

Do not replace these files with unsanitized sessions, profiles, API responses,
or PUSH_REPLY captures. Raw pushes may contain auth tokens as well as ACLs.
