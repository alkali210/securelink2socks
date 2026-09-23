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
  Actual raw syntax and any additional port/protocol forms are still unverified.

Do not replace these files with unsanitized sessions, profiles, API responses,
or PUSH_REPLY captures. Raw pushes may contain auth tokens as well as ACLs.
