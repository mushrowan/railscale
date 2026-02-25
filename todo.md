# todo

## ~~audit serde field names against tailscale Go structs~~ done

audited all `rename_all = "PascalCase"` structs. all acronym fields already have
explicit `#[serde(rename = "...")]` except `RegisterResponse.auth_url` which was
fixed in v0.3.2

## audit logging for secrets

debug/trace logging must never emit secrets. currently NodeKey raw bytes are
logged via `?` (Debug). need custom Debug impls or wrapper types that redact:
- `NodeKey`, `MachineKey`, `DiscoKey` - show prefix only (e.g. `nodekey:d53d06...`)
- preauth key tokens
- OIDC tokens/secrets
- noise session keys

also review `body = %String::from_utf8_lossy(&body)` in error paths - could
contain auth keys in the JSON

## structured logging pass

go through all handlers and core logic, add proper tracing instrumentation:
- `#[instrument]` on handler functions
- `debug!` for request parsing, routing decisions, intermediate state
- `info!` for successful registrations, logins, map responses, policy changes
- `warn!` for recoverable errors, unexpected client behaviour, timeouts
- `trace!` for wire-level detail (full request/response bodies, noise frames)
- consistent span fields: `node_key`, `machine_key`, `user`, `node_id`

areas needing coverage:
- register handler (started, needs more)
- map handler (poll vs update, which fields changed)
- oidc flow (redirect, callback, token exchange)
- tka handlers
- derp server connections
- ephemeral gc
- policy reload

## expand VM test coverage

current VM tests only cover basic registration (preauth key) and policy reload.
need e2e tests for flows that unit tests can't properly validate:

### OIDC e2e
- mock OIDC provider (or use dex) in the VM test
- test interactive registration flow: client → AuthURL → browser → callback → registered
- test `allowed_users` / `allowed_domains` restrictions reject unauthorised users
- test force-reauth flow

### TKA (tailnet lock) e2e
- enable tailnet lock with trusted signing keys
- test that a new node can join when signed by a trusted key
- test that a new node is rejected when not signed / signed by untrusted key
- test key rotation under lock
- test disabling/re-enabling lock

### policy e2e
- test that policy grants actually affect connectivity (node A can reach node B on
  allowed ports, blocked on others)
- test SSH policy grants with real SSH connections
- test policy reload (SIGHUP) changes take effect on existing nodes

### multi-node
- test 3+ nodes, verify mesh connectivity and DERP relay fallback
- test ephemeral nodes are cleaned up after disconnect
- test node expiry

### DERP
- test embedded DERP relay is used when direct connection fails
- test STUN server responds

## rename test names

alice→alicja, bob→ro, others→esme/valerie/reese across entire repo
