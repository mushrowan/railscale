# todo

## audit serde field names against tailscale Go structs

go uses unusual casing for acronyms (e.g. `AuthURL` not `AuthUrl`, `NodeID` not
`NodeId`). serde's `rename_all = "PascalCase"` gets these wrong since it doesn't
know which segments are acronyms

need to compare every `#[serde(rename_all = "PascalCase")]` struct in
railscale-proto and railscale handlers against the corresponding Go struct in
`~/dev/go/tailscale/tailcfg/tailcfg.go` and add explicit `#[serde(rename = "...")]`
where they diverge

known fixes:
- [x] `RegisterResponse.auth_url` → `AuthURL` (was `AuthUrl`)

likely suspects (fields with acronym suffixes):
- anything with `_url`, `_id`, `_ip`, `_dns`, `_tls`, `_ssh` suffixes
- `DERPMap`, `DERP` fields
- `OS`, `DNS`, `SSH`, `TLS` in field names

check at minimum:
- `RegisterRequest` / `RegisterResponse`
- `MapRequest` / `MapResponse`
- `Node` / `Hostinfo` / `NetInfo`
- `DERPMap` / `DERPRegion` / `DERPNode`
- `SSHPolicy` / `SSHRule` / `SSHAction`

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

## rename test names

alice→alicja, bob→ro, others→esme/valerie/reese across entire repo
