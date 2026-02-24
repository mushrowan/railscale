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

## rename test names
alice→alicja, bob→ro, others→esme/valerie/reese across entire repo
