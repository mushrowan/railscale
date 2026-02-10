# progress

## unvendor snow — complete
- removed vendored `vendor/snow` fork and `[patch.crates-io]` override
- custom `TailscaleResolver` in `railscale-proto::noise` overrides ChaChaPoly with big-endian nonce encoding (tailscale compatibility)
- `noise::builder()` factory centralises all `Builder::with_resolver` calls — no more `Builder::new` in the codebase
- test helper functions `build_initiator` / `build_initiator_with_prologue` deduplicate test setup
- `test_tailscale_resolver_uses_be_nonces` proves BE/LE divergence at nonce > 0

## audit remediation progress

## phase 1 — complete
- **1-1..1-3, 2-10** ts2021 fixes: body limits, frame buffer, partial write, ws spin loop
- **1-4** tka endpoint auth: `verify_requesting_node` helper, all 5 endpoints now check node_key
- **1-5** tka chain validation: `tka_sync_send` rejects AUMs with broken prev_hash links
- **1-6** tka init_begin guard: returns 409 Conflict when TKA already enabled
- **1-7** tka aum size limits: 32KB per AUM, 100 AUMs per request
- **1-8** register key fix: random machine key instead of hardcoded zero for non-noise
- **1-9** api key redaction: node_key/machine_key/disco_key truncated to 4 bytes in API

## phase 2 — complete
- **2-1, 2-11** verify endpoint: log DB errors as warnings, reject expired nodes
- **2-4** db migration 000011: unique constraint on users.name, index on nodes.node_key
- **2-5** map user profile filtering: only include profiles for visible peers + self
- **2-6** delete user cascade: delete_nodes_for_user + delete_preauth_keys_for_user
- **2-7** derp server_side_rate_limit default changed to true
- **2-8** derp map fetch: 1MB response size limit
- **2-2** verify allowlist: respect x-forwarded-for behind trusted proxy
- **2-3** oidc: email_verified_required defaults to true
- **2-9** version endpoint: hide_build_metadata config option

## phase 3 — complete
- **3-4** sqlite WAL default true
- **3-7** governor panic guard: clamp interval to 1ms min
- **3-5** ipv6 allocation: compute address space from prefix length, cap 10M
- **3-2** ip allocator: release IPs on node deletion (REST API + ephemeral GC)
- **3-3** api pagination: limit/offset on list_nodes and list_users
- **3-1** map response caching: MapCache with lazy invalidation via generation counters, pre-computed dns config

## phase 4 — complete
- **4-5** pkce plain: warn and fall back to S256
- **4-7** unsafe env var migration: improved safety docs
- **4-6** unused tuning config: marked as reserved for future use
- **4-1** tka signatures in map responses: batch-fetch KeySignature, populate on peers + self
- **4-2** tka rotation keys: nl_public_key on Node, DB migration, NLKey parsing in register, rotation_pubkey in tka_init_begin
- **4-3** derp map URL/path loading: load_external_derp_maps + spawn_derp_map_updater
- **4-4** policy persistence: atomic file write on REST/gRPC updates via tempfile+rename

## phase 5 — complete
- **5-2, 5-3** nix: parse derp/stun ports, postgres db_type, server_side_rate_limit, verify.trusted_proxies
- **5-1** config example: added verify, proxy, hide_build_metadata, WAL sections
- **5-4** rate limit config helper: extracted limiter cleanup into macro, deduplicated api router
- **5-5** html template consolidation: moved oidc html to handlers/templates.rs

## ssh accept_env — complete
- `accept_env: Option<Vec<String>>` on `SshPolicyRule`, propagated through `compile_ssh_policy()`
- `ssh-env-vars` node capability always sent in map response cap_map
- matches tailscale wire format: glob patterns (`*`, `?`) for env var allowlisting per SSH rule

## protocol features — complete
- **FilterRule.IPProto**: `ip_proto` field on FilterRule, grants engine groups by protocol, emits separate rules. icmp includes v4 (1) + v6 (58)
- **Node.Name FQDN**: sent as `{hostname}.{base_domain}.` with trailing dot, MapResponse.Domain set from config
- **Node.Cap**: CapabilityVersion set on all peer nodes
- **HomeDERP**: derived from client's hostinfo.net_info.preferred_derp instead of hardcoded first region
- **auto-approve routes**: `autoApprovers` policy field, supports routes (prefix → selectors) and exitNode. subset matching, wired into preauth + OIDC registration
- **key rotation**: preauth registration checks for existing node by machine_key, updates node_key in place preserving IP allocation. auto-approved routes merged without removing existing

## CapGrant on FilterRule — complete
- `CapGrant` struct in railscale-proto: `dsts` + `cap_map` (matches tailscale wire format)
- `FilterRule` now has `cap_grant` field (mutually exclusive with `dst_ports`, both skip_serializing_if empty)
- peer capability constants: `PEER_CAP_FILE_SHARING_TARGET`, `PEER_CAP_FILE_SEND`, `PEER_CAP_DEBUG_PEER`, `PEER_CAP_WAKE_ON_LAN`, `PEER_CAP_INGRESS`
- `generate_cap_grant_rules()` in grants engine: emits cap-grant filter rules from `Grant.app` capabilities
- `generate_taildrop_rules()`: same-user untagged peers automatically get `file-sharing-target` CapGrant
- map handler wires both into `packet_filter` (gated on `taildrop_enabled` for taildrop rules)
- headscale doesn't implement any of this — railscale is first open-source implementation

## cross-user taildrop — complete
- same-user taildrop now emits both `file-sharing-target` AND `file-send` peer caps (was missing `file-send`)
- cross-user file sharing works via explicit policy app grants through `generate_cap_grant_rules()`
- policy example: `{"src": ["bob@"], "dst": ["alice@"], "app": [{"name": "cap/file-sharing-target"}, {"name": "cap/file-send"}]}`

## app connectors v1 — complete
- `AppConnectorAttr` type in railscale-proto with `name`, `domains`, `routes`, `connectors` fields
- `CAP_APP_CONNECTORS` and `CAP_STORE_APPC_ROUTES` capability constants
- `NodeAttr` type on `Policy` — `target: Vec<Selector>`, `app: HashMap<String, Vec<Value>>`
- `resolve_node_cap_attrs()` on `GrantsEngine` — evaluates nodeAttrs against node, merges into self CapMap
- `build_self_cap_map` split into simple/full paths to support nodeAttrs merge in map handler
- `is_app_connector_node()` helper — checks `hostinfo.app_connector == true` AND matches connector selector
- app connector nodes get all non-exit routes auto-approved via extended `auto_approve_routes()`

## docker image — complete
- `streamLayeredImage` in flake.nix under `packages.docker`
- includes railscale binary + CA certificates
- entrypoint `railscale`, cmd `serve`, exposes 8080/tcp and 3478/udp
- usage: `nix build .#docker && ./result | docker load`

## tailscale cert / set-dns — complete
- **proto types**: `SetDNSRequest`, `SetDNSResponse`, `cert_domains` on `DnsConfig`
- **config**: `DnsProviderConfig` enum (cloudflare, godaddy, webhook) with secret redaction
- **dns_provider trait**: `DnsProvider` async trait with `DnsProviderBoxed` object-safe wrapper, `from_config()` factory
- **cloudflare**: POST/DELETE to zones API with bearer auth, wiremock-tested
- **godaddy**: PUT to domains/records API with sso-key auth, `relative_name()` for FQDN→record name
- **webhook**: POST JSON with optional HMAC-SHA256 `X-Signature` header, wiremock-tested
- **AppState wiring**: `dns_provider: Option<Arc<dyn DnsProviderBoxed>>` on AppState, constructed from config
- **CertDomains in map**: `with_cert_domains()` stamps per-node cert domain when dns_provider configured
- **DB migration 000013**: `dns_challenge_records` table with FK to nodes, record_name, record_id, created_at
- **`/machine/set-dns` handler**: validates node auth + TXT type + name matches cert domain, delegates to provider, persists record
- **cleanup task**: `DnsChallengeGarbageCollector` removes stale TXT records (>10 min) every 60s
- 25+ unit + integration tests across providers, handler, and GC
