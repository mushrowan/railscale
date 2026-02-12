- [x] unvendor the snow crate — custom CryptoResolver with BE nonces instead of patching upstream
- [x] wildcard certs per node — *.node.base_domain in CertDomains via dns-subdomain-resolve nodeAttr + peer CapMap propagation
- [x] admin api: enrich node API endpoints with live presence data (online, connected_at) from PresenceTracker
- [x] version test: assert on dirty field to verify build metadata is complete
- [x] ts2021: handle MSG_TYPE_ERROR (0x03) from clients during noise handshake
- [x] verify: log VerifyRequest.source ip for DERP client audit trail
- [x] ts2021 tests: rename stub to create_invalid_initiation_message for clarity
- [x] ephemeral.rs — saturate to MAX_UTC instead of panicking on large Duration::from_std
- [x] tka.rs — extract ParsedGenesis + parse_genesis() helper, deduplicating ~40 lines
- [x] notifier.rs — 8 unit tests for StateNotifier (subscribe, multi-sub, clone, cache invalidation)
- [x] machine_key_context.rs — 7 unit tests for extractors (from_bytes, extraction, optional)
- [x] map_cache.rs — Arc-wrapped snapshots to avoid cloning per map request
- [x] tka.rs — all 7 handlers refactored to Result<Json<T>, ApiError> with ? propagation (-317 lines)
- [x] map.rs — log warnings for swallowed TKA signature fetch DB errors
- [x] dns.rs — fix stale doc comment on MAGIC_DNS_RESOLVER, remove duplicate
- [x] resolver.rs — fix comment to say "OIDC groups" not duplicate "policy groups"
- [x] tests — deduplicate default_grants() into handlers/test_helpers.rs (was in 4 modules)
- [x] webhook.rs — propagate serialisation error instead of expect()

## low priority

- [ ] tka.rs — cache parsed TKA public key in AppState instead of re-parsing genesis AUM from CBOR per request
- [ ] resolver.rs — cache MapUserResolver in MapCache instead of rebuilding HashMap of all users per map request
- [ ] lib.rs — extract build_app_state() from create_app_routers_with_policy_handle (~150 lines)
- [x] noise.rs:47 — chacha20poly1305 encrypt is infallible, unwrap is safe (no change needed)
