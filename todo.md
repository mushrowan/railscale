- [x] unvendor the snow crate — custom CryptoResolver with BE nonces instead of patching upstream
- [x] wildcard certs per node — *.node.base_domain in CertDomains via dns-subdomain-resolve nodeAttr + peer CapMap propagation
- [x] admin api: enrich node API endpoints with live presence data (online, connected_at) from PresenceTracker
- [x] version test: assert on dirty field to verify build metadata is complete
- [x] ts2021: handle MSG_TYPE_ERROR (0x03) from clients during noise handshake
- [x] verify: log VerifyRequest.source ip for DERP client audit trail
- [x] ts2021 tests: rename stub to create_invalid_initiation_message for clarity

## high priority

- [x] ephemeral.rs:70 — `chrono::Duration::from_std` unwrap can panic with large timeouts, handle the error
- [x] tka.rs — extract shared helper for genesis AUM parsing + TKA key loading (duplicated in tka_init_finish and tka_sign, ~40 lines each)
- [ ] notifier.rs — add unit tests for StateNotifier (subscribe, notify, cache invalidation)
- [ ] machine_key_context.rs — add unit tests for MachineKeyContext and OptionalMachineKeyContext extractors

## medium priority

- [ ] map_cache.rs — wrap node/user snapshots in Arc to avoid cloning on every map request
- [ ] tka.rs — refactor TKA handlers to use ApiError instead of raw (StatusCode, Json) tuples
- [ ] map.rs:408-409, 518-519 — log DB errors for TKA signature fetch instead of silently swallowing
- [ ] dns.rs — fix stale doc comment on MAGIC_DNS_RESOLVER (belongs on the function) and remove duplicate comment on line 13
- [ ] resolver.rs:68 — fix comment to say "Add OIDC groups" (currently duplicates the "Add policy groups" comment from line 77)
- [ ] tests — deduplicate default_grants() helper (identical in register.rs and tka.rs test modules)

## low priority

- [ ] tka.rs — cache parsed TKA public key in AppState instead of re-parsing genesis AUM from CBOR per request
- [ ] resolver.rs — cache MapUserResolver in MapCache instead of rebuilding HashMap of all users per map request
- [ ] tka.rs — break up tka_init_finish (~180 lines) and tka_sign (~150 lines) into smaller functions
- [ ] lib.rs — extract build_app_state() from create_app_routers_with_policy_handle (~150 lines)
- [ ] noise.rs:47 — propagate error from noise::Builder instead of unwrapping
- [ ] dns_provider/webhook.rs:50,77 — propagate serialisation error instead of expect()
