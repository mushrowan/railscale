# Railscale audit

## Executive summary
Railscale shows strong security-conscious design (hashed tokens, constant‑time comparisons, zeroisation, request size limits, policy validation, and explicit warnings around insecure configuration). The core architecture is coherent and reasonably well isolated by crate boundaries. The largest risks are around **misconfiguration**, **resource exhaustion**, and a handful of **missing hardening controls** that are currently left to operators. There are also clear opportunities to simplify and harden critical paths (registration, map generation, rate limiting) without changing behaviour.

**Top priorities**
1. **IP allocation memory/perf risk** in `IpAllocator` for large prefixes (e.g. /10). This can become a resource‑exhaustion vector.
2. **Unauthenticated `/verify` endpoint** relies entirely on external firewalling with no built‑in allowlist/rate limiting.
3. **Tailnet map generation reads full DB state per request** and does not respect `omit_peers`, which increases load and attack surface.
4. **DERP map fetch lacks integrity controls** (no pinning/validation beyond TLS), leaving a supply‑chain risk when relying on remote DERP maps.

No code changes were made for this audit.

## Scope and methodology
- Read core server handlers (`/ts2021`, `/register`, `/map`, `/verify`, OIDC, admin API) and supporting modules.
- Reviewed token/key security (`ApiKey`, `PreAuthKey`, Noise keys), rate limiting, and config defaults.
- Examined grant policy evaluation and SSH policy compilation.
- Reviewed database and allocator implementation for safety/perf pitfalls.
- Inspected logging and error handling.

## Strengths and good practices
- **Split‑token API keys** with constant‑time verification, hashing, and zeroisation on drop.
- **Noise protocol** implementation cleanly separated, with prologue support and explicit frame limits.
- **Request size limits** (64 KB) on protocol and API routes.
- **Rate limiting** via `tower-governor` with proxy‑aware key extraction and trusted proxy list.
- **OIDC state invalidation** with pending‑registration cache and TTL.
- **Policy validation** for grants and SSH rules, with explicit error handling.
- **Sensitive log redaction** for database connection strings.

## Findings by severity

### High
1. **IPv4 allocator materialises all hosts** ✅ FIXED
   - `IpAllocator::allocate_v4` collects `prefix.hosts()` into a `Vec`, which is **very large** for the default /10 (≈16 million addresses). This can spike memory and degrade performance or trigger OOM in large deployments.
   - **Impact**: potential DoS if the allocator is hit frequently or on startup with large prefixes.
   - **Fix**: now computes addresses arithmetically from network base + offset.

2. **Unauthenticated `/verify` relies on external controls**
   - `/verify` is intentionally unauthenticated, but the code does not provide optional allowlists or built‑in rate limiting.
   - **Impact**: allows unauthenticated enumeration attempts or database load (if reachable externally).
   - **Recommendation**: add optional allowlist/IP filtering in config, plus optional rate limiting on `/verify` at the app layer, while preserving compatibility.

3. **Map generation loads full tailnet state per request** ✅ FIXED
   - `build_map_response` always loads all nodes/users, ignoring `MapRequest.omit_peers` and `MapRequest.is_read_only`.
   - **Impact**: elevated load, and an attacker could force repeated full scans.
   - **Fix**: now respects `omit_peers` flag and skips peer/filter/ssh computation when set.

4. **Remote DERP map lacks integrity validation**
   - `fetch_derp_map_from_url` trusts a remote URL without content signing or pinning (TLS only).
   - **Impact**: compromised remote endpoint could influence relay topology.
   - **Recommendation**: consider optional signature verification (if using an owned DERP map), or allow pinning to known fingerprints/ETags with integrity checks.

### Medium
1. **Non‑Noise registration toggle is dangerous**
   - `allow_non_noise_registration` allows registration without Noise context (with a zero machine key).
   - **Impact**: if enabled accidentally, it weakens cryptographic binding and may allow spoofing.
   - **Recommendation**: keep disabled by default (already), but consider an additional runtime guard (e.g., explicit `--allow-non-noise` CLI flag that must be paired with `--insecure`).

2. **`encode_length_prefixed` size overflow behaviour** ✅ FIXED
   - On oversized payloads, it clamps length to `u32::MAX` rather than returning an error, potentially confusing clients.
   - **Fix**: now returns `None` (error) when payload exceeds `u32::MAX`.

3. **`/bootstrap-dns` concurrency and cache‑miss amplification** ✅ FIXED
   - All DERP hostnames are resolved concurrently without an explicit concurrency cap.
   - **Impact**: large DERP maps can create transient DNS pressure.
   - **Fix**: now capped at 10 concurrent lookups using `buffer_unordered`.

4. **Policy updates not persisted**
   - REST API policy updates are in‑memory only.
   - **Impact**: policy changes are lost on restart; operators may assume persistence.
   - **Recommendation**: document clearly, or persist to a policy file/DB with a revision marker and reload on startup.

### Low
1. **`/key` endpoint logs the full public key** ✅ FIXED
   - Public key is not secret, but logs may be noisy; consider logging only a short prefix for hygiene.
   - **Fix**: now logs at debug level with short key prefix only.

2. **Repeated comments and inconsistent casing**
   - Several files contain duplicated/partially duplicated doc comments (e.g., DNS modules). This reduces clarity and can confuse audits.

3. **DELETE with JSON body**
   - `DELETE /api/v1/preauthkey` uses a JSON body, which some clients and proxies do not forward reliably.
   - Consider a path‑param or POST to a `/delete` route for maximal compatibility.

## Refactoring opportunities (behaviour‑preserving)
1. **Extract rate‑limit config helper**
   - `build_api_router` duplicates governor configuration for proxy/no‑proxy. A helper to construct governor config + limiter cleanup would simplify and reduce risk of divergence.

2. **Reduce map handler duplication**
   - `streaming_response` and non‑streaming map paths both call `build_map_response` then encode. A shared helper could reduce branching and improve testability.

3. **Encapsulate registration response building**
   - `handle_followup_registration` returns the same “pending” response in two branches. A small helper would make it clearer and avoid drift.

4. **Consolidate HTML generation**
   - OIDC manual registration HTML is inline. Moving it to a helper/template (or a const string with placeholders) would ease maintenance.

5. **Use stronger types for auth state**
   - `ApiAuthError` could use `thiserror` and carry internal causes for logging while keeping public messages stable.

## Performance and operability notes
- **Map generation** is the dominant hot path: consider caching user profiles, or precomputing grant results per node where feasible.
- **Grants engine** is lock‑guarded (RwLock) but called per map request. Consider read‑only cloning or per‑request handles if lock contention becomes visible.
- **DERP map updates**: refresh logic isn’t shown in the core handler; ensure it’s correctly scheduled in the server runtime and handles failures gracefully.
- **Taildrop flag** exists but feature is not implemented; ensure callers don’t assume it is active.

## Suggested quick wins
- ~~Fix `IpAllocator` to avoid `hosts().collect()`.~~ ✅ Fixed
- Add optional config allowlist + rate limit for `/verify`.
- ~~Respect `MapRequest.omit_peers` (skip expensive peer computation).~~ ✅ Fixed
- ~~Add a small `payload too large` error in `encode_length_prefixed`.~~ ✅ Fixed
- ~~Add concurrency limits to `bootstrap-dns` lookups.~~ ✅ Fixed

## Longer‑term improvements
- Introduce a **policy persistence mechanism** (DB table or file snapshot).
- Separate **admin API** into a dedicated listener by default when enabled, and document recommended deployment topology.
- Add **audit logging hooks** for sensitive operations (policy updates, key creation/expiry, node deletion).
- Improve **observability** of state changes (map refresh metrics, rate‑limit metrics, OIDC registration stats).

---

If you want, I can turn any of the above into concrete refactors or targeted security hardening changes.