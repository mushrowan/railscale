# todo

## 1. delta map responses
- `PeersChanged` / `PeersRemoved` on MapResponse
- `PeersChangedPatch` with `PeerChange` struct (online, DERP, endpoints, keys)
- `OnlineChange` / `PeerSeenChange` lightweight maps
- `MapSessionHandle` / `Seq` for session resumption
- per-node generation tracking in MapCache

## 2. `/machine/set-device-attr`
- PATCH endpoint for client-driven posture attribute updates over noise
- reuse existing `set_node_posture_attributes()` DB method
- `SetDeviceAttributesRequest` type in proto

## 3. `Debug` on MapResponse
- `Debug` struct with `SleepSeconds`, `DisableLogTail`, `Exit`
- add to MapResponse, wire from config or per-node overrides

## 4. `Health` / `DisplayMessages` on MapResponse
- `Health` field (Vec<String>) for simple warnings
- `DisplayMessages` for richer structured messages
- integrate with node expiry, version checks

## 5. `/machine/audit-log`
- POST endpoint for client audit log submission over noise
- `AuditLogRequest` type: action, details, timestamp
- new DB table + migration for audit log storage

## 6. `PacketFilters` (named/incremental)
- `packet_filters: HashMap<String, Vec<FilterRule>>` on MapResponse
- incremental filter updates instead of full filter every time
- pairs with delta map responses
