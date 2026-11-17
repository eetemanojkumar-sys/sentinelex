# SentinelX Historical Intelligence

## Scope
This feature extends the existing FastAPI, SQLAlchemy/PostgreSQL, Linux/Windows agent, SQLite outbox and static dashboard. It does not introduce Prometheus, Grafana or a second datastore.

## Historical sources
- Existing `telemetry` rows remain the source for retained CPU, memory, disk, network and process snapshots.
- Existing `security_events` remain the source for retained security and file events.
- Windows agents already report bounded service snapshots. Linux agents now report bounded systemd service snapshots.
- `service_state_history` stores initial observations and subsequent state transitions, not repeated identical polls.

## API
All endpoints require the existing administrator bearer token:
- `GET /api/v1/history/capabilities`
- `GET /api/v1/hosts/{host_id}/history/services?start=<ISO8601>&end=<ISO8601>&limit=500`
- `GET /api/v1/hosts/{host_id}/history/processes?start=<ISO8601>&end=<ISO8601>&limit=100`
- `GET /api/v1/hosts/{host_id}/timeline?start=<ISO8601>&end=<ISO8601>&limit=500`

The dedicated UI is `/dashboard/history.html`. Sign in on the main dashboard first; it reuses the same-origin session token.

## Existing-data backfill
After deploying the schema/code to a staging copy, run:
```bash
DATABASE_URL='postgresql+psycopg://...' SENTINELX_AGENT_TOKEN='...' python scripts/backfill_service_history.py
```
The backfill reads existing telemetry service snapshots, reconstructs observed state changes in timestamp order, and does not alter telemetry or security-event rows. It is idempotent for already imported transitions. Historical process snapshots are queried directly from retained telemetry JSON. Metrics history uses existing telemetry and its server receipt timestamps; pre-existing records cannot reveal exact collection time if that timestamp was not stored.

## Collection
- CPU/memory/disk/network and process inventory continue through the existing base collector.
- Process history is available at the central API's configured telemetry history cadence (currently controlled by `SENTINELX_HISTORY_INTERVAL_SECONDS`).
- Windows service snapshots use the existing Windows service collector.
- Linux service snapshots use `systemctl list-units`, bounded to 250 units by default.
- Service transition persistence occurs centrally when the state differs from the last stored state.

## Reliability and security
- Shared bootstrap-token telemetry authentication is disabled by default. Bootstrap tokens are for enrollment only. An explicitly configured temporary compatibility flag `SENTINELX_ALLOW_LEGACY_BOOTSTRAP_INGEST=true` re-enables legacy behavior and should only be used during a controlled migration window.
- Agent batches contain at most 200 queued events. HTTP 400/413/422 payload failures are moved to a local SQLite dead-letter table rather than blocking the oldest pending batch. Network and transient errors remain queued.
- The service history table is additive; the existing `Base.metadata.create_all` creates it on application startup. This does not migrate or rewrite existing telemetry tables.
- Current administrator auth is global, matching the existing product model. Per-tenant access control must be implemented before offering this to multiple independent customers.

## Safe rollout
1. Back up PostgreSQL and the agent outbox files.
2. Deploy to a staging environment with a copied database.
3. Run existing and new unit tests.
4. Verify Linux and Windows service snapshots.
5. Run the backfill and verify counts.
6. Validate historical queries and dashboard.
7. Roll out to one canary endpoint before the rest of the fleet.

No production deployment is performed by pushing this branch.
