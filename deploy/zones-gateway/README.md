# Run the Zone access gateway

The `zones-gateway` executable authenticates external RPC requests and forwards them to a private account-context listener. It also provides explicit Indexer query and stream routes and durable registered deliveries. PostgreSQL owns the ordered registry, receipts, decision logs, encrypted registration credentials and delivery jobs. A separate filesystem archive owns acknowledged mutation history.

## Configure dependencies

1. Copy `config.example.json` and replace the example domain, addresses and certificate paths. The configuration is JSON. Unknown fields are rejected. Set `ZONES_GATEWAY_DATABASE_URL` to a PostgreSQL connection string. The executable resolves the `env:` prefix without writing the value to the config.
2. Configure a fenced writable PostgreSQL primary with synchronous durable replication. Local PostgreSQL demonstrates transactions and recovery, but cannot prove production failover fencing or independent durability.
3. Mount `archive_dir` on durable storage in a separate failure domain from PostgreSQL. The filesystem must support atomic publication, file locks, file synchronization and directory synchronization. Protect immutable event files against replacement or deletion by the database operator's ordinary service credentials. Retain the full event history independently of request-log retention.
4. Configure the private Zone RPC listener for gateway client certificate trust. The listener must authenticate workload identity before reading `x-zone-account`, `x-zone-expires-at` or `x-zone-context-version`. The gateway's client certificate and key are transport credentials. Account and Client signing keys never belong in gateway configuration.
   The node's private listener uses these existing command options. Supply all four TLS options together; they replace the legacy redacted listener. The node also forces its ordinary raw HTTP and WebSocket listeners to loopback in this mode.

   ```text
   --redacted-rpc.addr 127.0.0.1
   --redacted-rpc.port 8547
   --gateway-rpc.cert /run/zone-access/rpc-server-cert.pem
   --gateway-rpc.key /run/zone-access/rpc-server-key.pem
   --gateway-rpc.ca /run/zone-access/workload-ca.pem
   --gateway-rpc.client-pin 0xREPLACE_WITH_CERTIFICATE_PIN
   ```

   Compute the pin with `scripts/gateway-certificate-pin.sh /run/zone-access/gateway-cert.pem`. This helper requires OpenSSL, `xxd` and Foundry `cast`. Set `CAST_BIN` if `cast` is installed outside the shell path. It hashes the certificate's DER bytes with Keccak-256. SHA3-256 and SHA-256 are different hashes and will not match. The same pin belongs in the Indexer boundary configuration. Certificate rotation requires updating the explicit pins with the new certificate.

5. Bind the gateway to loopback behind an authenticated TLS ingress, or set `frontend_tls` to certificate and key files before using a non-loopback listener. Keep the metrics listener on loopback. Set explicit request and egress rates, log retention, and response budget for the deployment.

```sh
cargo run -p zones-gateway -- --config /etc/zone-access/config.json migrate
cargo run -p zones-gateway -- --config /etc/zone-access/config.json verify-history
cargo run -p zones-gateway -- --config /etc/zone-access/config.json serve
```

`/health/live` reports process availability. `/health/ready` also requires recoverable registry history, fresh registry state and available authority dependencies. New replicas start closed. Supervise the process and use readiness to remove unavailable replicas from routing. A storage or verifier outage must not send callers around the gateway.

Deploy the private backend before the gateway. Route external clients through the gateway, then close every bypass listener, including the node's unredacted RPC. Confirm from an external host that direct backend connections fail. Rollback may restore account-token handling, but must never make the context-trusting listener public. The root-token cutover rejects root credentials with lifetimes above 600 seconds, so clients must regenerate those tokens.

## Connect an Indexer

The concrete Indexer is [TIDX](https://github.com/tempoxyz/tidx/blob/473c2fc53160f18956848cd4694c2def5f7d11ee/src/api/mod.rs). It exposes `GET /query` with `sql`, `chainId`, and optional `live=true` for SSE on the same route. [Tempo API's Indexer route](https://github.com/tempoxyz/api/blob/e2d5a65d77892f5ea3f20f943a08f3ecae9407b6/src/apps/data/routes/indexer.ts) forwards to it through [Zone-aware TIDX configuration](https://github.com/tempoxyz/api/blob/e2d5a65d77892f5ea3f20f943a08f3ecae9407b6/src/internal/Tidx.ts). Neither source is part of this checkout.

Run a dedicated single-Zone TIDX instance with `tidx.example.toml`. Its query role must have access only to that Zone database and no other Zone tables or schemas. Apply `reader-role.sql` after schema initialization, then supply the read-role password through the configured infrastructure secret. TIDX's inspected PostgreSQL validator accepts schema-qualified names by their allowed table suffix, so a `chainId` parameter alone does not enforce tenant isolation. Keep ClickHouse disabled for this boundary.

The executable `indexer-boundary` mode adds pinned gateway mTLS identity, context version and expiry checks around the real TIDX query/SSE protocol. It exposes `/events` by executing the fixed deployment SQL projection in `indexer-boundary.example.json`, wrapping it with bounded cursor ordering, and decoding actual TIDX `columns`, `rows` and `row_count`. The example emits block hashes with block numbers as cursors. Choose a projection whose identifiers and increasing cursor are stable for the source's canonical retention policy. A reorganization or reused cursor with changed content stops ingestion rather than silently replacing saved events. The underlying SQL remains subject to TIDX's SELECT validation and the dedicated read-role ACL.

```sh
cargo run -p zones-gateway -- --config /etc/zone-access/indexer-boundary.json indexer-boundary
```

Bind raw TIDX to loopback, place the mTLS boundary on the private network, and point the gateway at that boundary. Copy the gateway certificate's Keccak-256 hash into `gateway_certificate_hash`; a certificate signed by the same CA but with another hash is rejected. An explicit test exercises this pin and the real private listener. The boundary never exposes raw SQL execution through an unauthenticated listener.

Set `indexer_backend` to an HTTPS origin that trusts the gateway workload certificate. Add exact upstream query paths to `indexer_paths` and exact stream paths to `indexer_stream_paths`. At most 64 query/stream entries are accepted. Paths cannot contain authority changes, percent encoding, traversal, queries, fragments or backslashes. Incoming `/indexer/query` maps to upstream `/query`; the query string is preserved. Unlisted routes fail closed. The gateway forwards bounded GET/POST bodies and content type but never copies caller authentication or context headers. It generates context protocol version and expiry from the verified credential.

For the concrete TIDX boundary, use:

```json
{
  "indexer_backend": "https://zone-indexer.internal:8550",
  "indexer_paths": ["/query"],
  "indexer_stream_paths": ["/query"],
  "indexer_events_path": "/events",
  "delivery_key_env": "ZONES_GATEWAY_DELIVERY_KEY_V1"
}
```

Merge those fields into the complete configuration. TIDX queries and `live=true` SSE requests share `/query`; the boundary owns `/events`. Gateway query strings are pinned to the configured Zone chain. The boundary additionally fixes `engine=postgres` and `source=postgres`, rejecting alternate engine or chain selections. Database role isolation remains required for arbitrary SQL. Every query, stream frame and delivery attempt requires `indexer.read` or `admin` on the current Client admission. Account self-access does not grant a global Indexer view. Client account lists do not restrict this Zone-wide permission.

Stream GET requests support SSE or a WebSocket upgrade. The SSE upstream must return `text/event-stream`. Each emitted body chunk or WebSocket data frame receives durable authorization and a final release check. Idle streams check authority every second and close when evidence, token lifetime or permissions expire. Bounded streams use the same 1,000-stream capacity as RPC. The stated five-second bound governs authorization admissions. It does not guarantee that a paused process or already admitted transport buffer stops socket writes within five seconds.

## Register and maintain deliveries

Set the delivery key environment variable to 64 hexadecimal characters representing a 32-byte infrastructure-managed key. Restrict its access and keep it available across restart. The gateway encrypts original tokens with AES-256-GCM, a random 96-bit nonce and associated data binding domain, registration ID, Client address and generation. Key rotation requires migration of stored encrypted credentials before replacing the configured key; rotating it blindly pauses registrations that can no longer decrypt.

```sh
curl --fail -H "x-authorization-token: $CLIENT_TOKEN" \
  -H 'content-type: application/json' \
  --data '{"endpoint":"https://receiver.example/events"}' \
  http://127.0.0.1:8548/indexer/register
```

The receiver must answer a GET to that endpoint with `zone_challenge=<random challenge>` by returning exactly the challenge as its body. Registration validates HTTPS ownership and rejects private, loopback, link-local and other non-public destinations. Every connection resolves and validates addresses again, pins the chosen address, disables redirects and ignores ambient HTTP proxies.

The event-ingestion endpoint receives `GET /events?after=<cursor>&limit=100` and returns this bounded JSON contract:

```json
{
  "events": [{"event_id":"block-17-log-2","cursor":18,"payload":{"value":"example"}}],
  "next_cursor": 18
}
```

Cursors must increase strictly and the final cursor must match the last returned event, or the input cursor when no event is returned. IDs must remain stable across retries and may not be reused for changed content. The store writes jobs before advancing ingestion. Workers claim the earliest outstanding event with an expiring database-time lease and incremented fence. Receiver requests contain `id`, `cursor` and `payload`, plus `x-zone-event-id`. A successful HTTP response acknowledges the event. Acknowledgment advances the stored delivery cursor only under the current unexpired lease.

Delivery is at least once. Receiver acceptance followed by worker death causes the same event ID to be retried; receivers must deduplicate that ID. Failures use exponential delays capped at 60 seconds. Temporary verifier, database or receiver failures retain eligibility. Expired, invalid or revoked credentials pause the registration until its owner renews it. Removal or revocation cannot retract an already admitted webhook request.

```sh
curl --fail -X POST -H "x-authorization-token: $FRESH_CLIENT_TOKEN" \
  http://127.0.0.1:8548/indexer/registrations/REGISTRATION_ID/renew
curl --fail -X DELETE -H "x-authorization-token: $FRESH_CLIENT_TOKEN" \
  http://127.0.0.1:8548/indexer/registrations/REGISTRATION_ID
```

Renewal requires the same Client address and admission generation and preserves endpoint and both cursors. Deletion requires an authenticated owner and atomically removes registration and pending jobs. Neither route lets a new admission generation claim an old registration ID. Re-registering an existing owned ID can change its destination after a fresh ownership challenge.

## Verify the draft

Run `scripts/verify-zones-gateway.sh` with `ZONES_GATEWAY_TEST_DATABASE_URL` pointing to a disposable PostgreSQL database. The script runs credential/policy tests, real PostgreSQL state and delivery tests, protocol fixtures, formatting checks, scoped clippy and binary help. It fails if the database setting is absent rather than silently treating skipped database tests as evidence.

The source-shaped TIDX fixture exercises the executable private boundary with real mTLS, query/SSE results, fixed SQL event projection, expiry rejection and a wrong certificate pin. A real PostgreSQL test executes the deployment role grants and proves a schema-qualified CTE cannot read another Zone. These tests do not prove that a production deployment already uses those grants, routing or failover settings. Review those settings with the actual Indexer and deployment owners before cutover.

## Supervise and isolate the processes

The supplied `zones-gateway.service`, `zones-gateway-archive.service` and `zones-indexer-boundary.service` units restart failed processes and use restricted filesystem access. Install the built binary at `/usr/local/bin/zones-gateway`, configuration under `/etc/zone-access`, workload certificates under `/run/zone-access`, and the independent archive at `/var/lib/zone-access-archive`. Create the `zone-access` service user and use mode `0600` for environment and private-key files. Review and install the units through the deployment system; this draft does not install or start them.

The sample `zone-ingress.example.conf` routes RPC and Indexer traffic only through the gateway and rejects existing Zone Tempo API webhook routes. This matters because the inspected [Tempo API delivery pipeline](https://github.com/tempoxyz/api/blob/e2d5a65d77892f5ea3f20f943a08f3ecae9407b6/src/internal/Webhooks.ts) still calls destinations directly. Existing Zone webhook subscriptions must be paused or migrated before cutover; hiding registration routes does not stop an already-running queue consumer. Route the Zone's TIDX `baseUrl` through the gateway and supply an admitted Tempo API Client token through its configured `zoneHeaders`. Preserve the Tempo API's own caller authorization. External clients may also call the gateway directly using their signed Client token.

The ingress snippet is for a dedicated Zone hostname. Keep public Tempo API traffic on its existing host. Enforce private backend reachability separately with host firewall or network policy; a reverse-proxy file cannot close an already-public node listener. Confirm from outside the deployment that raw TIDX, its views/admin routes, private Zone RPC and unredacted RPC are unreachable.
