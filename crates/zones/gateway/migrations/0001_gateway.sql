CREATE TABLE IF NOT EXISTS gateway_heads (
 domain BYTEA PRIMARY KEY CHECK (octet_length(domain)=32),
 head BIGINT NOT NULL DEFAULT 0 CHECK(head >= 0),
 event_hash BYTEA NOT NULL CHECK(octet_length(event_hash)=32),
 archived_head BIGINT NOT NULL DEFAULT 0 CHECK(archived_head >= 0),
 registry JSONB NOT NULL
);
CREATE TABLE IF NOT EXISTS gateway_events (
 domain BYTEA NOT NULL REFERENCES gateway_heads(domain),
 log_offset BIGINT NOT NULL CHECK(log_offset > 0),
 digest BYTEA NOT NULL CHECK(octet_length(digest)=32),
 client BYTEA NOT NULL CHECK(octet_length(client)=20),
 sequence NUMERIC(20,0) NOT NULL CHECK(sequence >= 0 AND sequence <= 18446744073709551615),
 event JSONB NOT NULL, receipt JSONB NOT NULL,
 PRIMARY KEY(domain,log_offset), UNIQUE(domain,digest), UNIQUE(domain,client,sequence)
);
CREATE TABLE IF NOT EXISTS gateway_rejections (
 id BIGSERIAL PRIMARY KEY, domain BYTEA NOT NULL,
 digest BYTEA NOT NULL CHECK(octet_length(digest)=32),
 reason TEXT NOT NULL CHECK(octet_length(reason)<=512), created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS gateway_decisions (
 id BIGSERIAL PRIMARY KEY, domain BYTEA NOT NULL,
 principal_kind TEXT NOT NULL CHECK(principal_kind IN ('account','client','admin','unverified')),
 principal BYTEA CHECK(principal IS NULL OR octet_length(principal)=20),
 generation NUMERIC(20,0), token_id BYTEA CHECK(token_id IS NULL OR octet_length(token_id)=32),
 label TEXT CHECK(label IS NULL OR octet_length(label)<=64),
 account BYTEA CHECK(account IS NULL OR octet_length(account)=20),
 tempo_hash BYTEA CHECK(tempo_hash IS NULL OR octet_length(tempo_hash)=32),
 zone_hash BYTEA CHECK(zone_hash IS NULL OR octet_length(zone_hash)=32),
 method TEXT NOT NULL CHECK(octet_length(method)<=128),
 decision TEXT NOT NULL CHECK(octet_length(decision)<=64),
 log_offset BIGINT NOT NULL CHECK(log_offset>=0), created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE gateway_decisions ADD COLUMN IF NOT EXISTS tempo_hash BYTEA CHECK(tempo_hash IS NULL OR octet_length(tempo_hash)=32);
ALTER TABLE gateway_decisions ADD COLUMN IF NOT EXISTS zone_hash BYTEA CHECK(zone_hash IS NULL OR octet_length(zone_hash)=32);
CREATE INDEX IF NOT EXISTS gateway_decisions_owner ON gateway_decisions(domain,principal_kind,principal,generation,id);
CREATE TABLE IF NOT EXISTS gateway_completions (
 decision_id BIGINT NOT NULL REFERENCES gateway_decisions(id),
 outcome TEXT NOT NULL CHECK(octet_length(outcome)<=64), created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 PRIMARY KEY(decision_id,outcome)
);
CREATE TABLE IF NOT EXISTS gateway_registrations (
 domain BYTEA NOT NULL REFERENCES gateway_heads(domain), id TEXT NOT NULL CHECK(octet_length(id)<=128),
 owner BYTEA NOT NULL CHECK(octet_length(owner)=20),
 generation NUMERIC(20,0) NOT NULL,
 encrypted_credential BYTEA NOT NULL CHECK(octet_length(encrypted_credential)<=16384),
 endpoint TEXT NOT NULL CHECK(octet_length(endpoint)<=2048),
 ingest_cursor NUMERIC(20,0) NOT NULL DEFAULT 0,
 ack_cursor NUMERIC(20,0) NOT NULL DEFAULT 0, paused BOOLEAN NOT NULL DEFAULT FALSE,
 PRIMARY KEY(domain,id)
);
CREATE TABLE IF NOT EXISTS gateway_delivery_jobs (
 domain BYTEA NOT NULL, registration_id TEXT NOT NULL,
 event_id TEXT NOT NULL CHECK(octet_length(event_id)<=256), cursor NUMERIC(20,0) NOT NULL,
 payload JSONB NOT NULL, fence BIGINT NOT NULL DEFAULT 0 CHECK(fence >=0),
 lease_owner TEXT, lease_until TIMESTAMPTZ, next_attempt TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 acknowledged BOOLEAN NOT NULL DEFAULT FALSE, attempts BIGINT NOT NULL DEFAULT 0,
 PRIMARY KEY(domain,registration_id,event_id), UNIQUE(domain,registration_id,cursor),
 FOREIGN KEY(domain,registration_id) REFERENCES gateway_registrations(domain,id)
);
CREATE INDEX IF NOT EXISTS gateway_delivery_pending ON gateway_delivery_jobs(domain,next_attempt) WHERE NOT acknowledged;
