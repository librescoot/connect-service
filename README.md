# Librescoot connect service

This repository contains the first server slice for consented installation and firmware-version reporting. It is a standalone Go HTTP service backed by PostgreSQL. It does not include a scooter client, web pairing flow, provider integration, or an operator UI.

## Reporting consent boundary

The client must send no request while reporting permission is `unset` or `denied`. Only an explicit `allowed` choice permits installation registration and version-change reports. This server does not infer consent from scooter presence or enable reporting on its own. Reporting is separate from cloud-provider setup.

The basic report contains only the protocol and consent schema versions, random installation and event IDs, MDB/DBC board variant and firmware-version facts, the fixed software-capability enum, and installer version when known. Unknown versions are JSON `null`; an absent MDB or DBC board is omitted. Hardware serials, VIN, IMEI, SIM identifiers, location, uptime and riding data are not part of the schema. Unknown request properties are rejected.

Optional hardware inventory is not implemented. It has no default-on path and is not accepted by these endpoints. Pairing codes, provider offers, provider credentials, provider integrations, client behavior, dashboards and deployments are also unimplemented and remain separate security/design gates.

## API

The implemented contract is in [`docs/protocol-v1.md`](docs/protocol-v1.md) and [`openapi.yaml`](openapi.yaml).

- `POST /api/v1/installations` registers the client-supplied random ID and submits its initial report. The client supplies a 32-byte random bearer credential; the server stores only its SHA-256 digest.
- `PUT /api/v1/installations/{id}/report` submits a changed report using that credential.
- `DELETE /api/v1/installations/{id}` deletes report facts and leaves a permanent ID-and-timestamp tombstone, preventing stale registration replay.
- `GET /healthz` reports process health. `GET /readyz` checks database readiness. Both return no internal details.

There is no public list or lookup endpoint. The server does not persist request IP addresses and emits no per-request access logs. Before public exposure, deploy a trusted ingress with a per-client API rate limit and connection cap, using [`deploy/nginx-rate-limit.conf.example`](deploy/nginx-rate-limit.conf.example) or equivalent controls. Do not persist client IP addresses or log request URIs, queries, authorization headers or bodies.

## Local run

Requirements: Go 1.25.14 and PostgreSQL 15 or newer. The service applies checked-in SQL migrations at startup.

For a local-only test database, start PostgreSQL in a separate terminal:

```sh
docker run --rm --name connect-postgres \
  -e POSTGRES_USER=connect \
  -e POSTGRES_PASSWORD=local-test-only \
  -e POSTGRES_DB=connect_service_test \
  -p 127.0.0.1:55432:5432 postgres:17
```

The password above is for a loopback-only throwaway development database; do not reuse it. Then run the service:

```sh
export CONNECT_DATABASE_URL='postgres://connect:local-test-only@127.0.0.1:55432/connect_service_test?sslmode=disable'
go run ./cmd/connect-server
```

The default listener is `127.0.0.1:8080`. For non-local PostgreSQL, the database URL must use `sslmode=verify-full` so the server certificate and hostname are checked.

## Tests and checks

Unit tests use repository fakes. The PostgreSQL lifecycle test is skipped unless `CONNECT_TEST_DATABASE_URL` points to an isolated test database whose name ends in `_test`:

```sh
go test ./...
CONNECT_TEST_DATABASE_URL='postgres://connect:local-test-only@127.0.0.1:55432/connect_service_test?sslmode=disable' \
  go test ./internal/store -run TestPostgresReportingLifecycle -count=1
go vet ./...
```

The integration test applies migrations and creates random synthetic installations in that database. Use a disposable database, not a production database.

## Configuration

| Variable | Default | Constraints |
| --- | --- | --- |
| `CONNECT_LISTEN_ADDR` | `127.0.0.1:8080` | Host and port; port 1-65535 |
| `CONNECT_DATABASE_URL` | required | PostgreSQL URL; remote hosts require `sslmode=verify-full` |
| `CONNECT_READ_HEADER_TIMEOUT_SECONDS` | `5` | 2-30 seconds |
| `CONNECT_READ_TIMEOUT_SECONDS` | `10` | 1-60 seconds |
| `CONNECT_WRITE_TIMEOUT_SECONDS` | `10` | 1-60 seconds |
| `CONNECT_IDLE_TIMEOUT_SECONDS` | `60` | 10-300 seconds |
| `CONNECT_MAX_BODY_BYTES` | `16384` | 1024-65536 bytes |
| `CONNECT_DATABASE_MAX_OPEN_CONNS` | `10` | 1-50 connections |

## Retention

Each accepted distinct report sets `expires_at` to 24 calendar months after that report. An identical retry does not extend retention. The periodic sweep removes current facts, credentials, consent metadata and report receipts at expiration, retaining only the random installation ID and tombstone timestamp needed to block stale registration. It increments identity-free monthly expiration counts. Authenticated deletion removes facts and credentials immediately and leaves the same minimal ID-and-timestamp tombstone. Raw event receipts are retained for at most 30 days. This repository configures no backups. Before enabling collection, a deployment must define a bounded backup/WAL expiry period and test restoration against deletions. API deletion removes facts from the primary database immediately; retained backups may still contain them, and restoring a pre-deletion snapshot without reconciling later tombstones can restore stale records.

The initial registration fingerprint remains with the active current record so a lost registration response can be retried idempotently; it is removed on deletion or expiry. No report history is exposed.

## Deployment example

[`deploy/connect-server.service`](deploy/connect-server.service) is a systemd hardening example. Keep database credentials in a root-readable environment file outside this repository. Terminate HTTPS at a maintained reverse proxy, bind the application to loopback, and use a proxy access-log format that records only timestamp, method and response status. Do not put private hostnames, addresses, TLS material or credentials in this repository.
