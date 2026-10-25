# Installation reporting protocol v1

This document covers only the consented installation/version reporting API. Pairing, provider offers, credentials for providers and browser flows are not part of v1 in this repository.

## Consent and identity

A client must not make any request while its persistent installation-reporting permission is `unset` or `denied`. An explicit `allowed` choice permits registration and later reports. Manual provider pairing, when designed separately, must not imply reporting consent.

The client generates and persists an installation ID and bearer credential before its first request:

- `installation_id`: 32 bytes from a cryptographically secure random generator, encoded as unpadded base64url (43 characters).
- Credential: independently generated 32 random bytes, sent only in `Authorization: Bearer <base64url>` over HTTPS. The server stores SHA-256 of the decoded credential, not the credential itself.
- `event_id`: a fresh independent 32-byte random value for each logical report. An unacknowledged retry reuses the exact event ID and report content.

The installation ID is an opaque reporting identifier. It is not a hardware identity or evidence of ownership. The bearer credential authorizes only these reporting endpoints; it cannot initiate provider enrollment or retrieve other records.

## Report object

Requests use `Content-Type: application/json`. The object is strict: unknown properties, trailing JSON, invalid enum values and oversized bodies are rejected.

```json
{
  "protocol_version": 1,
  "consent_version": 1,
  "installation_id": "<43-character-base64url-id>",
  "event_id": "<43-character-base64url-id>",
  "mdb": {
    "board_variant": "unu-mdb",
    "firmware_version": "1.2.3",
    "version_known": true,
    "version_live": true
  },
  "dbc": {
    "board_variant": "unu-dbc",
    "firmware_version": null,
    "version_known": false,
    "version_live": false
  },
  "software_capabilities": ["connect.reporting.v1"],
  "installer_version": null
}
```

The `mdb` and `dbc` objects are omitted only when their respective board is absent; when present, each contains every field shown in the example. Unknown firmware versions and unrecognized board variants are represented with `null`. `board_variant` accepts only `unu-mdb`, `unu-dbc`, or `null`; the MDB object may use only `unu-mdb`, and the DBC object may use only `unu-dbc`.

An unknown firmware version is `null` with both flags false. A known cached version has a string value, `version_known: true`, and `version_live: false`. A currently observed version has a string value and both flags true. A live version cannot be marked unknown. Version strings are bounded to 64 ASCII version characters.

`software_capabilities` is a non-empty, duplicate-free array from the fixed enum `connect.reporting.v1`, `connect.pairing.v1`. Clients send only capabilities actually implemented by their build, sorted lexicographically. This reporting-only slice emits `connect.reporting.v1`; the pairing capability does not activate a server pairing feature. `installer_version` is `null` when unknown; otherwise it is a bounded version string.

No hardware serials, VIN, IMEI, SIM identifiers, location, uptime, service state, riding data, request IP or arbitrary software inventory are accepted. Optional hardware inventory is not implemented and would require a separate default-off consent contract.

## Endpoints

Deploy the listener only behind a trusted HTTPS TLS terminator; the service itself speaks plain HTTP and must not be exposed directly to the Internet. Request and response bodies are bounded. API errors have a generic JSON code and do not include database errors or submitted values.

### `POST /api/v1/installations`

Creates an installation reporting record and accepts its initial report. The bearer credential is generated and persisted by the client before this call; it is not in the JSON body. The ID and event ID in the report must be valid random identifiers.

A successful create or exact registration retry returns `204 No Content`. The same installation ID, credential, initial event ID and canonical report digest are idempotent even after process restart. Reusing the ID with another credential, changing the original event, or attempting to register a tombstoned ID returns a generic `409 conflict` or `401 unauthorized`.

Clients must use `PUT` for later events; a new event is not accepted through `POST`.

### `PUT /api/v1/installations/{installation_id}/report`

Replaces the latest report facts. The path ID and body `installation_id` must match. A valid bearer credential is required.

A successful report or exact retry returns `204 No Content`. For event IDs with a retained receipt, the same ID and canonical report digest returns success without refreshing retention; a changed digest returns `409 conflict`. Receipt records are pruned after 30 days. The client must not reuse event IDs after that bounded deduplication period.

A report ID with no active credential, an expired installation or a bad credential receives the same generic `401 unauthorized` response. There is no endpoint to read a stored report.

### `DELETE /api/v1/installations/{installation_id}`

Deletes report facts, credentials, consent metadata and idempotency receipts, then keeps only the random installation ID and tombstone timestamp. The request requires the active bearer credential and has no body. A successful deletion returns `204 No Content`; a later delete using the erased credential receives `401 unauthorized`. A later registration using the tombstoned ID cannot recreate the record.

### Health

`GET /healthz` is process liveness. `GET /readyz` checks PostgreSQL with a one-second timeout. Both return `204 No Content` on success. Readiness failure returns only `503` and `{"error":"not_ready"}`.

## Idempotency and retention

The canonical digest is SHA-256 of the validated, normalized report structure serialized in its fixed field order. The capability list is sorted before hashing. Equivalent JSON whitespace, object-key order and capability ordering produce the same digest. Values and event IDs remain part of the digest.

Current report facts expire 24 calendar months after the last accepted distinct report. Identical retries do not extend the period. A cleanup hook also runs on startup and every minute. Expiry converts the row to the same minimal ID-and-timestamp tombstone used by deletion and adds an identity-free monthly count. Report receipts are deleted after 30 days. The current registration fingerprint is retained only with the active record to make initial registration retryable, and is erased on deletion or expiry.

This repository configures no backups. Any deployment must define a bounded backup/WAL lifetime and test deletion-aware restore before enabling collection. API deletion removes facts from the primary database immediately; retained backups may still contain them, and restoring a pre-deletion snapshot without reconciling later tombstones can restore stale records. No API exposes installation enumeration, report facts or aggregate tables.

## Error responses

| Status | Code | Meaning |
| --- | --- | --- |
| `400` | `bad_request` | Invalid JSON, schema, identifier, query string or forbidden body |
| `401` | `unauthorized` | Missing/invalid credential or no active record |
| `404` | `not_found` | Unknown API path or invalid resource path |
| `405` | `method_not_allowed` | Wrong method; `Allow` names the supported method |
| `409` | `conflict` | Reused installation/event identifier with different data |
| `413` | `request_too_large` | Body exceeds configured limit |
| `415` | `unsupported_media_type` | JSON request lacks `application/json` |
| `429` | `rate_limited` | Trusted ingress request-rate or connection limit exceeded |
| `500` | `internal_error` | Generic persistence or service error |
| `503` | `not_ready` | PostgreSQL readiness check failed |

Errors never contain request bodies, authorization values, credentials, hardware identifiers or internal database details. The application emits no per-request access log and does not store request IP addresses.
