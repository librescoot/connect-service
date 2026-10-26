# Pairing protocol v1

Status: reviewed encrypted-offer proposal, separate from the implemented initial [claim-exchange enrollment flow](enrollment-v1.md). Its Go/Ruby wrapper fixtures remain available for that proposal. This is a contract only; no pairing HTTP handlers, database persistence, provider enrollment, provider credentials, scooter clients or UI are implemented here. The machine-readable API and message schemas are in [`pairing-openapi-v1.yaml`](pairing-openapi-v1.yaml). Installation reporting remains a separate protocol in [`protocol-v1.md`](protocol-v1.md).

## Security and trust boundaries

Pairing is independent of installation reporting. A registration contains no installation ID, reporting token, consent field or reporting facts. A pairing token cannot access reporting endpoints, and a reporting token cannot access pairing. No pairing request or result changes installation-reporting permission.

The rendezvous stores opaque signed JWS and encrypted JWE bytes. It verifies provider signatures and binding metadata but has no device private key or decryption path. Only the pairing agent has the per-session P-256 private key. The rendezvous remains trusted for availability, provider routing and correct public-key distribution; encryption does not make a compromised rendezvous harmless.

The provider ID and provider key ID are resolved only through the operator's exact provider registry. V1 production configuration enables `sunshine` only. No request value may select a URL, remote key set or callback origin. Device and provider bearer credentials are independent, high-entropy 32-byte values and are sent only in HTTPS authorization headers. Public session, transaction and handoff IDs are not credentials.

Pairing capabilities must not be exposed through lsd routes. An unauthenticated lsd route is not an acceptable boundary for start/show/cancel or capability retrieval. The eventual local entry point remains `/run/librescoot-connect/control.sock`, a privileged Unix control socket that is root-owned by default. A Bluetooth entry point remains gated on verification of the real authenticated-peer authorization boundary; it may return a code only after explicit authorized retrieval. Do not broadcast a code, QR capability, token or offer through Redis, status hashes, ordinary logs or unauthenticated BLE characteristics. Local network reachability alone is not authorization.

The provider's `radio-gaga/v1` plaintext configuration schema and provider client are not part of this freeze. The encrypted wrapper has a fixed UTF-8 JSON content type; provider integration must separately freeze and validate its typed plaintext schema before issuing real credentials.

## Identifiers, keys and time

- Protocol version is integer `1` in every JSON object.
- `session_id`, `creation_request_id`, `activation_request_id`, `exchange_request_id`, `selection_request_id`, `handoff_id`, `transaction_id`, `result_id` and `cancellation_request_id` are independent 32-byte CSPRNG values encoded as unpadded base64url (43 characters). They are identifiers, not bearer credentials.
- The device polling credential, claim QR capability, browser ceremony cookie and provider bearer credential are each independently generated 32-byte CSPRNG values. They are never reused for another purpose. The claim code is separate: 10 Crockford Base32 characters, displayed as `XXXXX-XXXXX`, submitted without the hyphen. The alphabet is `0123456789ABCDEFGHJKMNPQRSTVWXYZ`; implementations use rejection sampling, not modulo-biased random selection.
- The per-session recipient key is P-256. The device persists the private key before registration and sends only public JWK members `kty`, `crv`, `x`, `y`, and `kid`. `kid` is exactly `device-p256-v1`. Coordinates are 32-byte unpadded base64url values. The recipient fingerprint is the RFC 7638 SHA-256 JWK thumbprint over the canonical required public members `crv`, `kty`, `x`, `y`; `kid` is excluded.
- `issued_at`, `expires_at`, registration expirations and ceremony deadlines are integer Unix seconds in UTC. There is no signature or expiry clock leeway. A client with an untrusted clock does not disable TLS validation or accept an expired offer.
- Registration hard expiry is creation time plus 7 days and is not extended. An active claim window expires at the earlier of activation plus 15 minutes or registration hard expiry. A browser ceremony deadline is the earlier of first successful exchange plus 60 minutes or registration hard expiry. Renewing a claim or retrying a request does not extend those deadlines.

## Device registration and claim window

The device generates and durably stores `session_id`, `creation_request_id`, the polling credential, the private key and its public fingerprint before sending registration. Registration retries reuse the exact request body and polling credential. A matching retry returns the same registration. Reusing an ID with a different credential, request ID, public key or key fingerprint conflicts. A duplicate public key with different registration material conflicts. A public session ID alone never authorizes access.

`POST /api/v1/registrations` sends the polling credential in `Authorization: Bearer`, not the JSON body. The server stores only its digest and the public key. Registration starts in generation `0`, state `registered`, with a fixed hard expiry. It is not a claim window and cannot be exchanged in a browser.

`POST /api/v1/registrations/{session_id}/claim-window` is authenticated by the polling credential. The device chooses a fresh activation request ID, claim code and QR capability, and persists all display material before reporting success. These capabilities are sent over TLS; the server stores keyed digests only and never returns their plaintext. An exact retry with the same activation request ID and digests returns the same generation and expiry. A new activation invalidates the previous window and increments generation by one. It does not change the reporting identity or consent. The response contains the generation and expiry, not the code or QR capability.

The browser submits either the canonical 10-character claim code or the 43-character QR capability, never both, in a `POST /pair/exchange` body. The typed form accepts uppercase or lowercase Crockford characters with either no hyphen or the single display hyphen at position 6; it normalizes only ASCII lowercase to uppercase and removes that one hyphen. It rejects whitespace, other separators and ambiguous letters rather than guessing. The URL form is `https://connect.librescoot.org/pair#<qr-capability>`; first-party code reads the fragment, POSTs it, and immediately removes it from browser history. A GET, prefetch or link preview cannot exchange or reserve a session. Typed-code and QR failures have indistinguishable response bodies. Exchange requests include a fresh `exchange_request_id`; an exact retry returns the same browser ceremony so a lost response can recover without creating a second active ceremony. The claim capability is consumed atomically by the first successful exchange.

Successful exchange creates a browser ceremony cookie that is `Secure`, `HttpOnly`, `SameSite=Lax`, scoped to `/pair`, and never placed in a URL or response body. The exchange response returns a CSRF token in JSON; mutating browser requests send it in `X-CSRF-Token`. The server cookie is the only browser session credential. Pairing responses use `Cache-Control: no-store`; pages use a restrictive CSP and `Referrer-Policy: no-referrer` and have no third-party script, font or analytics dependencies.

## Browser ceremony, provider selection and handoff

The browser ceremony has one fixed generation and one absolute deadline. It exposes only sanitized progress, the provider allowlist and a non-identifying label if supplied by a separate approved contract. No device polling credential, private key, provider credential, raw offer, encrypted payload or installation-report data is sent to browser code.

`POST /pair/provider` requires the ceremony cookie and CSRF token. The body contains the current generation, a selection request ID and an exact provider ID from the enabled registry. Provider choice occurs only on this explicit POST, never on exchange, QR preview or a page load. `sunshine` is the only enabled v1 provider. Repeating the same selection request is idempotent; a different provider or competing selection for the same generation conflicts. Provider origins, handoff destinations, keys and callback paths come only from operator configuration.

Selection creates a random public `handoff_id` and atomically reserves this generation for the selected provider. The browser is directed to the exact configured provider origin with only this non-secret handoff ID. It is not a bearer token. The provider server redeems it through its authenticated server-to-server API using the provider's registered credential. The handoff is audience-bound to the selected provider, session and generation, one-use, and expires at the browser ceremony's absolute deadline; it cannot be redeemed afterward. An exact retry with the same provider request ID returns the same redemption result. A different provider or request ID cannot redeem it.

Redemption returns only the pairing context required by the provider: session ID, generation, provider ID, registration expiry, recipient public JWK, recipient fingerprint and protocol capabilities. It never returns the polling credential, claim capability, installation/report identity, private key, or a prior connection credential. Sunshine owns login, account creation, terms, ownership/conflict checks and final account confirmation. A browser redirect alone is not user confirmation and cannot authorize an offer.

The provider creates a stable provisioning transaction only after its own explicit account confirmation. It signs and encrypts one immutable offer and submits it through the authenticated provider API. An identical retry of the same transaction and exact signed bytes succeeds. Any changed ciphertext, digest, binding or signature for that session generation and transaction conflicts. A new credential or offer requires a new user-started ceremony and generation.

## Signed, encrypted offer

The transfer format is exactly compact JWS containing a JSON payload whose `ciphertext` member is exactly compact JWE. JWS JSON Serialization, JWE JSON Serialization, nested JSON serialization alternatives and detached payloads are rejected.

The outer JWS protected header has exactly these members and values:

```json
{"alg":"ES256","kid":"<registered-provider-signing-key-id>","typ":"application/librescoot-pairing-offer+jws"}
```

`kid` must exactly match a currently registered ES256 provider key for the signed `provider_id`. It is not interpreted as a URL or used to fetch a key. ES256 uses P-256 and SHA-256; JOSE signatures are the 64-byte `R || S` representation, not ASN.1 DER.

The signed JSON payload has exactly these members, with no unknown or duplicate keys:

```json
{
  "protocol_version": 1,
  "session_id": "<43-character-id>",
  "generation": 1,
  "provider_id": "sunshine",
  "transaction_id": "<43-character-id>",
  "issued_at": 2000000000,
  "expires_at": 2000003600,
  "recipient_key_fingerprint": "<RFC-7638-SHA-256-thumbprint>",
  "ciphertext_digest": "<base64url-sha256-of-compact-JWE>",
  "ciphertext": "<compact-JWE>"
}
```

`ciphertext_digest` is SHA-256 over the UTF-8 bytes of the complete compact JWE string, encoded as unpadded base64url. Offer binding fields are verified against the authenticated registration and provider handoff, not merely trusted because they are signed. The offer is immutable after first acceptance. Max plaintext is 32 KiB, compact JWE is 48 KiB, and compact JWS is 64 KiB. Oversize input is rejected before parsing/decryption.

The compact JWE uses `ECDH-ES+A256KW` and `A256GCM`, and has no compression. Its protected header has exactly the following members; `epk` contains exactly `kty`, `crv`, `x`, and `y` for an ephemeral P-256 public key:

```json
{
  "alg": "ECDH-ES+A256KW",
  "enc": "A256GCM",
  "kid": "device-p256-v1",
  "cty": "application/librescoot-pairing-config+json",
  "connect-v": 1,
  "connect-sid": "<session-id>",
  "connect-gen": 1,
  "connect-pid": "sunshine",
  "connect-tid": "<transaction-id>",
  "connect-iat": 2000000000,
  "connect-exp": 2000003600,
  "connect-recipient-thumbprint": "<RFC-7638-SHA-256-thumbprint>",
  "epk": {"kty":"EC","crv":"P-256","x":"<32-byte-base64url>","y":"<32-byte-base64url>"}
}
```

The complete protected-header segment is JWE additional authenticated data under RFC 7516. The version, session, generation, provider, transaction, issue/expiry times and recipient fingerprint are therefore authenticated by both the outer JWS and the JWE. The signed ciphertext digest additionally binds the exact encrypted object to the provider signature. The device verifies the provider key ID, signature, every expected binding field, digest, recipient thumbprint, fixed algorithm/header allowlists, offer time bounds and registration hard expiry before accepting plaintext. It rejects unknown algorithms, `crit`, `zip`, `jku`, `x5u`, embedded `jwk`, unregistered key IDs, non-compact serialization, duplicate JSON members, unknown fields and recipient substitution.

`issued_at` cannot be in the future. `expires_at` must be strictly after current trusted time, no more than 24 hours after `issued_at`, and no later than registration hard expiry. Re-delivery never extends expiry. The device may defer applying a fetched offer while vehicle state or a conflicting update/import operation is unsafe; it never unlocks or forces a vehicle-state transition to apply pairing. If the offer expires before safe application, the user starts a new ceremony.

## Offer retrieval, device result and provider receipt

`GET /api/v1/registrations/{session_id}/offer` uses the device polling credential. It returns only the exact stored signed JWS and public metadata for the authenticated session's current generation. It marks that immutable offer as fetched. Retries return the same bytes. After offer expiry, an offer not previously fetched is not delivered. The broker cannot decrypt or redact the JWE.

`POST /api/v1/registrations/{session_id}/result` requires device authentication and binds every result to generation, transaction ID and ciphertext digest. The agent persists its result before sending it. `waiting_for_safe_state` and `applying` are monotonically sequenced progress updates; `committed` and `failed` are terminal device outcomes. A failed result has one stable public error code and no raw configuration, credential, upstream body or stack trace. Exact result ID/body retries are idempotent; changed content under the same result ID conflicts. The committed result is the device ACK for exactly that immutable offer and cannot acknowledge a different generation, transaction or digest.

The device may report progress or a terminal result until 24 hours after offer expiry only if it fetched that exact offer before expiry. After that window the broker reconciles with the provider. The provider separately posts an authenticated connection receipt bound to provider, session, generation, transaction and ciphertext digest. A receipt is not inferred from a device ACK. The browser shows `connected` only after both a committed device result and matching authenticated provider receipt. The provider reads cancellation and reconciliation state through the authenticated `GET /api/v1/provider/registrations/{session_id}` route in [`pairing-openapi-v1.yaml`](pairing-openapi-v1.yaml), not through an unauthenticated callback URL. If the reconciliation deadline passes without a receipt, the provider may revoke only credentials created by that transaction. A confirmed connection receipt prevents revocation even when the device ACK was lost. Neither result replay nor receipt retry creates or rotates credentials.

## Cancellation and state transitions

Device cancellation is `DELETE /api/v1/registrations/{session_id}` with device bearer authentication and `If-Match: "generation-N"`. It has no body. The generation precondition prevents an old cancellation from cancelling a refreshed pairing. Repeating a cancellation for that terminal generation is idempotent. A matching cancellation revokes claim access, ceremony cookies, handoffs and undelivered offers and suppresses delivery for that generation. It does not disconnect an established provider. Cancellation after a confirmed connection returns `409 already_connected`; managed disconnect is a separate explicitly authorized future protocol.

Browser cancellation is `POST /pair/cancel` with the browser cookie, CSRF token, generation and cancellation request ID. It terminates only the matching pending generation and cannot disconnect an established provider. A provider that redeemed the handoff observes cancellation through its authenticated registration-status read and cleans up only provisional credentials it created. A cancellation racing with a committed provider receipt resolves to connected; it cannot revoke a connected credential. Starting a fresh local claim window after terminal cancellation increments generation and invalidates every old capability, cookie and offer.

Registration states and allowed transitions:

| State | Event | Next state | Rule |
| --- | --- | --- | --- |
| `registered` | claim activation | `claim_active` | Generation becomes 1; activation ID is idempotent. |
| `claim_active` | same activation retry | `claim_active` | Same generation, code/QR digests and expiry. |
| `claim_active` | new activation | `claim_active` | Increment generation; revoke the prior window and all prior ceremony state. |
| `claim_active` | code/QR exchange | `browser_open` | Consume matching capability once and start the bounded ceremony. |
| `browser_open` | explicit provider selection | `provider_selected` | Reserve exactly one provider for this generation. |
| `provider_selected` | authenticated handoff redemption | `handoff_redeemed` | One audience-bound redemption; same request ID retries. |
| `handoff_redeemed` | valid signed offer accepted | `offer_ready` | Persist one immutable transaction/envelope. |
| `offer_ready` | authenticated device fetch | `offer_fetched` | Exact offer bytes are replayable until offer expiry. |
| `offer_fetched` | device progress update | `applying` | Sequence increases; safe-state wait is a progress condition. |
| `offer_fetched` or `applying` | failed result | `failed` | Terminal for this generation; new setup needs new generation. |
| `offer_fetched` or `applying` | committed result | `device_committed` | Exact offer ACK; provider receipt may still be pending. |
| `device_committed` | provider connection receipt | `connected` | Both authenticated receipt and device commit are required for web success. |
| Any pending state | expiry or matching cancellation | `expired` or `cancelled` | Terminal for this generation; old secrets cannot be reactivated. |

`connected`, `cancelled` and `expired` are terminal for that generation. A new local activation increments generation only while the registration hard expiry has not passed; after that the device creates a new session. `failed`, `cancelled` and `expired` are terminal for that generation. A fresh local activation may create a new generation while the registration remains live; the provider must reconcile or revoke only its own provisional credentials from the failed generation before issuing another transaction. `connected` is terminal for the registration. Cancellation and connection receipt are serialized per session generation. If a connection receipt wins the race, the server preserves connected credentials. Offer state is retained only through the 24-hour post-expiry reconciliation deadline; cleanup does not change an installation report or an established provider connection.

State transitions are serialized per registration and generation with database transactions and uniqueness constraints. Provider network calls occur outside database locks. A registration backup restore invalidates all pending claim windows, browser cookies, handoffs and undelivered offers before serving traffic; restoring a consumed capability must never make it usable again. Existing provider connections do not depend on the rendezvous or its restored state. Short-code digests use a dedicated keyed digest secret; device/provider bearer credentials and browser cookies are stored only as digests. Access logging omits request bodies, authorization headers, capability codes, query strings and ceremony-bearing paths. All request and response sizes are bounded; compact JWS is at most 64 KiB and the JSON request/response wrapper carrying one is at most 66 KiB. Claim exchange and provider handoff redemption are rate-limited with shared-carrier NAT in mind.

## Installation reporting separation

The reporting objects and endpoints in `protocol-v1.md` and `openapi.yaml` remain independent. Pairing API schemas do not include reporting fields and do not use a reporting bearer credential. Reporting API schemas do not include registration IDs, pairing capabilities, browser sessions, provider IDs, handoffs or offers. No installation report creates a pairing registration; no pairing action implies reporting consent. Optional hardware inventory remains separately consented and is not disclosed by this protocol.

## Go and Ruby JOSE interoperability

The Go implementation pins `github.com/go-jose/go-jose/v4` v4.1.6, whose upstream release includes the fix for [GHSA-mgcc-cww5-fp2q](https://github.com/go-jose/go-jose/security/advisories/GHSA-mgcc-cww5-fp2q). Go/Ruby producers and consumers must implement the exact compact JWS and compact JWE algorithms, protected-header member sets, sizes, casing, ID encodings, RFC 7638 thumbprint, Unix-second times and digest calculation above. Both sides reject rather than downgrade unknown algorithms or headers. Neither implementation performs `jku`, `x5u`, embedded-key, network key resolution or compression processing. Ruby ES256 signatures must be JOSE `R || S`, and JWE ECDH uses the per-session P-256 public JWK with `kid` exactly `device-p256-v1`.

The JOSE protected-header segment is authenticated as serialized by its producer; consumers authenticate the exact transmitted segment and compare its parsed binding members. The JWS payload is the exact transmitted UTF-8 JSON byte sequence covered by the signature. JSON member ordering is not a cross-language signing convention; duplicate members, unknown members and trailing JSON are rejected. Ruby must serialize once and pass the same bytes to its JOSE library, not parse and reserialize a signed payload before verification. CSPRNG output and the compact JWE are intentionally not deterministic.

The Go crypto tests use fixed synthetic P-256 key scalars, synthetic IDs and synthetic plaintext. [`fixtures/pairing-v1.json`](fixtures/pairing-v1.json) is a Go-generated signed-and-encrypted vector; [`fixtures/pairing-v1-ruby.json`](fixtures/pairing-v1-ruby.json) is a Ruby-generated reciprocal vector. Go tests verify and decrypt both. Run `ruby scripts/pairing-jose-interop.rb` with Ruby JOSE 1.2.0 to verify and decrypt both fixtures in Ruby. These fixtures and the test-only private scalars contain no production credentials. Interoperability was run with Go go-jose/v4 4.1.6 and Ruby jose 1.2.0.

## Error behavior and headers

Pairing errors use stable JSON `{ "error": "<code>" }` and never contain request bodies, code values, bearer credentials, provider credentials, encrypted payloads, database errors or stack traces. `Cache-Control: no-store` applies to all pairing responses. Pairing endpoints reject query strings that could carry ceremony or capability state. GET is read-only and never consumes a capability, selects a provider, redeems a handoff, acknowledges an offer or cancels a session. All mutations are POST/DELETE with their specified credentials, idempotency identifiers and CSRF checks. HTTPS hostname and time verification remain enabled.
