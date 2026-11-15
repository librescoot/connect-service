# Configuration-only enrollment v1

This implementation connects an installed client through a provider-neutral rendezvous. The initial real profile is `radio-gaga/1`; the separate `sunshine-poc/v1` demonstration remains local-only. This claim-exchange API replaces the encrypted-configuration delivery proposal for the initial integration. The bouncer never receives permanent provider credentials or client configuration.

## Flow

1. Explicit `connect register` queries the installed client's profiles, registers them and privately saves the returned polling credential. It sends available IMEI, ICCID and full MDB serial to the rendezvous for this session.
2. Explicit `connect code` requests a 15-minute claim window and displays a code and fragment-bearing pairing URL.
3. The user exchanges the code on connect, chooses a compatible provider, logs in there and confirms the connection. The browser receives no claim or permanent credential.
4. The provider retrieves the selected session/profile using its own server credential, then submits a short-lived claim token bound to that session.
5. `connect wait` retrieves the claim using the scooter's polling credential. It invokes the installed client's enrollment operation with JSON on stdin.
6. The client exchanges the claim directly with the selected provider, validates its profile-specific connection material and applies its own configuration. Retries retain the same transaction and credential.
7. After its verified connection/configuration succeeds, the client records completion directly with the provider. The CLI acknowledges connect, which discards its claim token.

Public communication uses verified HTTPS, with no credential-bearing redirects. Operator registry configuration pins provider origins, profile support and separate S2S credentials. Device-generated key binding and certificate-based S2S authentication remain compatible additions; this version uses scoped high-entropy bearer credentials.

## Rendezvous API

All responses are `Cache-Control: no-store`. Bearer authentication uses the Authorization header, never a query string. Display capabilities and provider claims use their specified POST bodies; arbitrary callback destinations are not accepted. There is no anonymous enumeration or reporting side effect.

- `POST /api/v1/enrollments`: `{ "profiles": ["radio-gaga/1"] }`; returns random `session_id`, `polling_token` and `expires_at`.
- `POST /api/v1/enrollments/{session_id}/identity`: device bearer; optional `imei`, `iccid` and `mdb_serial` strings. Accepted before the claim window starts. The full MDB serial is lowercase hexadecimal. Missing fields are omitted; malformed identifiers are rejected. Existing registrations without this step remain supported.
- `POST /api/v1/enrollments/{session_id}/code`: device bearer; returns code, pairing URL and expiry. Explicit refresh before browser exchange invalidates the previous code/QR pair.
- `GET /api/v1/enrollments/{session_id}/claim`: device bearer; returns sanitized state until approval, then `session_id`, `provider_id`, `provider_origin`, selected `profile`, short-lived `claim_token` and expiry.
- `POST /api/v1/enrollments/{session_id}/complete`: device bearer; idempotently marks completion and deletes the claim token.
- `GET /api/v1/provider/{provider_id}/{handoff_id}`: provider bearer; returns the reserved session, selected profile, ceremony deadline and optional `identity` object. Only the selected provider can retrieve it. A handoff ID alone cannot retrieve context.
- `POST /api/v1/provider/{provider_id}/preclaims` and `DELETE` at the same path: enabled provider bearer and `{ "iccid": "..." }`. Add or remove an ICCID provider restriction, idempotently. A different provider cannot overwrite or remove an existing restriction. The operator must explicitly enable `preclaim_enabled` for that provider.
- `POST /api/v1/provider/{provider_id}/{handoff_id}`: provider bearer and `{ "claim_token": "..." }`; identical retries succeed, changed claims conflict.
- `GET /healthz`: immutable build revision only.

`GET /pair` is read-only. Browser exchange and explicit provider selection use CSRF-protected POST forms. Provider redirects carry the handoff in `/connect#<handoff>`, never in a request query. The provider landing page removes that fragment and submits it in a CSRF-protected POST before login; later confirmation/login URLs contain no handoff capability. Claim codes contain ten Crockford Base32 characters, displayed as five-five. QR capabilities and bearer credentials contain 32 random bytes. Codes/QR capabilities are consumed together on successful browser exchange. Registration lasts seven days; browser approval and claim retrieval have a fixed 60-minute deadline after exchange.

The single-process bouncer holds at most 512 transient registrations in a private, atomically replaced state file. Device polling credentials and display capabilities are stored as digests. Expiry is swept each minute. Source rate limits, a bounded limiter table and the global registration cap bound public resource use. Deploy a trusted rate/connection-limited ingress; only the loopback proxy may supply `X-Real-IP`. Access logs must omit capabilities, bodies and authorization headers.

Pairing state is disposable and is not backed up. Loss or restore of transient state requires a new local registration/ceremony; never restore a snapshot containing old browser/code capabilities. Established provider connections do not depend on this state.

Provider preclaims are separate from transient pairing state, in the private `pairing.json.preclaims` file alongside the configured state path. They survive restarts and session expiry. Back up and reconcile this registry with the provider's authoritative records; restore it independently of transient ceremony state. Removing a provider or disabling its preclaim capability requires removing its entries first. Providers must serialize adds and removals for each ICCID and retry/reconcile failed requests. These records restrict provider selection only; they do not create a scooter, link an account, issue credentials or establish ownership. On a match, only that provider appears and the server also rejects attempts to select another. No live provider lookup is required. If the ICCID is unavailable, no restriction can be applied. Device-reported identifiers can be copied and must never be used as proof of ownership.

Explicitly starting Connect sends available device identifiers to the rendezvous before provider selection. The client reads `internet[sim-imei]`, `internet[sim-iccid]` and `version:mdb[serial_number_real]` from local Redis, independently omitting unavailable or malformed fields. Registration and identity submission are separate so older rendezvous servers, which return 404 for the identity endpoint, continue to support pairing without this feature. A newer rendezvous accepts older clients without an identity; no ICCID restriction can be applied to those clients. The provider receives the identifiers only after it is selected and authenticates the handoff. The rendezvous removes session identifiers on completion or expiry. Keep identifiers and credentials out of access logs, URLs and browser output.

Upgrade the bouncer before the client and enable the provider registry only after the provider can synchronize it. Older bouncers reject session files containing identity fields: when rolling back, discard transient session state and start new ceremonies rather than restoring capabilities. An older bouncer does not enforce the preclaim registry. Existing stable images remain unchanged until a release updates their Connect pin.

## Installed client interface

The initial CLI supports `register`, `code`, `status` and `wait`. It persists pairing state under `/data/connect-service/` when `/data` exists, or `/var/lib/connect-service/` otherwise, with private permissions and a process lock. No automatic startup, reporting, DBC, BLE, installer or package installation is enabled.

```sh
connect register
connect code
connect wait
connect status
```

`-client` chooses an installed executable through trusted local administration. The executable exposes:

- `-connect-capabilities`: JSON containing supported `profiles`.
- `-connect-enroll`: consumes `session_id`, `profile`, `provider_origin` and `claim_token` on stdin; returns a non-secret connected/profile result on stdout.

The bouncer cannot select that executable, its flags, local paths or service unit. Unknown profiles fail without downloading code. A future signed-package mechanism requires its own advertised capability and signing policy.

## Sunshine and radio-gaga

Sunshine reuses `BootstrapToken` with a distinct `connect` purpose. That token cannot authenticate to the existing general bootstrap/install endpoints. Approval is account-bound and expires with the ceremony. Direct exchange is under `/api/v1/connect/exchange`; it binds the claim to the exact session/profile and first submitted hardware identity. An existing hardware record may reconnect only when the approving account is its current owner and the device proves possession of its existing credential directly to the provider. The existing ownership, accepted claim, scooter record, configuration and credential remain unchanged. New installations still create their own claim and credential. Identical retries return the same encrypted-at-rest provisioning material and reprovision the same broker password if needed.

The `radio-gaga/1` payload contains the session/profile/transaction, scooter identifier and ID, credential, MQTT endpoint/username and CA certificate. It contains no YAML, commands, filesystem paths or Redis target. Radio-gaga renders a production configuration locally with verified MQTT TLS and shell/Redis commands disabled.

Radio-gaga selects the platform's managed configuration path: `/data/radio-gaga/config.yaml` for Librescoot 1.0.0 and later, `/etc/rescoot/radio-gaga.yml` for scooterOS 1.12.0 and later. A new configuration uses the existing probe/transaction engine with atomic no-replace installation and mode 0600. A compatible existing configuration is retained byte-for-byte after credential, owner, broker, service and verified-TLS checks; unrelated or concurrently created configuration blocks enrollment. Its private journal resumes lost exchange/completion responses without rotating credentials or reapplying a committed config. Before real application it checks stationary vehicle state and inactive update status. It starts and verifies only the locally installed radio-gaga service; it never unlocks or forces a vehicle-state transition. This is an explicit administrative CLI, not an unattended OTA/import integration; physical rollout remains separately authorized.

Direct `/api/v1/connect/complete` authenticates with the issued scooter credential, revokes the bootstrap claim and destroys cached claim/configuration material. An expiry task also revokes expired claims and removes their encrypted delivery material; minimal enrollment rows are removed after seven more days. Provider approval and successful device completion are distinct states.

## Validation

```sh
go test -race ./internal/enrollment
go test ./...
go vet ./...
python3 scripts/test-installed-client.py \
  --sunshine-dir /path/to/sunshine \
  --radio-gaga-dir /path/to/radio-gaga
```

The installed-client test uses disposable PostGIS databases, a real Sunshine web login, synthetic identities, compiled CLI/client binaries and a password-authenticated MQTT TLS broker with an ephemeral test CA. It exercises both typed-code and QR-URL entry, actual broker probe, private client-owned configuration, stable retries and claim revocation. No production account, scooter or broker is used by that test.
