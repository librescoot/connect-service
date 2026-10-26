# Configuration-only enrollment v1

This implementation connects an installed client through a provider-neutral rendezvous. The initial real profile is `radio-gaga/1`; the separate `sunshine-poc/v1` demonstration remains local-only. This claim-exchange API replaces the encrypted-configuration delivery proposal for the initial integration. The bouncer never receives permanent provider credentials or client configuration.

## Flow

1. Explicit `connect register` queries the installed client's profiles, registers them and privately saves the returned polling credential.
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
- `POST /api/v1/enrollments/{session_id}/code`: device bearer; returns code, pairing URL and expiry. Explicit refresh before browser exchange invalidates the previous code/QR pair.
- `GET /api/v1/enrollments/{session_id}/claim`: device bearer; returns sanitized state until approval, then `session_id`, `provider_id`, `provider_origin`, selected `profile`, short-lived `claim_token` and expiry.
- `POST /api/v1/enrollments/{session_id}/complete`: device bearer; idempotently marks completion and deletes the claim token.
- `GET /api/v1/provider/{provider_id}/{handoff_id}`: provider bearer; returns the reserved session, selected profile and ceremony deadline. A handoff ID alone cannot retrieve context.
- `POST /api/v1/provider/{provider_id}/{handoff_id}`: provider bearer and `{ "claim_token": "..." }`; identical retries succeed, changed claims conflict.
- `GET /healthz`: immutable build revision only.

`GET /pair` is read-only. Browser exchange and explicit provider selection use CSRF-protected POST forms. Claim codes contain ten Crockford Base32 characters, displayed as five-five. QR capabilities and bearer credentials contain 32 random bytes. Codes/QR capabilities are consumed together on successful browser exchange. Registration lasts seven days; browser approval and claim retrieval have a fixed 60-minute deadline after exchange.

The single-process bouncer holds at most 512 transient registrations in a private, atomically replaced state file. Device polling credentials and display capabilities are stored as digests. Expiry is swept each minute. Source rate limits, a bounded limiter table and the global registration cap bound public resource use. Deploy a trusted rate/connection-limited ingress; only the loopback proxy may supply `X-Real-IP`. Access logs must omit capabilities, bodies and authorization headers.

Pairing state is disposable and is not backed up. Loss or restore of transient state requires a new local registration/ceremony; never restore a snapshot containing old browser/code capabilities. Established provider connections do not depend on this state.

## Installed client interface

The initial CLI supports `register`, `code`, `status` and `wait`. It persists pairing state under `/data/connect-service/` with private permissions and a process lock. No automatic startup, reporting, DBC, BLE, installer or package installation is enabled.

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

Sunshine reuses `BootstrapToken` with a distinct `connect` purpose. That token cannot authenticate to the existing general bootstrap/install endpoints. Approval is account-bound and expires with the ceremony. Direct exchange is under `/api/v1/connect/exchange`; it binds the claim to the exact session/profile and first submitted hardware identity. Existing hardware records are refused; this flow never rotates an existing scooter's credentials or transfers ownership. Identical retries return the same encrypted-at-rest provisioning material and reprovision the same broker password if needed.

The `radio-gaga/1` payload contains the session/profile/transaction, scooter identifier and ID, credential, MQTT endpoint/username and CA certificate. It contains no YAML, commands, filesystem paths or Redis target. Radio-gaga renders a production configuration locally with verified MQTT TLS and shell/Redis commands disabled.

Radio-gaga applies only a new `/data/radio-gaga/config.yaml`, using its existing probe/transaction engine with an atomic no-replace installation mode and mode 0600. Existing or concurrently created configuration blocks enrollment. Its private journal resumes lost exchange/completion responses without rotating credentials or reapplying a committed config. Before real application it checks stationary vehicle state and inactive update status. It starts and verifies only `librescoot-radio-gaga.service`; it never unlocks or forces a vehicle-state transition. This is an explicit administrative CLI, not an unattended OTA/import integration; physical rollout remains separately authorized.

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
