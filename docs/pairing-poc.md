# Local three-component pairing proof of concept

This demonstration exercises the scooter, connect bouncer and real Sunshine Rails app locally:

1. Explicit `register` contacts connect and saves its returned polling credential privately. Registration does not create a claim code or contact Sunshine.
2. Explicit `code` requests a short-lived code and pairing URL. The code can be typed on connect; opening the URL fills its QR capability and strips the fragment from browser history.
3. The user chooses Sunshine on connect. A non-secret handoff ID takes the browser to Sunshine's normal login and then to an explicit connection confirmation.
4. Sunshine creates an account-bound enrollment and sends its claim token to connect over its authenticated provider interface. Neither claim token nor connection credential appears in the browser.
5. The scooter CLI retrieves the claim token using its polling credential, exchanges it directly with the pinned Sunshine origin, and proves possession of the returned connection credential.
6. Sunshine records a connection receipt. The CLI saves `cloud.json` privately and acknowledges connect, which removes the claim token. Repeated exchange or CLI completion does not rotate credentials.

The profile is `sunshine-poc/v1`: an authenticated HTTP connection with a disposable CLI identity. It does not provision radio-gaga, create a real `Scooter`, start telemetry, enable remote commands or change a vehicle. This proves the handoff, web account confirmation and return path before adding vehicle configuration. Reporting, DBC, BLE, lsd and installer integration are outside this slice.

## Run

Requirements: Go 1.25.14, Ruby 3.4.12, Sunshine's installed bundle, Python 3, Docker, and free loopback ports 4300/4301. The automated browser check also needs Chrome and ChromeDriver (or Selenium Manager). Use an isolated Sunshine working copy containing the matching proof-of-concept changes, based on the intended local main. Do not point the launcher at a production deployment.

From connect-service:

```sh
python3 scripts/pairing-poc-demo.py --sunshine-dir /path/to/sunshine-working-copy
```

The launcher starts a new disposable PostGIS container on a randomly assigned loopback port, loads empty Sunshine databases, builds both Go commands and starts the two local web servers. It creates a confirmed local test account, avoiding email or signup side effects. It prints a private temporary directory, the login password's file path, and these commands with the actual paths filled in:

```sh
/path/to/connect-poc-device -state-dir /private/demo/scooter register
/path/to/connect-poc-device -state-dir /private/demo/scooter code
/path/to/connect-poc-device -state-dir /private/demo/scooter wait
/path/to/connect-poc-device -state-dir /private/demo/scooter status
```

After `code`, open `http://127.0.0.1:4300/pair`, enter the code, choose Sunshine, log in with the test account and confirm. Run `wait` to finish; it can run while you complete the web flow. There is no second local approval. The output configuration is `/private/demo/scooter/cloud.json`, mode 0600. Do not paste it into logs or support reports.

Ctrl-C stops the demo services and removes the disposable database container and its volumes. Temporary configuration/log files remain in the printed private directory for inspection. Every launcher run creates fresh state; the original Sunshine checkout and any existing databases are untouched.

For the complete automated run:

```sh
python3 scripts/pairing-poc-demo.py --sunshine-dir /path/to/sunshine-working-copy --smoke
```

This uses headless Chrome for the actual chooser, Devise login and Sunshine confirmation; it then runs the compiled CLI, checks the saved configuration and stable retry, and verifies the account-bound receipt and absence of real scooters in Sunshine. Both servers and the database are stopped afterward.

## Implementation boundaries

- `cmd/connect-poc-bouncer` is separate from `cmd/connect-server`. It does not mount routes in the reporting server. Its routes are `/poc/v1/*` and `/pair`; these are not implementations of the proposed production pairing-v1 contract.
- Both Go commands reject non-numeric-loopback or non-HTTP origins and disable redirects/proxies for credential-bearing requests. The bouncer binds only its validated loopback origin and checks Host.
- Sunshine's adapter is disabled by default and rejects production/staging, non-local requests and database names not beginning with `sunshine_pairing_poc_`. The launcher binds Rails to loopback and supplies its own database URLs and secrets.
- Device state and bouncer state are separate private files. The device journal is process-locked. Atomic writes, restart recovery, stable codes until expiry, provider callback retries and stable claim exchange are exercised. An interrupted registration before its returned token is saved can leave an orphan that expires; this demo does not implement registration-response recovery.
- The bouncer stores only the device credential digest and code/QR digests. It temporarily holds the disposable claim token in its private state file. Sunshine encrypts its retryable token material using its local application key. These loopback HTTP demo tokens are not production credentials, and the signed/encrypted production wrapper is not used by this experiment.
- Claim codes last 15 minutes; successful exchange consumes both code and QR capability and starts a 60-minute web/claim ceremony. Registration lasts seven days. At most 100 registrations are retained. Start a fresh local demo for another account or expired ceremony; refresh/cancel/disconnect are not part of this proof of concept.
- Browser mutations use CSRF protection. Pairing pages have no third-party assets and use a same-origin referrer policy, avoiding cross-origin referrers while allowing ordinary same-origin form Origin checks. Provider URLs and exchange origins are operator-pinned, not taken from user input.

## Targeted checks

```sh
go test -race ./internal/poc -count=1
go test ./...
go vet ./...
```

The Go test suite exercises restart/retry behavior with a test HTTP provider. The `--smoke` run separately verifies the real Sunshine adapter and browser login. Sunshine's targeted controller tests cover login, explicit approval, competing-account rejection, token separation, session binding, expiry and the disabled-feature guard; run them only against disposable databases using the same `sunshine_pairing_poc_` naming convention.
