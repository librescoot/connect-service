# Generic deployment example

These are generic service-host examples. They contain no private production address, database credentials or TLS material.

## Configuration-only pairing

Build `cmd/connect-bouncer` with an immutable version (`-ldflags '-X main.version=<commit>'`) and install it under `/opt/connect-service/releases/<commit>/connect-bouncer`, selected by a `current` symlink. Create an unprivileged `connect-service` user/group. Install [`connect-bouncer.service`](connect-bouncer.service) and a root-only `/etc/connect-service/pairing.json` based on [`pairing.json.example`](pairing.json.example). Generate an independent 32-byte random unpadded-base64url provider credential; configure the same credential only at that provider. Systemd passes this configuration as a private credential file.

The bouncer listens on loopback behind a trusted HTTPS ingress. [`nginx-pairing.conf.example`](nginx-pairing.conf.example) provides request/connection limits and trusted-address handling; replace its documentation IP with the ingress's exact source address. The TLS ingress must overwrite `X-Real-IP` and preserve the configured Host. Do not enable access logs for pairing. Verify `/healthz` reports the expected revision, secure browser cookies and unauthenticated API denial before enabling a provider. The matching provider adapter must be enabled and validated independently.

Only transient pairing state lives under `/var/lib/connect-service`, mode 0700, with private files and a process lock. It is capped, periodically expired and disposable: do not back it up or restore old capability state. Preserve registry secrets separately so recovery can start with empty pairing state. A bouncer outage does not interrupt established cloud connections. No reporting collection or PostgreSQL service is needed for this binary.

## Installation reporting

1. Build `connect-server` for the server architecture and install it as `/usr/local/bin/connect-server`.
2. Create an unprivileged `connect-service` account and install `connect-server.service` under `/etc/systemd/system/`.
3. Install `server.env.example` as `/etc/connect-service/server.env`, replace the database placeholder, and restrict the file to root and the service account. Provision PostgreSQL separately on a private network. Remote database URLs must use `sslmode=verify-full` to verify the certificate and hostname.
4. Keep `CONNECT_LISTEN_ADDR` on loopback when the TLS proxy is on the same host. Do not expose the service listener directly to the Internet. Terminate HTTPS with a maintained reverse proxy and valid certificates.
5. Apply the request-rate and connection limits in [`nginx-rate-limit.conf.example`](nginx-rate-limit.conf.example), or equivalent controls at the trusted ingress. The example limits API and health traffic to five requests per minute per direct client address, allows a burst of 20 and caps concurrent requests per address. Tune for expected NAT/client populations without disabling the API rate limit. Nginx holds the address only in its rate-limit shared memory; do not configure persistent address logging. If a trusted proxy or CDN sits in front of Nginx, configure real-client-address handling from explicit trusted proxy ranges; never trust arbitrary forwarded headers.
6. Configure proxy access logs to exclude client IP addresses, request URIs, query strings, headers and bodies. The example records only timestamp, method and response status and discards this virtual host's Nginx error log to avoid persisting client addresses. Monitor service health through systemd and `/readyz`. The application itself emits no per-request access log.
7. Start the service with systemd. Startup checks PostgreSQL, applies the numbered SQL migrations and performs a retention sweep before listening. `/healthz` is liveness; `/readyz` is readiness.

This example configures no database backups. Before enabling collection, define a bounded backup/WAL expiry window and test deletion-aware restore. Application deletion removes facts from PostgreSQL but cannot erase an existing backup; restoring an older snapshot without later tombstones can restore stale report records.
