# Generic deployment example

This is a service-host example only. It contains no production address, database credentials or TLS material. Pairing/provider deployment is not implemented.

1. Build `connect-server` for the server architecture and install it as `/usr/local/bin/connect-server`.
2. Create an unprivileged `connect-service` account and install `connect-server.service` under `/etc/systemd/system/`.
3. Install `server.env.example` as `/etc/connect-service/server.env`, replace the database placeholder, and restrict the file to root and the service account. Provision PostgreSQL separately on a private network. Remote database URLs must use `sslmode=verify-full` to verify the certificate and hostname.
4. Keep `CONNECT_LISTEN_ADDR` on loopback when the TLS proxy is on the same host. Do not expose the service listener directly to the Internet. Terminate HTTPS with a maintained reverse proxy and valid certificates.
5. Configure proxy access logs to exclude client IP addresses, request URIs, query strings, headers and bodies. A minimal access log can include only timestamp, method and response status. The application itself emits no per-request access log.
6. Start the service with systemd. Startup checks PostgreSQL, applies the numbered SQL migrations and performs a retention sweep before listening. `/healthz` is liveness; `/readyz` is readiness.

This example configures no database backups. Before enabling collection, define a bounded backup/WAL expiry window and test deletion-aware restore. Application deletion removes facts from PostgreSQL but cannot erase an existing backup; restoring an older snapshot without later tombstones can restore stale report records.
