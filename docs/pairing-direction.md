# Pairing direction: configuration first, packages later

## Decision

Start with configuration of an installed cloud client. Keep the pairing and claim-exchange envelope independent of providers, client configuration formats and filesystem layout. A future signed client-package delivery mechanism may extend the same flow, but is not required for configuration-only pairing.

The local demonstration in [pairing-poc.md](pairing-poc.md) proves the three-component handoff with the synthetic `sunshine-poc/v1` profile. Real client provisioning and profile negotiation are not implemented by that demonstration.

## Smallest initial implementation

1. Explicitly authorized scooter registration obtains and privately persists the bouncer polling credential. Registration alone does not select a provider or enable cloud access.
2. The scooter advertises the versioned connection profiles supported by its installed clients. The first real integration is Sunshine through an already installed radio-gaga client.
3. Connect offers compatible providers. Provider/account confirmation takes place on the web, with no required second local confirmation.
4. The provider submits a short-lived claim token to connect, bound to the pairing session and selected profile. The scooter retrieves it using its separate polling credential.
5. The scooter exchanges the claim directly with the registered provider endpoint for the selected profile's connection material. Permanent connection credentials stay out of the bouncer.
6. The installed client validates and applies its own connection material. Retryable exchange and application preserve the same credential and transaction. Existing unmanaged configuration is not silently replaced.

Use ordinary verified HTTPS and independent scoped credentials for public communication. Provider endpoints come from trusted registry configuration. Device-key binding can strengthen claim redemption without requiring a scooter certificate authority. The loopback-only demonstration is not the public transport/security configuration.

## Compatibility boundary

A provider ID identifies an account service. A connection profile identifies a versioned application protocol and its provisioning schema. They are separate: multiple providers may support the same profile, and one provider may support several profiles.

Identifiers such as `radio-gaga/1` and `uplink/1` illustrate the negotiation. Their exact wire names and schemas must be defined consistently when the corresponding real adapter is implemented; the demonstration's `sunshine-poc/v1` remains a separate profile.

Keep only the necessary extension points in the initial exchange:

- A protocol version, pairing/session binding, provider ID and selected profile ID.
- An advertised list of supported profiles, with selection restricted to that list.
- A profile-specific connection payload in the direct provider exchange. Its interpretation belongs to the installed client.

The bouncer does not generate client YAML, select local paths or interpret connection credentials. Local client integration owns configuration layout, service lifecycle and safe transactional application. Provider data cannot choose shell commands, executables, local Redis targets or arbitrary file paths.

Adding a provider that implements an existing enrollment and connection profile should require registry configuration, not new scooter code. Login, onboarding and internal cloud APIs remain provider responsibilities. A genuinely new on-scooter protocol needs a compatible client or a server-side bridge.

Do not build a general plugin framework, package installer or universal configuration generator for the first integration. A narrow adapter for the installed client is sufficient. Unknown profiles fail clearly; they never trigger executable downloads implicitly.

## Future extension: signed client packages

A scooter may eventually advertise a separately versioned package-installation capability. When no installed connection profile matches, the provider could offer a compatible client package, followed by its connection configuration. Scooters without that capability continue to accept configuration-only flows and reject package offers. A new client can then be added without a firmware upgrade, within the installed package runtime and architecture support.

Package installation is a separate software-trust decision:

- A signed manifest binds publisher, version, architecture/runtime requirements, package digest, connection profiles and requested permissions.
- Trusted signing keys are established by scooter policy, independently of the provider's response. HTTPS or a provider-supplied certificate alone does not authorize running its executable.
- Packages have a fixed layout with no arbitrary root installation scripts. A locally controlled launcher installs versioned releases under `/data` and defines the allowed execution environment.
- Clients run with explicitly granted privileges and vehicle access. Activation includes integrity checks, a health check and rollback; updates enforce the same signing policy.
- Web confirmation explicitly discloses installation, publisher and permissions. A trusted-package policy can preserve web-only completion without making ordinary pairing permission to execute arbitrary code.

Keep this as a future capability. Do not advertise it, accept packages or specify a package archive format in the configuration-only implementation.
