# ADR 0020: The daemon's API serves TLS with a certificate of its own, pinned by the fleet

Date: 2026-10-20 · Status: accepted

## Context

A create request carries a tenant's environment secrets to the daemon. The fleet forwarded it to `http://<ip>:7420` with the host's bearer, in clear across the internet between providers. Kubernetes nodes serve TLS with a certificate the control plane trusts (`KUBERNETES-MAP.md`, TLS to the nodes). This covers the control path only: the HTTP ingress and TCP endpoints carry customers' traffic from the edge and need a private network (`LEAVING-FLY.md` item 1).

## Decisions

**The daemon serves its API over TLS with a self-signed certificate it makes once.** ECDSA P-256 (`rcgen`), valid 100 years, the configured addresses as SANs (`listen`, `fleet.advertise`, `ingress.advertise`), in `<data_dir>/api-cert.pem` and `api-key.pem` (`0600`), kept across restarts and upgrades. Made by whichever runs first: the daemon's start or `briqyardd tls-fingerprint`. A certificate that exists without its key is an error, never a new pair. Self-signed, not a CA: the fleet is the client that matters and it pins; a CA means issuance, rotation and distribution for nothing the pin does not already give, and ACME needs a public name per host. A long validity: the pin is the trust, an expiry would only be an outage.

**`api_tls: true` by default; plain HTTP only on a loopback `listen` or with `api_tls: false`.** Loopback stays plain: nothing leaves the host (the CLI on the host, Lima's port forwards). There is no other way to a plain non-loopback listen, so nothing to refuse beyond that; what is refused is a `fleet.advertise` whose scheme is not the API's (`https://` for TLS), since the fleet would dial the wrong one. `/metrics` and `/healthz` follow the listener. The ingress and TCP endpoints are untouched.

**The fingerprint is the trust: the SHA-256 of the certificate's DER, pinned per host.** The daemon reports it in `/v1/status` and in its heartbeat. The fleet's host record carries `tls_fingerprint`; its client to the host accepts exactly the certificate with that SHA-256 (a `rustls` `ServerCertVerifier`: no CA, no host name, no expiry) and still checks the handshake's signature with that certificate's key, so the certificate alone, which is public, proves nothing. One client per pinned certificate, `https_only`. The verifier lives in `briqyard-api` (feature `tls`): the fleet and the CLI use the same code.

**The pin comes from the bootstrap, over the SSH connection already pinned, or from the operator.** An ordered host's URL is `https://<ip>:7420` from delivery. Once the script succeeds and the SSH host key is pinned (ADR 0013), a second, strict connection runs `briqyardd tls-fingerprint`; the fleet records the fingerprint in the same write that marks the host `bootstrapped`. An ordered host that answers no fingerprint (plain HTTP) fails its bootstrap. A static host has `tls_fingerprint` in its `hosts:` entry, with an `https://` URL exactly when it has one (refused at load otherwise).

**A heartbeat must report the pinned fingerprint.** A different one is refused (403 `tls_mismatch`) and logged at `warn`: another machine at that address, or a host whose certificate was remade. A heartbeat on TLS for a record with no pin is refused too: no trust on first use outside the bootstrap. A plain heartbeat for a record with no pin (a loopback host the operator forwarded) is taken. The fingerprint in a heartbeat is self-reported: it catches a replaced host early; the handshake of every forwarded call is the proof.

**The fleet's own listener: the operator's certificate, or plain on loopback.** `tls: { cert, key }` (PEM files, Let's Encrypt in production). Without it the fleet serves plain HTTP, and refuses a non-loopback `listen` unless `tls: off` says something else in front terminates TLS (ADR 0012's shape). A daemon's heartbeat to an `https` fleet verifies it against the web PKI roots (`webpki-roots`, what `reqwest`'s `rustls-tls` carries).

**`rustls` with `ring`**, the provider `reqwest` already uses: no `aws-lc` C build. New dependencies: `rcgen` 0.13 (0.14 needs Rust 1.88, the workspace says 1.85), `rustls` 0.23 (already in the tree through `reqwest`), `axum-server` 0.7 with `tls-rustls-no-provider` (axum 0.7's `serve` takes plain TCP only).

## Consequences

- A host whose certificate files are removed, or a reinstalled server, has a new fingerprint: its heartbeats are refused until it is pinned again (bootstrap again, or edit `hosts:`). There is no rotation tool.
- The CLI talks to a daemon over TLS with `--tls-fingerprint`; to a fleet, over the web PKI.
- The SANs are what the configuration names; a host bound to `0.0.0.0` with no advertise has none. Nothing checks them.
- A host configured before this ADR with a non-loopback `listen` and an `http://` `fleet.advertise` refuses to start: write `https://` and pin its fingerprint, or set `api_tls: false`.
- The development VM's daemon listens on `0.0.0.0` for Lima's forwards and sets `api_tls: false`; its fleet sets `tls: off`. The suites stay on plain HTTP; the TLS path is covered by unit tests over loopback.
- The daemon logs on stderr, as `OPERATIONS.md` always said: stdout is `tls-fingerprint`'s answer.
- Reopen for mutual TLS (the daemon checking the fleet beyond the bearer) or when a CA arrives with the mesh (`../MESH.md`).
