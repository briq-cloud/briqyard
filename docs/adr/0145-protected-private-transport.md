# ADR 0145: Private pinned transport for the protected authority

Date: 2026-11-23 · Status: implemented boundary; no production identity or startup caller yet

## Decision

The protected authority's peers (`execution_service::protected::Peers`) and the host and
authority route surface use one fixed-origin private transport,
`execution_service/protected/transport`. It implements interface v3.1 "HTTP/IPC interface"
and v3.3 "Private identities" (v3.4 changes nothing here). It forwards nothing generically:
each route is one typed request and one typed reply.

| Route (POST) | Served by | Callers (actor) | Reply |
| --- | --- | --- | --- |
| `/internal/execution/v2/transition/read` | H | A, R, B | 200 `HRead` |
| `/internal/execution/v2/transition/clock` | H | A, R, B | 200 `HostClock` |
| `/internal/execution/v2/transition/register` | H | A | 204 |
| `/internal/authority/v2/transition/read` | A | H, R, B | 200 `ARead` |
| `/internal/authority/v2/transition/adopt` | A | B | 204 |
| `/internal/authority/v2/transition/register` | A | installer | 204 |
| `/internal/authority/v2/transition/record-ack` | A | installer | 204 |
| `/internal/sealed/v2/read` | B (client only here) | H, A, R | 200 `ApiView` |

Reading the actor columns is a decision, not a quote: v3.1 names signers for reads and
"adopted authority, never the receiver" for host registration, but only describes the
authority crossings by credential (`tr`, `ni`). The table is the single place that maps them
to enrolled actors; it is the narrowest reading and one line per route to change.

- **Inputs binding (v3.6).** Rows are the §closure.peers§ of the independently verified
  §native.inputs/v1§ manifest. §Inventory::new§ takes that manifest's X and its §actors§
  key set and requires the rows to equal it one to one; §Scope::new§ refuses a Plan of
  another X. The transport opens no path the manifest names (config, TLS, journal, listener
  or fragment): identities arrive as bytes from the sealed descriptors, listeners as bound
  sockets, and there is no caller path, environment or current-global token fallback.
- **Identity.** Each peer row pins a leaf and an SPKI digest for a server and a client
  identity. A leaf is accepted only if its bytes match the pin, then only inside a closed
  X.509 profile: version 3, self-issued (the self-signature is verified, never trusted),
  P-256, one non-wildcard SAN, exactly one EKU (serverAuth or clientAuth), no CA, qualified
  validity of the whole clock interval. The client leaf's SAN form is not named by v3.3; one
  exact non-wildcard DNS or IP name is required. Possession is the handshake signature.
- **TLS.** 1.3 only, one signature scheme, no chain, OCSP, resumption, early data, ambient
  roots or system time. Server and client configs are built in memory from inputs the
  caller already validated; nothing reads a file, URL or environment variable. A listener
  admits only the client leaves of the actors its routes list.
- **Origins.** `https://host:port` exactly; H is 7541, A is 7542, no other actor uses them;
  7441, 7442, 3003, 80 and 443 are refused. A DNS endpoint is resolved once and its first
  address used; the pin, not DNS, authenticates it.
- **HTTP.** One request per connection, no keep-alive. Checks before any handler: POST,
  origin-form path, exact `Host`, `Content-Type`, one `Content-Length`, no chunked,
  compressed, upgrade, expect, trailer, proxy or forwarding headers, a route and caller ACL
  before the body is read, then the body bound (64 KiB; 1 MiB for the packet and register
  wrapper only). A reply is complete typed JSON with a matching length, or a bare 204; a
  redirect, retry, other status or truncated reply is unavailable. Only 400/401/403/409/507
  count as a definite refusal.
- **Binding.** The signed query must carry the signer key of the caller's actor, this
  operation's X and Plan digest, and its own tag; a packet must carry the API and receiver
  keys. The service still verifies every signature and owns every state decision.
- **Detached effects.** A handler runs in its own task: a caller that disconnects after
  the request reached a service cannot cancel a mutation half way.
- **One send.** `AuthorityPeers::register_once` sends the unchanged `RegisterRequest` once
  per value and requires 204; the service's durable marker remains the real gate.

Tests generate throw-away P-256 identities in memory and are explicitly non-authorizing.
Test-only endpoints use ephemeral loopback ports; production parsing refuses them.

## Not done here

The sealed-descriptor reader and root-installed peer rows, the real qualified clock source,
the listener descriptor adoption, an H-side `HostService` and the `…/transition/observe`
route remain with their owners. The transport has no readiness, journal or issuer effect.
Dependencies added to `briqyard-fleet` (all already in the lockfile): `rustls`,
`tokio-rustls` (ring), `http`, `http-body-util`, `bytes`, `zeroize`, `ring` (now a normal
dependency).
