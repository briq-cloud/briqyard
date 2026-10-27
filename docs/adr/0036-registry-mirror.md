# ADR 0036: A pull-through registry mirror per region (Zot), tried first; tags resolved by the registry, content checked by digest

Date: 2026-10-27 · Status: accepted; amends ADR 0009 (a tag is resolved with a `HEAD`) and ADR 0019 (`image_pulled` says `from`)

## Context

A host builds a root disk once per image digest and remembers a tag's digest for 10 minutes (ADR 0009), but every new image or new digest still goes to its registry, from every host. Docker Hub limits anonymous pulls per address; the stress spike hit it (`../research/2026-10-19-stress-spike.md`), and a fleet behind a few addresses hits it sooner. A pull-through mirror in the region pulls each image from Docker Hub once for every host, and serves the rest from the vRack.

Kubernetes leaves this to the container runtime: containerd's `hosts.toml` lists mirrors per registry, tried in order, then the registry. A mirror is trusted for tags there; pinned digests are safe because the content is checked.

`oci-client` 0.14 (our client) has a mirror on a reference (`set_mirror_registry`), but it is `#[doc(hidden)]`, exempt from semver, and adds containerd's `?ns=` parameter. It already checks every manifest and blob it pulls by digest against the digest asked for (`validate_digest`, the layer `Digester`), so a mirror is a second registry name for the same digest: `Reference::with_digest(<mirror host>, <repository>, <digest>)`, public API.

## Decisions

**`registry_mirrors` in the daemon's config, one mirror per registry**: `{docker.io: http://10.0.0.5:7440}`, the registry as references name it. A mirror is a registry at the root of its address (no path); `http://` is allowed for a mirror only (below).

**A tag is resolved by the registry, never by a mirror, with a `HEAD`.** `fetch_manifest_digest` reads `Docker-Content-Digest` (a GET only if the registry sends none). Docker Hub does not count a `HEAD` as a pull, so tags cost nothing against its limit; ADR 0009 resolved with a GET of the manifest, which counted. The digest is the one the registry names: an index's for a multi-platform image (it was the platform manifest's), so a tagged multi-platform image is built once more on each host after this change. When the registry cannot answer, ADR 0009 holds: the image already built for the last resolution serves, else the create fails. A mirror's answer for a tag is never asked: it would let the mirror choose the image.

**The content by that digest: the mirror first, then the registry.** The manifest (and, for an index, the platform's manifest), the config and each layer are pulled by digest, and checked by `oci-client` against it. A source that fails (no connection within 10 s, a connection silent for 15 minutes, an error, bytes that are not the digest) is dropped for the rest of the pull with a warning (`mirror failed; pulling from the registry`), and the registry serves what is left. A mirror cannot serve another image for a digest: it can only fail. That is why plain HTTP is enough on the vRack.

**The daemon sends a mirror no credentials.** `registries[]` credentials go to their registry only. The mirror holds what it serves: public images only for now; a private registry is pulled directly.

**`image_pulled` says `from`**: the mirror's host when it served every byte, `registry` otherwise; the message says `through <host>`.

**Zot (Apache-2.0, one Go binary, OCI-native) is the mirror we run**, with `sync.onDemand` from `https://index.docker.io`: a request for a digest it lacks is fetched from upstream and kept. Measured in the dev VM: Zot keeps an index by its exact bytes, and fetches a platform's manifest and layers only when that manifest is asked for, so one architecture's hosts store one architecture. `hack/install-mirror.sh` installs the pinned release (`v2.1.22`, by digest), `hack/mirror/zot.json` with the host's address, and a systemd unit `briqyard-mirror` as a user of its own; it refuses a public address, since the mirror has no authentication. One per region, on the first host, bound to its vRack address (port 7440), behind the host firewall; the region's daemons name it. Retention: what nobody pulled for 30 days goes.

Rejected, one line each:
- Docker's `registry:2` (distribution) in proxy mode: one upstream per instance, and its cache expires by a fixed TTL, not by the last pull.
- Harbor: a database, Redis and several services, for a cache.
- Trusting the mirror for tags when the registry is down: availability bought with the mirror choosing images.
- A mirror's address with a path (`https://m/docker.io`): `oci-client` names a registry by host, and Zot serves one namespace per instance.
- Several mirrors per registry: no second mirror to name; the field is a map, a list later is additive.
- `set_mirror_registry`: hidden and unstable, and `?ns=` is not the OCI spec.

## Consequences

- Measured in the dev VM, `node:22-alpine` through the daemon (`image_pulled`'s seconds, the build included): from Docker Hub 11.7 s, through a cold mirror 15.4 s (Zot fetches, then serves), through a warm one 12.4 s. Under nested virtualization the build dominates; the mirror is for the registry's limits and outages, not for speed here. A real host's link to Docker Hub and the vRack decide the rest.
- The mirror is one process per region: down, every pull goes to the registry as before, at the cost of a 10 s connect timeout only when its address does not refuse. A mirror that takes the connection and never answers holds a pull for the read timeout, 15 minutes per read, above Zot's `syncTimeout` (10 minutes, its first copy of an image); every create of that image waits on that one pull. A host that never reaches it pays nothing more.
- A pinned digest that Docker Hub deleted still pulls from the mirror while Zot keeps it.
- e2e (`hack/e2e.sh`): a pull through the mirror (`through 127.0.0.1:7440`, the mirror holding the digest); with the mirror stopped, the same image from the registry, the same digest, the fallback logged. The VM's mirror is fc's, reached by fc2 at `host.lima.internal:7440` (`DEVELOPMENT.md`).
- Not built: Docker Hub credentials in Zot (higher limits), mirrors of other registries (a Zot per registry, or `content` prefixes once a reference can carry a path), a mirror's own metrics in the host's.
