# ADR 0113: A host without a private network joins the host plane over WireGuard

2026-11-05 · Proposed

## Context

A fleet reaches its hosts on one private range (`10.42.0.0/16`, OVH's vRack, ADR 0028). The daemon's API and the HTTP ingress bind the host's private address; `ingress.allowed_clients` is that range; the fleet identifies a host's calls (heartbeat, pool key request, ADR 0026) by their source address; the public interface takes SSH and the ports named, nothing else. A server the provider cannot put in the vRack (some models have none) cannot be a host today.

This ADR gives such a server an address in the range through an encrypted tunnel, and changes nothing for a host on the vRack. The scope is the host plane: the fleet and the routers reaching a host's API (7420) and ingress (8080). A namespace spanning hosts is `MESH.md`'s, not built, and untouched here.

Kubernetes's answer to the same question (nodes with no shared network) is not a feature of the cluster: a node joins with a reachable address, and a CNI or a VPN (WireGuard in several CNIs) provides the overlay, its keys exchanged through the API server. Here the tunnel is a host primitive, like the firewall (ADR 0028); the fleet only tells the script whom to tunnel to.

## Decisions

**One interface, `briqyard0`, in the bootstrap script.** `WIREGUARD_PEERS` (comma-separated `PUBLIC_KEY|TUNNEL_ADDRESS|ENDPOINT[:PORT]`) with `PRIVATE_ADDRESS` and no `PRIVATE_INTERFACE`. The script installs `wireguard-tools`, writes `/etc/wireguard/briqyard0.conf` and enables `wg-quick@briqyard0`. The kernel module is in Ubuntu's kernel (7.0 here): no DKMS. `WIREGUARD_ONLY=1` sets the peers of a host already installed (the fleet's host, when another joins) and changes nothing else. Nothing else in the script changes: an upgrade (ADR 0027) sends neither variable and skips the whole section.

**Keys: each host makes its own, and the private half never moves.** `wg genkey` at the first run into `/etc/wireguard/briqyard0.key` (0600, root); the public key is printed and kept in `briqyard0.pub`. Public keys reach peers by the operator: the fleet's `bootstrap.wireguard.peers` lists the peers a tunnel host gets (public key, private address, public endpoint), and `WIREGUARD_ONLY=1` on the fleet's host adds the new host. The first run fails with the key in its message, which the fleet records in the host's note; the fleet tries again every two minutes and succeeds once the peer has the key. This is a manual step per host, on purpose: the alternative (the fleet writes peers onto the hosts over SSH, or hosts publish keys in their heartbeat) is the same step done by code, worth building when hosts join often (a mesh, `MESH.md`'s `/v1/hosts/mesh`, will need it). A removed host: delete its peer line and run `WIREGUARD_ONLY=1` again (the peer and its route go; the others' routes are not touched). The last peer goes the same way with `WIREGUARD_PEERS=` set and empty: no peer, no route, no firewall rule. Unset is not empty: `WIREGUARD_ONLY=1` without the variable is refused, and a full bootstrap without it keeps the installed tunnel and its rule (an upgrade or a re-run on the fleet's host must not close the tunnel), so removal is only ever this explicit run, and it is also how access is revoked in a rollback. A reinstalled host has a new key: replace the peer's key the same way; until then its calls are not answered, and a key no peer holds can never be used from the old one.

**Topology: a /32 per peer, no range.** Each tunnel host carries its address as `/32` on `briqyard0` and one `/32` route per peer; the script refuses a prefix. A tunnel host has no route to the rest of `10.42.0.0/16`, so it reaches the fleet's host and nothing else. The fleet's host (on the vRack) carries its own address a second time as `/32` on `briqyard0`, so a call to a tunnel host leaves with its vRack address as source (the one the tunnel host's `allowed_clients` and cryptokey routing expect); its `/16` vRack route is untouched, and the `/32` route to the tunnel host is more specific than it for that one address (rig: `ip route get` for a vRack neighbour still says `vrack0`). Other vRack hosts need no route: hosts do not call each other, the fleet and the edge are the only callers of a host's API and ingress, and both live on the fleet's host. A vRack host that must reach a tunnel host becomes a peer too (same primitive); nothing routes through the fleet's host (no forwarding), so a tunnel host is never a path between the vRack and the internet.

**A peer behind a NAT.** The configuration needs an `Endpoint` with a port even if the peer's real port is not known: give a placeholder (`51820`). The endpoint's address is what the firewall allows, so it is the NAT's public address; WireGuard learns the real source port from the peer's first packet and follows a rebinding. `wg syncconf` alone adds no route for a new peer; the script adds it (`wg-quick` adds routes only when it starts the interface), so run a peer change through `WIREGUARD_ONLY=1`, not `wg syncconf` by hand.

**Firewall: the port is open to the peers' public addresses only; the tunnel is trusted as the vRack is.** The script adds `ip saddr { <peers' endpoint addresses> } udp dport 51820 accept` to `briqyard_host` (the same file the edge's bootstrap already requires, ADR 0028). `iifname != public accept` then admits what arrives on `briqyard0`, as it admits the vRack. That is acceptable for this reason: only a packet that decrypts under a configured peer's key and whose source is that peer's one `/32` reaches the interface (cryptokey routing), so a peer can reach 7420/8080 as the vRack's members can, and cannot send as another host. A compromised peer is a compromised vRack member, no more. The bind rule is unchanged: the API and ingress bind `PRIVATE_ADDRESS`, a private address, and nothing on the public interface answers 7420 or 8080; `ALLOWED_CLIENTS` is still the daemon's own second line.

**Identity by source address holds across the tunnel.** The source of a call from a tunnel host is its tunnel address, `10.42.0.13`, the `url` the fleet has for it. WireGuard rejects any other source from that peer, which makes the check stronger than on the vRack (a layer-2 network where a host can claim any address). The script resolves the fleet's name to `FLEET_ADDRESS` as for a vRack host.

**Boot order: the tunnel is up before the daemon asks for the pool key.** The unit the script writes at each install carries `After=` and `Wants=wg-quick@briqyard0.service` when `/etc/wireguard/briqyard0.conf` exists, so an upgrade keeps it. Not a drop-in: the daemon refuses to start under a unit with `DropInPaths` (found in the rig). `wg-quick` runs after `network-online`; the firewall unit stays before `network-pre`. At the first install, the script waits up to 30 s for a handshake with the fleet's peer (sending a ping, a tunnel handshakes when it has data) before going on to the pool, so a missing key stops the run before a disk is touched.

**A per-host override of `private_interface`: `bootstrap.wireguard.hosts`.** `private_interface` is fleet-wide because servers of one model share interface names. A host listed in `bootstrap.wireguard.hosts` (by its private address) is sent no `PRIVATE_INTERFACE` and gets `WIREGUARD_PEERS` and `WIREGUARD_PORT`; every other host is sent exactly what it was. A mixed fleet needs no other change, and a fleet without the section is unchanged (tests).

**MTU and the failure mode.** The interface MTU is `wg-quick`'s 1420 (1500 minus 80 for IPv6 transport, the safe default for an unknown path); control traffic and an ingress proxy fit with no fragmentation (measured below). The tunnel carries only the host plane, never machine traffic (machines egress on the host's own public interface). If the tunnel is down, the host is unreachable for the fleet, exactly as a vRack host with its link down: heartbeats stop, the host goes `down` after `down_after_sec`, machines keep running (ADR 0013, 0027), the daemon cannot fetch its pool key at a restart and waits (ADR 0026); `PersistentKeepalive = 25` keeps the path open through a NAT and brings the tunnel back after either side restarts without any action.

**Seeds, backups, `host upgrade`: no change.** Backups and the registry's backup go to the object store over the public interface; the tunnel carries neither. An upgrade re-runs the script with the release only; the tunnel, its drop-in and its firewall rule stay. The sealed seeds (guest memory and disks) are made on the host and reach no other.

**Relation to `MESH.md`.** That design's `wg0` carries namespace slices (`10.64.0.0/10`) between hosts that share a namespace, with peers from the fleet. This one carries `10.42.0.0/16` `/32`s between the fleet and a host. They do not clash: different addresses, so different `AllowedIPs`; the mesh can reuse this host key and peer endpoint list and add its slices to the same interface or use a second one (`wg0`, another port), and the fleet's peer list that the mesh needs would also replace the manual step above.

## Rig measurements

A rig on one server (RISE-S, 16 cores, kernel 7.0.0-42): the public network is a pair of veth in /30s with one namespace as the fleet's host (vRack address on a dummy NIC) and one as an outsider; a throwaway `briqyard-fleet` with its own state runs in the first. The host is the server itself: its default route and firewall are real, the rig's two interfaces are added to the firewall's public set by hand.

Both ends are on one machine, so the figures are the tunnel's cost (encryption on both ends), not a network's.

| Check | Result |
|---|---|
| `host add` through the tunnel | the first run failed with the host's key in the note; with the key on the fleet's host, the next run (2 min) took the pool key over the tunnel and the host heartbeat `ready` |
| A machine and an endpoint | `nginx:alpine` ran on the host; its TCP endpoint (`10.42.0.13:30000`) and the ingress (`:8080`) answered from the fleet's namespace |
| Latency | 0.32 ms mean (50 pings), against 0.05 ms on the bare veth |
| Throughput | 10.1 Gbit/s, one `iperf3` stream, 8 s, no retransmits |
| MTU | 1420; a 1420-byte packet with DF passes, 1428 does not |
| Daemon restart | `ready` again within 25 s, machine and endpoint served; `wg-quick@briqyard0` restart: the next ping answers |
| Reboot | tunnel, firewall and daemon active; the daemon waited with `pool locked` (the rig's fleet was down, rebuilt by hand), then took its key over the tunnel; the machine came back |
| From outside | 7420, 8080 and 30000 closed from the outsider; 22 open; a UDP packet to 51820 from a non-peer hit the final drop (in the rig) |
| `WIREGUARD_ONLY=1` | adding a peer added its `/32`, its route and its endpoint to the rule; removing it took all three away; the handshake with the other peer did not restart; a range as tunnel address and a private endpoint are refused |

The rig found three faults, fixed in the script: `wg syncconf` cleared a private key set by `PostUp` (now inline in the configuration); a tunnel handshakes only when it has traffic (the wait pings); and the daemon refuses to run under a unit with a drop-in (the ordering is in the unit). ## Real-path measurements

A second test used a real internet path: the host behind a NAT at a different site, about 24 ms from the fleet's host, with the fleet's host as its only peer.

| Check | Result |
|---|---|
| Latency | about 24 ms round trip, no measurable cost of the tunnel over the bare path |
| MTU | 1420 passes, with DF set |
| Tunnel outage | the tunnel recovered on its own when the path returned |
| NAT rebinding | the peer's mapping was dropped and re-learned; the tunnel recovered |
| Daemon restart, reboot with the fleet up | both recovered unaided |

The pool key request from the bootstrap timed out (curl 28, 20 s) three times through the tunnel; the same request by hand answered in 0.13 s, and a later attempt passed. The fleet refuses a wrong source address at once (403 `unknown_host`), so the source check is not what waits. The handler waits in two places: the key admission (up to 30 s behind another key) and, for a key the backup does not hold yet, the registry backup's write before it answers. A first ask of a new host does the second, and a client that gives up cancels the handler, so the cause may be that wait, but this was not shown (the fleet's log was not read for it) and stays unknown. The script now asks up to three times, 3 s apart; that bounds the effect and does not explain it.

Rebuilding a pool on a reinstalled host: `zpool destroy` leaves the labels, and the next bootstrap stops with "holds a pool"; `wipefs -a` on the pool's partitions clears them.

Still unproved: a fleet on a vRack host with a fixed endpoint on both sides, the edge firewall rewrite (ADR 0028) on a host with a tunnel, a second tunnel host, an `https` fleet URL through the tunnel, and UDP to the port from a source that is not allowed (the rig showed the drop; the real path did not test it).

The rig's firewall differs from a host's in one line: its two veths count as public interfaces (`iifname != { "enp6s0", "vhub", "vout" } accept`), by hand.

## Consequences

- A tunnel host costs one manual step per join and per reinstall (the key). The fleet's note tells the operator the key; automation is the mesh's `/v1/hosts/mesh`.
- The fleet's host is a peer of every tunnel host: its `briqyard0` carries all their host-plane traffic (ingress proxying and API calls), so its public bandwidth is shared with them; at one tunnel host that is small, at many it is the signal to put the tunnel hosts on a vRack or to run the mesh.
- The WireGuard UDP port is public on every host that has peers; with the source restriction a scan sees nothing, but it is one more rule to keep right: tests cover the rule's generation and the script's refusals.
- Reopen when hosts join without an operator (a scaler), or when a tunnel host must reach another tunnel host.
