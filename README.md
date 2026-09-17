# WireServe

A small, self-hosted WireGuard mesh with a service directory. You run one
coordinator. Every machine that joins gets a stable mesh address, an
automatically maintained set of WireGuard peers, a default-deny firewall on
the tunnel, and a `<service>.wg` hostname for anything it chooses to
publish. Phones and laptops that only want to *reach* things join as
ordinary WireGuard clients with a generated `.conf`, no agent required.

It deliberately does not become your DNS server, does not relay traffic,
and has no web UI. See `wireserve-design-spec.md` for the full design and
the reasoning, and `PLAN.md` for implementation status.

## How it fits together

```
  admin CLI ──▶ coordinator ◀── agents poll every ~20s over HTTPS
                (axum + SQLite)     │
                                    ├─ configure WireGuard peers
                                    ├─ open only declared ports on wg0
                                    └─ write <service>.wg into /etc/hosts
```

The coordinator holds no private keys and is never itself a WireGuard peer.
Each node generates its own keypair locally and sends only the public half.
Nodes talk to each other directly; the coordinator only tells them who
exists.

## Getting started

### 1. Run the coordinator

Somewhere reachable by every node, behind a reverse proxy that terminates
TLS. Copy `deploy/env/coordinator.env.example` to
`/etc/wireserve/coordinator.env`, set `WIRESERVE_ADMIN_TOKEN` to a fresh
secret, and check the two mesh ranges before anything registers.

```sh
openssl rand -hex 32                      # the admin token
podman build -f deploy/docker/coordinator.Dockerfile -t wireserve-coordinator .
podman run -d --name wireserve-coordinator \
    --env-file /etc/wireserve/coordinator.env \
    -p 127.0.0.1:8080:8080 \
    -v wireserve-coordinator-data:/var/lib/wireserve \
    wireserve-coordinator
```

Point your proxy at `127.0.0.1:8080`. There is a systemd unit and a Quadlet
unit in `deploy/` if you would rather not use a container.

The admin port never leaves the host by design, so admin commands run
inside it:

```sh
podman exec wireserve-coordinator wireserve-admin list-peers
```

### 2. Add a node

Creating a node prints a one-time join token. Hand it to the machine out of
band. **The token is redeemable for 30 minutes** — long enough to walk over
to the machine, short enough that a token left in a chat log or a password
manager is not a live way into the mesh months later. If the window lapses,
`wireserve-admin rejoin <name>` mints a fresh one for the same node, name
and address. Override with `--ttl <secs>` per token, or coordinator-wide
with `WIRESERVE_JOIN_TOKEN_TTL_SECS`; `0` disables expiry.

```sh
# on the coordinator
podman exec wireserve-coordinator wireserve-admin create-node homeserver

# on the node itself
wireserve-agent join https://wireserve.example.com --join-token-file ./token
systemctl enable --now wireserve-agent
```

`join` generates the keypair locally, redeems the token, and stores
everything mode-600. Pass `--ifname wg1` if the machine already has a
`wg0`. Prefer `--join-token-file` or `-` over typing the token as an
argument, where it lands in shell history and is visible via `ps`.

### 3. Publish a service

On the node hosting it.

**By default a declaration needs an admin to approve it** before any other
node sees it. Service names are globally unique and first-come-first-served,
so without that gate any node holding a valid bearer token could claim an
unclaimed name — or re-claim one freed a moment earlier when its owner was
revoked — and every other node's `/etc/hosts` would point `<name>.wg` at it.
One compromised node is enough. Set
`WIRESERVE_REQUIRE_SERVICE_APPROVAL=false` on the coordinator for a
single-operator mesh where every node is already trusted and the round trip
is pure ceremony.

So the flow is two steps:

```sh
# on the node
wireserve-agent serve plex 32400 tcp

# on the coordinator — see what is waiting, then approve it
wireserve-admin list-services --pending
wireserve-admin approve-service homeserver plex
```

Until it is approved, `wireserve-agent list` shows the service with
`"pending": true`, which is how you tell "waiting on an admin" from "this
node has not polled yet". The node's own firewall hole opens immediately
either way — it is only firewalling itself, and nothing resolves
`<name>.wg` for it yet.

`wireserve-admin deny-service <node> <service> --reason '...'` refuses one,
and the declaring node withdraws it and closes the hole on its next poll.
Denying an already-approved service pulls it back out of the directory,
which is the way to re-review a name on a mesh where approval was switched
on after the fact — enabling it grandfathers everything already declared,
rather than blanking every hosts file at upgrade time.

**Deny is for mistakes; `revoke` is for compromise.** A denied service still
holds its globally-unique name until the declaring node withdraws it, and a
node you do not trust will not withdraw anything. `revoke` deletes all of
its declarations and kills its token.

Once approved, the declaration takes effect on the next poll:
the port opens on the tunnel and the name appears in every other node's
hosts file.

```sh
wireserve-agent serve plex 32400 tcp
wireserve-agent list                    # what this node sees right now
wireserve-agent unserve plex
```

Any other node can then reach `plex.wg:32400`. Names are unique across the
whole mesh, first come first served. Note that the hostname carries the
address only, not the port, which is what `list` is for.

### 4. Add a phone or laptop

A device that only consumes services does not run the agent. This creates
the node and prints a ready-to-import WireGuard config:

```sh
podman exec wireserve-coordinator wireserve-admin export-config myphone \
    --out myphone.conf
```

Import it into the official WireGuard app, by file or by feeding the
contents to any QR-code generator. The file contains a private key, so it
is written mode 600; move it, do not copy it. Such a peer gets a mesh
address and reaches every service by IP and port, but has no `.wg` name
resolution, and it is a snapshot: re-export and reimport after new nodes
join.

### 5. When a machine is lost or compromised

```sh
podman exec wireserve-coordinator wireserve-admin revoke homeserver
```

The node's token stops working immediately, and every other node drops it
as a peer on its own next poll, so removal across the mesh is bounded by
the poll interval rather than instant. `rejoin` issues a fresh join token
for the same name and address when the machine itself is still trusted;
`delete-node` frees the name entirely, and refuses until the node is
revoked.

## Command reference

On a node, talking to the local daemon over a Unix socket:

| Command | What it does |
| --- | --- |
| `wireserve-agent join <url>` | one-time bootstrap, generates the keypair |
| `wireserve-agent serve <name> <port> [tcp\|udp]` | publish a service |
| `wireserve-agent unserve <name>` | withdraw one |
| `wireserve-agent list` | peers, services and rejected declarations |
| `wireserve-agent leave` | tear down interface, firewall, hosts block |

On the coordinator host, against the loopback-only admin port:

| Command | What it does |
| --- | --- |
| `wireserve-admin create-node <name>` | create a node, print a join token |
| `wireserve-admin export-config <name>` | create a static peer, print a `.conf` |
| `wireserve-admin list-peers` | the full directory |
| `wireserve-admin revoke <name>` | cut a node off, keep its name reserved |
| `wireserve-admin rejoin <name>` | fresh join token, same name and address |
| `wireserve-admin delete-node <name>` | remove the record, free the name |
| `wireserve-admin clear-endpoint <name>` | drop a stale advertised endpoint |
| `wireserve-admin list-services [--pending]` | declared services and their approval state |
| `wireserve-admin approve-service <node> <svc>` | let a declaration reach the mesh |
| `wireserve-admin deny-service <node> <svc>` | refuse one, or withdraw an approval |

## Workspace layout

- `crates/wireserve-types` — shared wire structs, validation, token hashing.
- `crates/wireserve-coordinator` — axum + SQLite coordinator binary.
- `crates/wireserve-agent` — WireGuard/firewall/hosts-file daemon + CLI.
- `crates/wireserve-admin` — separate admin CLI (distinct trust surface).
- `deploy/` — systemd units, Dockerfiles, Quadlet files, env examples.

## Build prerequisites

`wireserve-agent` depends on the `rustables` crate, which generates nftables
netlink bindings at build time via `bindgen`. Building it requires:

- `clang`/`libclang` (e.g. `apt install clang libclang-dev` on Debian/Ubuntu)
- Linux kernel headers providing `linux/netfilter/nf_tables.h` (present by
  default on most distros; `linux-libc-dev` on Debian/Ubuntu if missing)

No `libnftnl`/`libmnl` runtime linking is required — `rustables` talks to
netlink directly.

```sh
cargo build --workspace
```

`wireserve-coordinator` and `wireserve-admin` have no special system
dependencies beyond a C toolchain (for `rusqlite`'s bundled SQLite).

## What each machine needs open and configured

### Coordinator host

| Port | Direction | Who connects | Notes |
| --- | --- | --- | --- |
| 443/tcp | inbound | every agent | your reverse proxy, terminating TLS |
| 8080/tcp | none | the proxy only | plain HTTP, must not be reachable from an untrusted network (§7) |
| 8081/tcp | none | nobody | admin listener, loopback only; the coordinator refuses to start if it is not (§4.0) |

The coordinator is not a WireGuard peer and needs no UDP port, no
`NET_ADMIN`, and no access to `/dev/net/tun`. Admin commands run inside the
host or container (`podman exec <container> wireserve-admin ...`), because
the admin port is deliberately unreachable from anywhere else.

### Agent nodes

| Port | Direction | Who connects | Notes |
| --- | --- | --- | --- |
| 51820/udp | inbound | other agent nodes | the WireGuard listen port, on the node's real interface |
| 443/tcp | outbound | the coordinator | the poll loop |

Inbound UDP 51820 has to reach the node for other peers to open a tunnel to
it, which usually means a port-forward on the router plus an
`--endpoint-addr` the other nodes can resolve. A node behind NAT with no
port-forward can still reach nodes that do have one, and they can reach
back into it, because `PersistentKeepalive` holds its side of the mapping
open. Two nodes that both lack a forward cannot reach each other at all.
There is no relay, STUN or NAT traversal in v1, which the spec lists as
deliberately deferred. `deploy/e2e/run-nat-test.sh` builds this topology
and checks all of it.

**Two machines behind the same router is the case to watch.** They learn
each other's address as their shared router's external one, so reaching it
from inside means sending a packet out to your own NAT and expecting it
back, which is NAT hairpinning. Many routers do not do it, and where it
fails those two nodes cannot reach each other even though both reach
everything else on the mesh normally. Giving at least one of them a
port-forward avoids it.

A related wrinkle if you skip `--endpoint-addr`: the coordinator falls back
to the source address it observed plus the port the node reported for
itself, and behind NAT the port a router maps for WireGuard's UDP is not
that one. The recorded endpoint is then wrong, and two nodes behind one
router get recorded identically. It self-corrects, because WireGuard
replaces a peer's endpoint with the real source of the first packet it
receives, so any node that speaks within the 25-second keepalive is found.
Set `--endpoint-addr` on nodes that have a stable reachable address rather
than relying on the guess.

The agent needs `CAP_NET_ADMIN` and `/dev/net/tun`, and in a container it
needs host networking, or the mesh exists only inside that container.

### Two conflicts worth checking before the first start

**The interface name.** The agent defaults to `wg0`, which is also what
`wg-quick` uses. It will not take over an interface it did not create — it
refuses to start instead — so an existing tunnel is safe, but you will need
`--ifname wg1` (or another free name) on a host that already has one.

**The mesh address ranges.** Both of the binary's compiled-in defaults are
poor choices, for unrelated reasons, and `deploy/env/coordinator.env.example`
sets better ones. Fix these before the first node registers: addresses are
allocated once and kept for the life of the node record, so a later change
leaves the mesh addressed out of two ranges.

The IPv4 default `100.90.0.0/24` sits inside `100.64.0.0/10`, the
carrier-grade-NAT block Tailscale allocates all of its addresses from and
some ISPs use on WAN links. A host running such an overlay routes that
whole `/10` to the overlay's interface, covering these mesh addresses too.

The IPv6 default `fd00:90::/64` is not a Tailscale problem at all, since
Tailscale uses `fd7a:115c:a1e0::/48`. It is an RFC 4193 problem: a unique
local address is `fd` followed by 40 **pseudo-randomly generated** bits,
and that randomness is the entire mechanism that lets two networks built
by strangers be merged without renumbering. `fd00:90::` throws it away,
and round-numbered `fd00::` prefixes are the most commonly hand-picked
there are, so it collides with exactly the neighbours it should coexist
with. Generate your own:

```sh
python3 -c "import secrets; h=secrets.token_bytes(5).hex(); print(f'fd{h[0:2]}:{h[2:6]}:{h[6:10]}::/64')"
```

The coordinator warns at startup about either default.

## Building the container images

Both Dockerfiles use build cache mounts for the cargo registry and the
target directory, shared between the two images. The first build is a cold
compile of the whole dependency graph, including bindgen against the
kernel netfilter headers for the agent; every build after that is
incremental, even though `COPY . .` invalidates its layer on any source
change.

Builds run inside the container rather than on the host on purpose, and
this is not just about having a toolchain available. The runtime images
are `debian:bookworm-slim` (glibc 2.36), and a binary compiled against a
newer host glibc will not start in them at all. Building in the same
Debian release the binary will run on is what keeps that honest.

```sh
podman build -f deploy/docker/coordinator.Dockerfile -t wireserve-coordinator .
podman build -f deploy/docker/agent.Dockerfile -t wireserve-agent .
podman builder prune --all   # if a build ever looks like it reused something stale
```
