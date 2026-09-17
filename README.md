# WireServe

Minimal, self-hosted WireGuard mesh with a declared-service directory. See
`wireserve-design-spec.md` for the full design and `PLAN.md` for current
implementation status.

## Workspace layout

- `crates/wireserve-types` — shared wire structs, validation, token hashing.
- `crates/wireserve-coordinator` — axum + SQLite coordinator binary.
- `crates/wireserve-agent` — WireGuard/firewall/hosts-file daemon + CLI.
- `crates/wireserve-admin` — separate admin CLI (distinct trust surface).
- `deploy/` — systemd units, Dockerfiles, Quadlet files.

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
port-forward can still reach nodes that do have one, because
`PersistentKeepalive` keeps its side of the mapping alive; two such nodes
cannot reach each other at all. There is no relay or NAT-traversal
assistance in v1, which the spec lists as deliberately deferred.

The agent needs `CAP_NET_ADMIN` and `/dev/net/tun`, and in a container it
needs host networking, or the mesh exists only inside that container.

### Two conflicts worth checking before the first start

**The interface name.** The agent defaults to `wg0`, which is also what
`wg-quick` uses. It will not take over an interface it did not create — it
refuses to start instead — so an existing tunnel is safe, but you will need
`--ifname wg1` (or another free name) on a host that already has one.

**The mesh address range.** The default is `100.90.0.0/24`, which sits
inside `100.64.0.0/10`, the carrier-grade-NAT block that Tailscale
allocates all of its addresses from and that some ISPs use on WAN links. If
any node also runs such an overlay, that overlay routes the whole `/10` to
its own interface and mesh traffic can leave the wrong way. Set
`WIRESERVE_NET_V4_CIDR` to something you control, for example
`10.90.0.0/24`, before the first node registers; the coordinator logs a
warning at startup when the configured range overlaps. Addresses are
allocated once and kept, so changing this later affects only nodes that
have not registered yet.
