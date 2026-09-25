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
                                    ├─ open only declared ports on wireserve0
                                    └─ write <service>.wg into /etc/hosts
                                       (each service has its own address)
```

The coordinator holds no private keys and is never itself a WireGuard peer.
Each node generates its own keypair locally and sends only the public half.
Nodes talk to each other directly; the coordinator only tells them who
exists.

## Getting started

### 1. Run the coordinator

Somewhere reachable by every node, behind a reverse proxy that terminates
TLS. You don't need to invent a secret or pick a mesh IP range up front —
the coordinator generates and persists both for you on first start if you
leave them unset.

**Bare metal**, using the shipped systemd unit:

```sh
cargo build --release --workspace
sudo useradd --system --no-create-home --shell /usr/sbin/nologin wireserve
sudo install -m 0755 target/release/wireserve-coordinator target/release/wireserve-admin /usr/local/bin/
sudo cp deploy/systemd/wireserve-coordinator.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now wireserve-coordinator
```

No `/etc/wireserve/coordinator.env` is required for this — the unit's
`StateDirectory=` gives the coordinator `/var/lib/wireserve-coordinator` to work with,
and it generates its own admin token and mesh ranges there on first start.
Get the admin token it generated:

```sh
sudo grep WIRESERVE_ADMIN_TOKEN /var/lib/wireserve-coordinator/coordinator-secrets.env
```

and save it once so `wireserve-admin` never needs a flag or env var again:

```sh
mkdir -p ~/.config/wireserve-admin
sudo grep WIRESERVE_ADMIN_TOKEN /var/lib/wireserve-coordinator/coordinator-secrets.env \
    | cut -d= -f2 > ~/.config/wireserve-admin/admin_token
chmod 600 ~/.config/wireserve-admin/admin_token
```

```sh
wireserve-admin list-peers   # just works — no --coordinator-url, no --admin-token
```

If you'd rather manage the admin token or mesh ranges yourself, copy
`deploy/env/coordinator.env.example` to `/etc/wireserve/coordinator.env`
and set whichever of `WIRESERVE_ADMIN_TOKEN`, `WIRESERVE_NET_V4_CIDR`,
`WIRESERVE_NET_V6_PREFIX` you want — an explicit value there always wins
over the generated one.

**Point a reverse proxy at `127.0.0.1:47820`.** `deploy/proxy/` has a
ready-to-use `Caddyfile.example` (auto-TLS via Let's Encrypt, about five
lines) and `nginx.conf.example`. This is the one piece the coordinator
deliberately never does itself — see spec §7 for why. The coordinator
listens on loopback only unless you set `WIRESERVE_LISTEN_ADDR`, so a
proxy on a different host needs that set to an address it can reach.

An existing install that predates the coordinator's own state directory
used `/var/lib/wireserve`, which it shared with the agent. The unit moves
the database and `coordinator-secrets.env` over on its first start
(unless `WIRESERVE_DB_PATH` is set explicitly), and refuses to start
rather than move anything that is a symlink.

**Containers**, if you'd rather not use systemd directly:

```sh
podman build -f deploy/docker/coordinator.Dockerfile -t wireserve-coordinator .
podman run -d --name wireserve-coordinator \
    -p 127.0.0.1:47820:47820 \
    -v wireserve-coordinator-data:/var/lib/wireserve \
    wireserve-coordinator
```

Same zero-config behavior applies: the admin token and mesh ranges are
generated into the named volume on first start unless you pass
`--env-file /etc/wireserve/coordinator.env` with your own values. There is
also a Quadlet unit in `deploy/` for Podman-under-systemd.

The admin port never leaves the host by design, so admin commands run
inside the container:

```sh
podman exec wireserve-coordinator wireserve-admin list-peers
```

### 2. Add a node

`wireserve-admin` doesn't have to run on the coordinator host — it's a
plain HTTP client, so it works just as well from your own laptop, as long
as it can reach the admin listener (loopback-only by default; bind it to
a private address, or SSH-tunnel it, to reach it from elsewhere). Give it
the coordinator's public URL once and it remembers it:

```sh
wireserve-admin create-node homeserver
```

If you haven't set `--coordinator-url`/`WIRESERVE_COORDINATOR_URL` or
`--admin-token`/`WIRESERVE_ADMIN_TOKEN` (or the coordinator host's own
generated `coordinator-secrets.env`, see above), it asks for each —
masked for the token — and offers to save both to
`~/.config/wireserve-admin/` so you're never asked again. Same for
`--register-url`/`WIRESERVE_REGISTER_URL` (the coordinator's *other*
listener, the one nodes actually register against): set it once and every
`create-node`/`rejoin` prints the exact command to run on the new node:

```
node 'homeserver' created — join token: jtk_...
  redeemable until: ...

To add this node to the mesh:
  sudo wireserve-agent install https://wireserve.example.com
  (needs the wireserve-agent binary already on that machine, and root)
  then paste the join token above when prompted
```

**The token is redeemable for 30 minutes** — long enough to walk over
to the machine, short enough that a token left in a chat log or a password
manager is not a live way into the mesh months later. If the window lapses,
`wireserve-admin rejoin <name>` mints a fresh one for the same node, name
and address. Override with `--ttl <secs>` per token, or coordinator-wide
with `WIRESERVE_JOIN_TOKEN_TTL_SECS`; `0` disables expiry.

On the node itself, with the `wireserve-agent` binary already there (built
via `cargo build --release --workspace` in a checkout, or copied over from
wherever you built it):

```sh
sudo wireserve-agent install https://wireserve.example.com
```

One command: it installs the binary to `/usr/local/bin`, installs and
enables the right systemd unit, then joins — prompting for the join token
(masked, not echoed) exactly like `join` does below, so nothing sensitive
ever lands in shell history. Running an *additional* agent on a host that
already runs one? Add `--instance work` (see "Several agents on one host"
below); `wireserve-admin create-node --instance work` fills that flag into
the printed command for you. `install` needs Linux/systemd — Quadlet/podman
deployments install by hand, per `deploy/quadlet/`.

The coordinator URL must be `https://` (or `http://` to loopback): the join
token, the node's bearer token and the peer directory all travel over it,
and the directory decides which keys the node trusts. For a coordinator
reached only over a network you trust end to end, pass
`--allow-plaintext-http` to `install`/`join`; the node remembers the
choice. A node that joined over plain HTTP before this check existed
refuses to start until you set `WIRESERVE_ALLOW_PLAINTEXT_HTTP=1` in
`/etc/wireserve/agent.env` (or join again).

Or, step by step, if you'd rather not have `install` touch systemd for you:

```sh
wireserve-agent join
systemctl enable --now wireserve-agent
```

Run with no arguments like this, `join` prompts for the coordinator URL and
then the join token (masked, not echoed) — nothing to paste into the
command line at all, which is also the safer option: a token passed as an
argument lands in shell history and is visible to any local user via `ps`
for as long as the process is alive. Passing both explicitly still works
the same as before (`wireserve-agent join <url> <token>`, or
`--join-token-file <path>`/`-` for scripted joins) if you'd rather not be
prompted. `join` generates the keypair locally, redeems the token, and
stores everything mode-600. The daemon brings the mesh up on `wireserve0`,
or the next free name if that one is taken; `wireserve-agent list` shows
which.

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
# on the node: plex.wg:80 reaches this node's port 32400
wireserve-agent serve plex 80:32400

# on the coordinator — see what is waiting, then approve it
wireserve-admin list-services --pending
wireserve-admin approve-service homeserver plex
```

Until it is approved, `wireserve-agent list` shows the service as
`pending approval`, which is how you tell "waiting on an admin" from "this
node has not polled yet". The node's own firewall is ready immediately
either way — it is only firewalling itself, and nothing routes to the
service's address or resolves `<name>.wg` for it yet.

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

Once approved, the declaration takes effect on the next poll: the service's
address is routed to its node and its name appears in every other node's
hosts file.

```sh
wireserve-agent serve openobserve 80:5080          # openobserve.wg:80 -> :5080
wireserve-agent serve mydns 53/udp 53/tcp 8080:8000 # several ports, TCP and UDP
wireserve-agent serve plex 32400                    # a bare port maps to itself
wireserve-agent list                    # what this node sees right now (--json for scripts)
wireserve-agent unserve plex
```

Each `PORT` is `[PUBLIC:]TARGET[/tcp|/udp]` (TCP unless given). Names are
unique across the whole mesh, first come first served.

`list` reads the daemon's cache of the last poll, no network call:

```
lego2, instance default on wireserve0

SERVICE         ADDRESS          PORTS                        NODE               STATE
mydns.wg        10.1.0.4         53/udp 53/tcp 8080:8000/tcp  lego2 (this node)  pending approval
openobserve.wg  10.1.0.3         80:5080/tcp                  strato             online
plex.wg         10.1.0.2 (node)  32400/tcp                    strato             offline

PEER    ADDRESS   ENDPOINT              HANDSHAKE
lego2   10.1.0.1  -                     this node
strato  10.1.0.2  85.215.231.166:51820  1m ago
```

A peer's endpoint and handshake are read from the WireGuard interface
itself: the address it really talks to, which can differ from the one the
coordinator has on record (an IPv6 candidate this node can't use, say, or
a peer that roamed).

`(node)` marks a service without an address of its own, which resolves to
its node: one declared by an agent from before service addresses.

#### Service addresses

Every service gets **its own mesh address** from the coordinator, and
`<name>.wg` resolves to it, so any number of services on one node can each
answer on `:80`. Peers route that address to the owning node, whose
firewall rewrites `address:PUBLIC` to `node:TARGET` in the kernel:

- **Only the published ports answer.** The target port is closed to the
  mesh, on the node's own address and on the service's: after
  `serve openobserve 80:5080`, `openobserve.wg:80` works and
  `openobserve.wg:5080` does not.
- **The service sees the real client.** Nothing is proxied; any TCP or UDP
  protocol works, and logs, rate limits and allowlists see the peer's own
  mesh address. (A connection from the owning node itself shows up as that
  node, as local connections do.)
- **Containers work**, published ports included, whatever the runtime —
  the rewrite happens before connection tracking, so a published port's
  own NAT still applies (rootful Podman, Docker with or without its
  userland proxy). The target must listen somewhere the mesh can reach:
  `0.0.0.0`, or the node's mesh address. A service bound to `127.0.0.1`
  is not reachable, by design.
- A target port can back one mapping per node (per protocol); `serve`
  refuses a second.
- Addresses come from the mesh range, shared with the nodes (a `/24`
  holds 253 nodes and services together), and stay with a service until
  it is withdrawn.

Rewriting packets needs the agent to run as root in the host's own
namespaces, as the shipped systemd unit and quadlets do. The kernel refuses
it inside an unprivileged container (LXC, rootless podman); the agent says
so in its log, and the services on that node stay unreachable.

Upgrade every agent: an agent from before service addresses still resolves
new services to their node's address, where their ports are now closed.
Its own declarations keep working the old way (node address, same port)
until it is upgraded.

### 4. Add a phone or laptop

A device that only consumes services does not run the agent. This creates
the node and prints a ready-to-import WireGuard config:

```sh
podman exec wireserve-coordinator wireserve-admin export-config myphone \
    --out myphone.conf
```

Import it into the official WireGuard app, by file or with `--qr`, which
prints a code to scan straight from the terminal. The file contains a
private key, so it is written mode 600; move it, do not copy it. (So does
the QR code — it will sit in your scrollback.) Such a peer gets a mesh
address and reaches every service by its address (in `wireserve-admin
list-services`) and port, but has no `.wg` name resolution.

**Give it a gateway so the config does not go stale.** Without one, the
config is a snapshot: every node is listed individually, so anything that
joins later is unreachable from the device until you export again. Point it
at a node that can carry traffic for it and the whole mesh range is routed
there instead, so new nodes and services just work:

```sh
wireserve-admin approve-transit vps1      # and `wireserve-agent transit on` on vps1
wireserve-admin export-config myphone --gateway vps1 --qr
```

The gateway needs a publicly reachable endpoint — a phone on cellular has
one `Endpoint =` line and no way to refresh it — and must be carrying
traffic already, which is the same opt-in plus approval that
[transit](#6-route-through-another-node-when-nat-blocks-a-direct-path) uses,
for the same reason: it sees the traffic in the clear. With exactly one
node eligible, `--gateway` can be left off.

Nodes that *are* reachable from anywhere still get their own direct entry,
so the device talks to them straight rather than through the gateway. Only
what it cannot dial itself is routed onward.

**A node with a public address its router will not let in.** An endpoint
can be globally routable on paper and still be undialable: a home router
that firewalls inbound IPv6, a public IPv4 with no port forward. The export
cannot tell, and WireGuard has no failover — a direct entry for such a node
outranks the gateway's range and drops everything sent to it, its services
included. Tell the coordinator once:

```sh
wireserve-admin via-gateway minipc on       # `off` undoes it
wireserve-admin export-config myphone --refresh --qr
```

From then on every export with a gateway reaches `minipc` through it, and a
service `minipc` declares later is reachable from the phone without
re-exporting. This affects **only** configs made by `export-config` for
phones and other static devices; how agents reach each other is untouched.
It changes nothing already on a device either: the command lists the
devices whose config needs `--refresh`. Such a node is never picked as a
gateway, and the gateway itself must still reach it directly, as above.
Upgrade the coordinator before the admin CLI — an older coordinator does
not know the flag, and the export then keeps the node direct.

**Re-issuing a config** keeps the device's name and mesh address:

```sh
wireserve-admin export-config myphone --refresh --qr
```

Only the keypair changes. Delete the old tunnel on the device before
importing the new one — the address is unchanged, so the stale config still
looks valid, and two tunnels claiming one address is its own kind of
confusing. This is destructive from its first call: the old key stops
working immediately and the device is briefly absent from the mesh while
the new one is redeemed. It refuses outright if the name belongs to a node
that runs the agent.

### 4b. Give services real names, reachable from a phone

`<service>.wg` lives in each agent's `/etc/hosts`, which a phone does not
have. To give services a name that works everywhere, point one node's reverse
proxy at the mesh and tell the coordinator the domain:

```sh
# on the coordinator
WIRESERVE_SERVICE_DOMAIN=int.example.com
WIRESERVE_SERVICE_PROXY=web
```

Every service is then `<name>.int.example.com` instead of `<name>.wg` — the
suffix is **replaced, not added to**. Two working names would mean two base
URLs, and anything with a single configured one (Gitea's `ROOT_URL`, Grafana's
`root_url`, an OIDC `redirect_uri`) emits redirects that bounce between them.

**Publishing on TCP 443 is what asks for a name with TLS:**

```sh
wireserve-agent serve plex 443:32400   # plex.int.example.com, via the proxy
wireserve-agent serve prom 80:9090     # prom.int.example.com, direct
```

| Published on | Resolves to | From a node | From a phone |
| --- | --- | --- | --- |
| 443 | the proxy | via the proxy, HTTPS | via the proxy, HTTPS |
| anything else | its own address | direct, plain HTTP | 404 at the proxy |

A 443 service resolves to the same place with the same scheme wherever you
ask, which is what makes one configured base URL correct everywhere. Anything
else keeps the direct path, and with it the real client address and no extra
hop — it simply is not reachable *by name* from a phone. Publish it on 443 if
you want the name; reach it at `address:port` if you do not. Nothing that is
not HTTP ever gets a hostname or a certificate it did not ask for.

On the proxy node, publish the proxy itself and run the agent with it:

```sh
wireserve-agent serve web 443:8443
wireserve-agent daemon --proxy caddy
```

The agent then writes one matcher and one handler per 443 service into
`/etc/caddy/conf.d/wireserve.caddy` on every poll that changes anything, and
reloads Caddy. `deploy/proxy/Caddyfile.services.example` is the half you
write. A service declared later appears by itself; nothing on any device
changes, ever.

Two things to get right:

- **Point the wildcard DNS record at the proxy's *service* address**, the one
  `wireserve-agent list` shows — not at the node's mesh address. The firewall
  opens `service:443` and deliberately refuses `node:443`, so a record aimed
  at the node is dropped by that node's own firewall.
- **Caddy needs a custom build** for the wildcard certificate: the stock
  binary ships no DNS provider module (`xcaddy build --with
  github.com/caddy-dns/cloudflare`). DNS-01 itself is fine for a name the
  internet cannot reach — it only needs the `_acme-challenge` TXT record.

#### If the name resolves on one network but not another

This is almost always **DNS rebinding protection**, and it is worth knowing
before it costs you an evening. Resolvers strip private addresses out of
answers from public DNS by default; the usual list is `127/8`, `10/8`,
`172.16/12`, `192.168/16`, `169.254/16`, `fd00::/8` and `fe80::/10`. The
coordinator generates a `10.x.x.0/24` mesh and an `fd..::/64` prefix, so
**both families are on that list** and the wildcard record is silently
dropped — no error, just a name that does not resolve.

OpenWrt's dnsmasq enables this by default, as do pfSense, NextDNS and AdGuard.
The usual offender is your own router, and every one of them has a per-domain
exception:

```
rebind-domain-ok=/int.example.com/       # dnsmasq, OpenWrt
private-domain: "int.example.com"        # unbound, pfSense
```

NextDNS and AdGuard take an allowlist entry for the domain. Carrier and plain
public resolvers generally do not filter, which is why the symptom is often
"works on cellular, fails at home".

`100.64.0.0/10` is not on the strip list, but do not reach for it — see the
mesh-range warning further down, since Tailscale allocates that entire `/10`.

### 5. When a machine is lost or compromised

```sh
podman exec wireserve-coordinator wireserve-admin revoke homeserver
```

The node's token stops working immediately, and every other node drops it
as a peer on its own next poll, so removal across the mesh is bounded by
the poll interval rather than instant. `rejoin` issues a fresh join token
for the same name and address when the machine itself is still trusted
but its key may not be: the old key and token stop working at once, and
the node drops out of every other node's peer list until it registers
again under a new key. `delete-node` frees the name entirely, and refuses
until the node is revoked.

### 6. Route through another node when NAT blocks a direct path

Two nodes each behind their own hard (symmetric) NAT — no shared LAN,
nothing port-forwarded to either — can end up with no direct path at all:
a symmetric NAT maps a different external port per destination, so
whatever WireServe's own NAT-traversal already learned for one peer is
useless for reaching a different one. When that happens, a third node
that already reaches both can carry the connection: WireGuard itself
decrypts and re-encrypts at the kernel layer and forwards it on, the same
way any router forwards a packet — no separate relay server, no new
protocol, and the coordinator never sees the traffic.

**A node carries traffic only with two approvals, and has neither by
default.** Its own operator opts in, so a node with a data cap, say, is
never used; and the mesh admin approves it as a carrier:

```sh
wireserve-agent transit on   # on the node: willing to carry traffic for others
wireserve-agent transit off  # stop — takes effect on the next poll, no rejoin

wireserve-admin approve-transit homeserver   # on the admin side: trusted to
wireserve-admin deny-transit homeserver      # withdraw it again
```

The admin half is there because of what a carrier can do. Unlike an
ordinary connection, which is end-to-end between the two nodes involved,
a carrier sees the mesh-layer plaintext of whatever pairs route through
it, and can send packets that appear to come from either end. What a node
says about itself (that it is willing, which peers it reaches) cannot be
verified, so without approval a single compromised node could offer to
carry every pair in the mesh. Until it is approved, `wireserve-agent
list` on that node says `Transit: on, waiting for an admin to approve
this node as a carrier`. Revoking or rejoining a node withdraws its
approval, and `list-peers` shows who currently has one
(`transit=approved`).

`wireserve-agent list` shows the outcome, both for a peer this node can't
reach directly and for what this node is carrying on others' behalf:

```
PEER    ADDRESS   ENDPOINT  HANDSHAKE  ROUTE
laptop  10.1.0.5  -         never      via homeserver

Transit: on, carrying: laptop <-> phone
```

`direct` is the ordinary case; `via <name>` means this node is one end of
a pair being routed through a carrier. Only a single hop is ever used —
the carrier must already, currently reach both ends itself — and nothing
here is a substitute for a real port-forward or a working reflexive
address when one is available; it only ever engages once every other path
has failed.

## Command reference

On a node, talking to the local daemon over a Unix socket:

| Command | What it does |
| --- | --- |
| `wireserve-agent install <url> [--instance name]` | installs the binary + systemd unit, then joins — one command, needs root |
| `wireserve-agent join [url] [token]` | one-time bootstrap, generates the keypair — prompts for either if omitted |
| `wireserve-agent serve <name> <[public:]target[/tcp\|/udp]>...` | publish a service on its own address |
| `wireserve-agent daemon --proxy caddy` | publish this mesh's 443 services as vhosts on the reverse proxy running here |
| `wireserve-agent unserve <name>` | withdraw one |
| `wireserve-agent transit on\|off` | opt in/out of carrying traffic for two other nodes that can't reach each other directly (also needs `approve-transit`) |
| `wireserve-agent list [--json]` | services (name, address, ports, owner, state), peers (with each one's route — direct or via a carrier) and anything not published, from the last poll |
| `wireserve-agent leave` | tear down interface, firewall, hosts block |

Against the admin port (loopback-only by default; run from the coordinator
host, or point `--coordinator-url`/`WIRESERVE_COORDINATOR_URL` at it from
anywhere that can reach it):

| Command | What it does |
| --- | --- |
| `wireserve-admin create-node <name>` | create a node, print a join token |
| `wireserve-admin export-config <name> [--gateway <node>] [--refresh] [--qr]` | create (or re-issue) a static peer's `.conf` |
| `wireserve-admin list-peers` | the full directory |
| `wireserve-admin via-gateway <name> on\|off` | exported phones reach this node through their gateway, not directly |
| `wireserve-admin revoke <name>` | cut a node off, keep its name reserved |
| `wireserve-admin rejoin <name>` | fresh join token, same name and address; the old key stops working at once |
| `wireserve-admin delete-node <name>` | remove the record, free the name |
| `wireserve-admin clear-endpoint <name>` | drop a stale advertised endpoint |
| `wireserve-admin list-services [--pending]` | declared services and their approval state |
| `wireserve-admin approve-service <node> <svc>` | let a declaration reach the mesh |
| `wireserve-admin deny-service <node> <svc>` | refuse one, or withdraw an approval |
| `wireserve-admin approve-transit <name>` | let a node that opted in carry traffic for others |
| `wireserve-admin deny-transit <name>` | withdraw that |

## Workspace layout

- `crates/wireserve-types` — shared wire structs, validation, token hashing.
- `crates/wireserve-coordinator` — axum + SQLite coordinator binary.
- `crates/wireserve-agent` — WireGuard/firewall/hosts-file daemon + CLI.
- `crates/wireserve-admin` — separate admin CLI (distinct trust surface).
- `deploy/` — systemd units, Dockerfiles, Quadlet files, env examples.

## Build prerequisites

```sh
cargo build --workspace
```

No special system dependencies beyond a C toolchain (for `rusqlite`'s
bundled SQLite in the coordinator).

At **runtime**, `wireserve-agent` needs the `nft` binary (the `nftables`
package on Debian/Ubuntu/Fedora/Arch) at `/usr/sbin/nft`, `/sbin/nft`,
`/usr/bin/nft` or `/bin/nft` — it manages its firewall through nft's JSON
API and refuses to start without it. The container image already includes
it.

## What each machine needs open and configured

### Coordinator host

| Port | Direction | Who connects | Notes |
| --- | --- | --- | --- |
| 443/tcp | inbound | every agent | your reverse proxy, terminating TLS |
| 47820/tcp | none | the proxy only | plain HTTP, must not be reachable from an untrusted network (§7) |
| 47821/tcp | none | nobody | admin listener, loopback only; the coordinator refuses to start if it is not (§4.0) |

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

**The interface name.** The agent picks the first free name of
`wireserve0` … `wireserve15` and keeps it across restarts (it's stored in
the instance's state). It never takes over an interface it did not create:
a name held by another tunnel is simply skipped. `--ifname <name>` pins an
exact name instead — then a conflict makes the daemon refuse to start
rather than pick another, since you presumably refer to that name
elsewhere — and `--ifname auto` removes the pin. Agents from before this
used `wg0`; on upgrade, the default instance moves to `wireserve0` and
removes what the old one left behind.

**The mesh address ranges.** If you left `WIRESERVE_NET_V4_CIDR` and
`WIRESERVE_NET_V6_PREFIX` unset, the coordinator already generated a safe
pair for you on first start (see "Run the coordinator" above) and there is
nothing to do here. This section is for anyone who set one or both
explicitly, or who is running against an older deployment that still has
the binary's compiled-in defaults — either way, both are poor choices, for
unrelated reasons, and changing them requires care: addresses are
allocated once and kept for the life of the node record, so a later change
leaves the mesh addressed out of two ranges. Each node also pins the ranges
it joined with and ignores any peer or service address outside them (so a
compromised coordinator can't route arbitrary addresses into its tunnel).
After a change, nodes joined under the new ranges therefore don't see
peers still addressed from the old ones until those are re-joined.

The compiled-in IPv4 default `100.90.0.0/24` sits inside `100.64.0.0/10`,
the carrier-grade-NAT block Tailscale allocates all of its addresses from
and some ISPs use on WAN links. A host running such an overlay routes that
whole `/10` to the overlay's interface, covering these mesh addresses too.

The compiled-in IPv6 default `fd00:90::/64` is not a Tailscale problem at
all, since Tailscale uses `fd7a:115c:a1e0::/48`. It is an RFC 4193
problem: a unique local address is `fd` followed by 40
**pseudo-randomly generated** bits, and that randomness is the entire
mechanism that lets two networks built by strangers be merged without
renumbering. `fd00:90::` throws it away, and round-numbered `fd00::`
prefixes are the most commonly hand-picked there are, so it collides with
exactly the neighbours it should coexist with. Generate your own the same
way the coordinator does internally:

```sh
python3 -c "import secrets; h=secrets.token_bytes(5).hex(); print(f'fd{h[0:2]}:{h[2:6]}:{h[6:10]}::/64')"
```

The coordinator warns at startup if either configured range still matches
one of these compiled-in defaults.

### Other firewalls on the host

A host firewall filters the mesh interface on its own, next to the agent's
table: ufw's default deny, firewalld's default zone, or a hand-written
`nftables.conf` with `policy drop` all block a declared service even though
the agent allows it (netfilter lets every table drop a packet; an accept in
one doesn't override a drop in another). So the agent makes them let the
mesh interface through, the same way NetBird does, and its own table then
decides what is actually reachable:

- **nftables tables** (native configs, crowdsec, geoip-shell, …): a rule
  `iifname "wireserve0" counter accept comment "wireserve:wireserve0"` at the
  top of every other table's input filter chain.
- **iptables** (ufw, Docker hosts, scripts; both nft-backed and legacy):
  `-A INPUT -i wireserve0 -m comment --comment "wireserve:wireserve0" -j ACCEPT`
  at the top of `INPUT`.
- **firewalld**: the interface goes into the `trusted` zone for the current
  boot only (never `--permanent`), plus a small table
  `inet wireserve-interop.wireserve0` that drops traffic *forwarded* from the mesh
  interface, because a trusted zone would otherwise let mesh peers route
  through this host. A zone you bound the interface to yourself is left
  alone (the agent logs that it did).

All of it is scoped to exactly the mesh interface, and only to traffic
addressed to this host: nothing is opened on any other interface, and
nothing is opened for forwarded or outgoing traffic. The agent keeps it in
place when another tool reloads (`ufw reload`, `firewall-cmd --reload`,
`nft -f`), usually within a second, and removes all of it on stop or
`leave`. To see what it added:

```sh
sudo nft list ruleset | grep wireserve:
sudo iptables -S INPUT | grep wireserve:
firewall-cmd --get-zone-of-interface=wireserve0
```

`sudo ufw allow in on wireserve0` or similar manual exceptions are not
needed and can be removed.

In a container (Docker/Podman with host networking) the same happens on
the host, except for firewalld, which the container can't reach; the agent
logs the command to run on the host instead.

### Several agents on one host

One host can be a node in several meshes (or hold several identities in
one) by running one agent *instance* per mesh. The plain unit runs the
default instance; name the others:

```sh
sudo wireserve-agent install https://wireserve.example.com --instance work
sudo wireserve-agent --instance work serve git 3000
sudo wireserve-agent --instance work list
```

Or, by hand:

```sh
sudo wireserve-agent --instance work join          # prompts, as above
sudo systemctl enable --now wireserve-agent@work   # deploy/systemd/wireserve-agent@.service
```

(`WIRESERVE_INSTANCE=work` works in place of the flag.) Each instance is a
separate node with its own:

| | default instance | instance `work` |
|---|---|---|
| state and keys | `/var/lib/wireserve/` | `/var/lib/wireserve/instances/work/` |
| socket | `/run/wireserve/agent.sock` | `/run/wireserve-work/agent.sock` |
| interface | first free `wireserve<N>` | next free `wireserve<N>` |
| listen port | first free from 51820 | next free from 51820 |
| nftables | `inet wireserve.<if>`, `inet wireserve-interop.<if>` | same, for its interface |
| hosts file | `# BEGIN WIRESERVE` block | `# BEGIN WIRESERVE work` block |

Instances leave each other alone: each keeps, rewrites and removes only
its own table, hosts block and host-firewall rules. Another instance's
rules are left in place while it runs; if it dies without cleaning up,
whichever instance runs next removes them. An instance can't be run twice,
and `join` refuses while that instance's daemon is up. Interface names and
listen ports stored by an instance stay reserved for it even while it's
stopped.

Give the meshes' coordinators non-overlapping address ranges; the daemon
refuses to start if its own mesh address is already on another interface.

Running `deploy/e2e/run-multi-instance-test.sh` (after
`cargo build --workspace`) exercises all of this end to end in a throwaway
unprivileged namespace — no root and no containers needed.

The agent adds one route per peer address on its interface and nothing
else — no routes to peers' endpoints, so hosts without a default route
work too. Versions before this let the WireGuard library pin a route to
every peer endpoint via the default gateway; those stay until the link
goes down or the host reboots, and are harmless while the gateway doesn't
change (`ip route` lists them as `<endpoint-ip> via <gateway>`).

## Building the container images

Both Dockerfiles use build cache mounts for the cargo registry and the
target directory, shared between the two images. The first build is a cold
compile of the whole dependency graph; every build after that is
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
