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

**Bare metal**: build (or copy over) `wireserve-coordinator` and
`wireserve-admin`, keep them side by side in one directory, and run:

```sh
cargo build --release --workspace
sudo ./target/release/wireserve-coordinator install
```

It asks six questions in plain language, each with a short explanation and
a sensible default:

1. the web address your machines reach the coordinator at (`https://…`);
2. whether the HTTPS web server (reverse proxy) runs on this machine — and,
   if not, which addresses the two machines talk over;
3. the internal port the web server passes requests to (47820): TCP stays
   closed to the internet, UDP may be forwarded for NAT help;
4. whether new services wait for your approval (yes);
5. whether services get names under a domain you own, and which service is
   your web proxy (`web`, e.g. `wireserve serve web 443:8443`);
6. which local user gets the admin key saved, so `wireserve-admin` needs no
   flags (whoever ran sudo).

Then it creates the `wireserve-coordinator` user and group, installs both
binaries to `/usr/local/bin`, writes `/etc/wireserve/coordinator.env`,
generates the admin key and mesh ranges, starts the service, and prints what
is left by hand: a ready-to-paste Caddy block, the firewall rules, and (with a
domain) the DNS record. Every question also has a flag (`install --help`), and
without a terminal it never asks — `--public-url` is the only one without a
default:

```sh
sudo ./wireserve-coordinator install --public-url https://mesh.example.com --yes
```

Run it again on a machine where it is installed and it **upgrades** instead:
both binaries and the unit replaced and the service restarted, no questions,
`coordinator.env` untouched. That makes `scp wireserve-coordinator
wireserve-admin host:/tmp/ && ssh host sudo /tmp/wireserve-coordinator
install` the whole update. `install --reconfigure` asks the questions again
with the current settings as defaults, and changes only those keys in
`coordinator.env` — a key you drop is commented out, never deleted.

The coordinator runs as its own `wireserve-coordinator` user. Earlier
versions ran it as `wireserve`, which on a host that also runs an agent is the
group allowed to drive the agent daemon (see "Using it without sudo"); an
upgrade moves it over, and systemd hands the state directory to the new user.
The old `wireserve` user is left alone — keep its group if an agent runs there.

**By hand**, if you'd rather not run the installer:

```sh
sudo useradd --system --user-group --no-create-home --shell /usr/sbin/nologin wireserve-coordinator
sudo install -m 0755 target/release/wireserve-coordinator target/release/wireserve-admin /usr/local/bin/
sudo cp deploy/systemd/wireserve-coordinator.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now wireserve-coordinator
```

No `/etc/wireserve/coordinator.env` is required for this — the unit's
`StateDirectory=` gives the coordinator `/var/lib/wireserve-coordinator` to work with,
and it generates its own admin token and mesh ranges there on first start.
Save the admin token it generated once, so `wireserve-admin` never needs a
flag or env var again:

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
proxy on a different host needs that set to an address it can reach — and
`WIRESERVE_TRUSTED_PROXY` set to the proxy's address, so the coordinator
believes the client addresses it forwards and nobody else's.

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
  sudo wireserve install https://wireserve.example.com
  (needs the wireserve binary already on that machine, and root)
  then paste the join token above when prompted
```

**The token is redeemable for 30 minutes** — long enough to walk over
to the machine, short enough that a token left in a chat log or a password
manager is not a live way into the mesh months later. If the window lapses,
`wireserve-admin rejoin <name>` mints a fresh one for the same node, name
and address. Override with `--ttl <secs>` per token, or coordinator-wide
with `WIRESERVE_JOIN_TOKEN_TTL_SECS`; `0` disables expiry.

On the node itself, with the `wireserve` binary already there (built
via `cargo build --release --workspace` in a checkout, or copied over from
wherever you built it):

```sh
sudo wireserve install https://wireserve.example.com
```

One command: it installs the binary to `/usr/local/bin/wireserve`, installs
and enables the right systemd unit, then joins — prompting for the join token
(masked, not echoed) exactly like `join` does below, so nothing sensitive
ever lands in shell history. It also creates a `wireserve` group (see
"Using it without sudo" below); it does not add anyone to it. Running an *additional* agent on a host that
already runs one? Add `--instance work` (see "Several agents on one host"
below); `wireserve-admin create-node --instance work` fills that flag into
the printed command for you. `install` needs Linux/systemd — Quadlet/podman
deployments install by hand, per `deploy/quadlet/`.

**Run the agent on the host, not in a container, on any node that forwards**:
a transit carrier, a phone's gateway or exit, or a node serving a device on
its LAN. Those need the agent to switch on forwarding for its own interfaces
in `/proc/sys/net`, which Podman and Docker mount read-only. A containerised
agent logs a warning and forwards nothing, and from the other end that looks
like a dead route. A node that only serves its own ports, and never
forwards, runs fine in the container.

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
wireserve join
systemctl enable --now wireserve-agent
```

Run with no arguments like this, `join` prompts for the coordinator URL and
then the join token (masked, not echoed) — nothing to paste into the
command line at all, which is also the safer option: a token passed as an
argument lands in shell history and is visible to any local user via `ps`
for as long as the process is alive. Passing both explicitly still works
the same as before (`wireserve join <url> <token>`, or
`--join-token-file <path>`/`-` for scripted joins) if you'd rather not be
prompted. `join` generates the keypair locally, redeems the token, and
stores everything mode-600. The daemon brings the mesh up on `wireserve0`,
or the next free name if that one is taken; `wireserve list` shows
which.

#### Using it without sudo

`install`, `join` and `daemon` need root. Everything else (`serve`,
`unserve`, `list`, `transit`, `exit`, `leave`) only talks to the running
daemon over a Unix socket, and needs no root of its own: whoever can open
the socket can run them. By default that is root alone. If a group named
`wireserve` exists when the daemon starts, the daemon shares the socket with
it, and its members can run those commands as themselves:

```sh
sudo usermod -aG wireserve $USER   # then log out and back in
wireserve list
```

`install` creates the group for you and prints that line; without
`install`, `sudo groupadd --system wireserve` before starting the daemon.
The group is looked up once, when the daemon binds its socket, so a daemon
that was already running needs `sudo systemctl restart wireserve-agent`
to pick it up. Someone who is not allowed in is told so, rather than that
the daemon isn't running. `WIRESERVE_SOCKET_GROUP` in
`/etc/wireserve/agent.env` names a different group, and an empty value keeps
the socket root-only even though the group exists.

Treat membership as "operator of this node", the way you would the `docker`
group. A member can publish and withdraw services, opt the node in or out
of transit and exit duty, and `leave` the mesh. What a member cannot do is
get past the coordinator: a new service, a transit carrier or an exit still
needs an admin's approval there, and members cannot read the node's keys
or bearer token, which stay in a root-only state file. Only add people you
would trust to run that node.

A containerised agent does not see the host's groups, so its socket stays
root-only (`podman exec`/`docker exec` runs as root anyway).

#### Upgrading a node

Build, copy the binary over, and run its `install` on the node:

```sh
cargo build --release --workspace
scp target/release/wireserve you@node:/tmp/
ssh -t you@node sudo /tmp/wireserve install
```

On a node that has already joined, `install` given no URL or token is an
upgrade, not a join: it installs the binary, rewrites the systemd unit files
(the default unit, and the `@` template if one is on disk), reloads systemd,
and restarts every running `wireserve-agent*` unit, so no agent keeps running
the old binary. The node keeps its identity and its declared services; the
mesh drops out for the few seconds the daemon takes to restart, and its
firewall is rebuilt deny-first as on any start. Pass a URL or a token and it
joins again, as before. Upgrade the coordinator (copy `wireserve-coordinator`
and `wireserve-admin` to `/usr/local/bin/` and restart it) before the agents;
the notes elsewhere in this file say where a feature needs that.

Coming from the days when the command was `wireserve-agent`: the same
upgrade does it. The systemd unit is still called `wireserve-agent`, the
old `/usr/local/bin/wireserve-agent` is left where it is — unused once the
unit points at the new binary, and yours to remove — and the `wireserve`
group is created (see above).

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
wireserve serve plex 80:32400

# on the coordinator — see what is waiting, then approve it
wireserve-admin list-services --pending
wireserve-admin approve-service homeserver plex
```

Until it is approved, `wireserve list` shows the service as
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
wireserve serve openobserve 80:5080          # openobserve.wg:80 -> :5080
wireserve serve mydns 53/udp 53/tcp 8080:8000 # several ports, TCP and UDP
wireserve serve plex 32400                    # a bare port maps to itself
wireserve serve myrouter 443:192.168.178.1:80 # a device on this node's LAN, see below
wireserve list                    # what this node sees right now (--json for scripts)
wireserve unserve plex
```

Each `PORT` is `[PUBLIC:][ADDRESS:]TARGET[/tcp|/udp]` (TCP unless given;
without an address, the target is on this node). Names are unique across the
whole mesh, first come first served.

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

#### Devices on the node's network

A mapping can name an IPv4 address the node reaches, such as a router,
NAS or printer that can't run an agent itself:

```sh
wireserve serve myrouter 443:192.168.178.1:80   # myrouter.wg:443 -> the router's :80
```

The node forwards `myrouter.wg:443` to `192.168.178.1:80`, and the device
sees every connection come from the node's own LAN address. It has no route
back into the mesh, so unlike a service on the node, **the client's address
is not preserved**. Everything else works the same: approval, the name, only
the published port answering, and (on 443) a reverse-proxy vhost for
phones. What an admin approves includes the address:
`wireserve-admin list-services` shows `443:192.168.178.1:80/tcp`. The rest
of the mesh only ever sees `443:80/tcp`.

- **IPv4 only**, and a literal address, not a hostname. A service's own
  address is IPv4, and the kernel can't forward an IPv4 connection to an
  IPv6 one.
- Not loopback, and nothing inside the mesh range. A service on this node
  is the form without an address; one on another node is that node's to
  serve.
- **Forwarding.** Replies arrive on the interface facing the device, and
  Linux only forwards what arrives on an interface with forwarding on. If
  that interface's `net.ipv4.conf.<if>.forwarding` is off and the host
  doesn't forward globally, the agent turns it on. While it does, its own
  table drops anything else forwarded from that interface, so the host
  doesn't become a router for its LAN. It turns forwarding off again on
  stop. A host that already forwards (a router, or a Docker or Podman host)
  is left as it is.
- **Routers that check the Host header.** Many (a FRITZ!Box among them)
  answer only to their own name, as a defence against DNS rebinding, and
  refuse `myrouter.wg`. The generated proxy vhost passes the client's name
  through. For such a device, write its `handle` yourself ahead of the
  generated `import`, with `reverse_proxy <its service address>:443` and
  `header_up Host fritz.box` (not yet tried against a real router).
- Before downgrading an agent to a version from before target addresses,
  `unserve` such services: an older agent would read `443:192.168.178.1:80`
  as its own port 80.

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
wireserve-admin approve-transit vps1      # and `wireserve transit on` on vps1
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
wireserve serve plex 443:32400   # plex.int.example.com, via the proxy
wireserve serve prom 80:9090     # prom.int.example.com, direct
```

| Published on | Resolves to | From a node | From a phone |
| --- | --- | --- | --- |
| 443 | the proxy | via the proxy, HTTPS | via the proxy, HTTPS |
| anything else | its own address | direct, plain HTTP | direct with [DNS records](#let-the-coordinator-write-the-dns-records), else 404 at the proxy |

A 443 service resolves to the same place with the same scheme wherever you
ask, which is what makes one configured base URL correct everywhere. Anything
else keeps the direct path, and with it the real client address and no extra
hop. A phone reaches it by name only when the coordinator writes the DNS
records (below); with a hand-made wildcard record it lands on the proxy
instead. Nothing that is not HTTP ever gets a certificate it did not ask for.

On the proxy node, publish the proxy itself and run the agent with it:

```sh
wireserve serve web 443:8443
wireserve daemon --proxy caddy
```

The agent then writes one matcher and one handler per 443 service into
`/etc/caddy/conf.d/wireserve.caddy` on every poll that changes anything, and
reloads Caddy. `deploy/proxy/Caddyfile.services.example` is the half you
write. A service declared later appears by itself; nothing on any device
changes, ever.

Two things to get right:

- **Let the coordinator write the DNS records** (next section), or point a
  wildcard record at the proxy's *service* address, the one `wireserve list`
  shows — not at the node's mesh address. The firewall opens `service:443`
  and deliberately refuses `node:443`, so a record aimed at the node is
  dropped by that node's own firewall.
- **Caddy needs a custom build** for the wildcard certificate: the stock
  binary ships no DNS provider module (`xcaddy build --with
  github.com/caddy-dns/cloudflare`). DNS-01 itself is fine for a name the
  internet cannot reach — it only needs the `_acme-challenge` TXT record.

#### Let the coordinator write the DNS records

Instead of a wildcard record, the coordinator can keep one record per
service up to date through your DNS provider's API: `plex.int.example.com`
pointing wherever `plex.int.example.com` resolves on a node, written when
the service is approved, moved when its address changes, removed when it is
withdrawn or its node revoked. That is what gives a phone the names of
services that are not on 443.

```sh
# on the coordinator, next to WIRESERVE_SERVICE_DOMAIN
WIRESERVE_DNS_PROVIDER=cloudflare      # or rfc2136, desec, hetzner, porkbun
WIRESERVE_DNS_API_TOKEN=...            # a token that may edit the zone
```

`wireserve-coordinator install --reconfigure` asks for these, and before
saving writes and removes a throwaway `_wireserve-check` TXT record, so a
wrong token shows up there rather than as names that never appear.

| Provider | Settings |
| --- | --- |
| `rfc2136` | `WIRESERVE_DNS_SERVER` (`host:port`), `WIRESERVE_DNS_TSIG_KEY_NAME`, `WIRESERVE_DNS_TSIG_SECRET` (base64), `WIRESERVE_DNS_TSIG_ALGORITHM` (default `hmac-sha256`) — BIND, Knot, PowerDNS |
| `cloudflare`, `desec`, `hetzner` | `WIRESERVE_DNS_API_TOKEN` |
| `porkbun` | `WIRESERVE_DNS_API_TOKEN` (the API key), `WIRESERVE_DNS_API_SECRET` |

`WIRESERVE_DNS_ZONE` names the zone when it is a parent of the service domain
(default: the domain itself); `WIRESERVE_DNS_TTL` defaults to 300 seconds.

What to know first:

- **The coordinator manages service names under the domain.** A record with
  the same name as a service is replaced. It deletes only records it wrote
  itself, and never touches anything else in the zone — a wildcard record
  you made earlier stays, and is simply overridden by each service's own.
- **Keep the domain to itself.** Most providers' tokens cover a whole zone,
  so a token for `example.com` could also change its mail records. A zone of
  its own (a subdomain delegated to its own zone, or a spare domain) keeps
  the token that small.
- **The records publish your mesh addresses and service names.** They are
  private addresses and unreachable from outside the mesh, but anyone can
  read them.
- **An address change waits 20 seconds** before it is written, so a proxy
  that drops out of the directory for a moment does not swing every name.
  `wireserve-admin list-services` shows each record as `dns=published`,
  `dns=pending` or the provider's error.

#### A sign-in in front of chosen services

With names in place, a service can also sit behind a sign-in at the proxy —
per person, with your own identity provider, rather than "anything on the
mesh gets in". Any `forward_auth` provider works; the example is written for
[authward](https://git.tia.sh/tia/authward) in front of Pocket ID.

```sh
wireserve-admin approve-service homeserver jellyfin --auth   # new services
wireserve-admin service-auth grafana on                      # existing ones
```

Two things happen from the next poll:

- the proxy puts your `wireserve_auth` snippet in front of the service — for
  authward, its `forward_auth` block;
- the service's **own node admits nobody but the proxy**, on every one of
  its mappings. Without that, anyone on the mesh could skip the sign-in by
  dialling the service address directly, and set whatever identity headers
  they liked. That is authward's trust boundary, enforced by the mesh.

The two snippets, and a handler for authward's own pages, are in
`deploy/proxy/Caddyfile.services.example`; they are needed once anything is
marked, and never before. The mark belongs to the service **name**: it
survives the service being withdrawn and declared again, and can be set
before anything declares it. `list-services` shows it.

Worth knowing before you mark something:

- **Native apps can't do a browser sign-in.** The Jellyfin, Immich and Home
  Assistant apps, or anything speaking CalDAV/CardDAV, fail behind it. That
  is why it is per service. authward's API tokens and `bypass_paths` are the
  way through for those.
- **Only services published on TCP 443** can be marked — the others are not
  behind the proxy at all — and the proxy itself cannot be.
- **Close the owner's LAN yourself.** The mesh admits only the proxy; a
  backend listening on every interface is still reachable from its own
  network. Bind it to the node's mesh address.
- **Every HTTP service under the domain gets the sign-in cookie**, which is
  scoped to the whole domain. The generated config strips it from
  everything behind the proxy; a service reached on another port is not
  behind it and keeps receiving it, so publish HTTP services on 443 once
  sign-in is in use.
- **Upgrade before marking.** The coordinator refuses the mark until the
  service's node and the proxy's node both report that they understand it,
  because either one ignoring it leaves the service open. Don't downgrade
  either one while a service is marked.

#### If the name resolves on one network but not another

This is almost always **DNS rebinding protection**, and it is worth knowing
before it costs you an evening. Resolvers strip private addresses out of
answers from public DNS by default; the usual list is `127/8`, `10/8`,
`172.16/12`, `192.168/16`, `169.254/16`, `fd00::/8` and `fe80::/10`. The
coordinator generates a `10.x.x.0/24` mesh and an `fd..::/64` prefix, so
**both families are on that list** and the records are silently dropped —
no error, just a name that does not resolve.

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

### 4c. Send all of a phone's traffic through the gateway

For public Wi-Fi, or to browse from home while away, a device exported with
a gateway can also get a **full-tunnel profile**: same key, same address,
but everything goes to the gateway, which sends it on to the internet under
its own address. The gateway opts in first, as it did for transit, because
the traffic leaves under *its* public IP:

```sh
wireserve exit on                           # on the gateway, besides `transit on`
wireserve-admin export-config myphone --gateway vps1 --exit --dns 9.9.9.9 --qr
```

That prints two codes; import both. The WireGuard app runs one tunnel at a
time, so switching on `myphone-exit` is the exit switch. With `--out
myphone.conf` the second one is written beside it as `myphone-exit.conf`.
`--refresh` without `--exit` withdraws it.

- **IPv4 only.** The full tunnel captures the device's IPv6 as well, so none
  of it leaks around the tunnel on someone else's network, and the gateway
  drops it. Phones fall back to IPv4 on their own, since the only IPv6
  address the tunnel gives them is a private one.
- **The internet, not the gateway's LAN.** Private and other non-public
  destinations are refused, so the exit never reaches around the per-service
  approval a device on a LAN needs. To reach one, [serve it](#devices-on-the-nodes-network).
- **`--dns` is required.** Without it, the phone keeps asking the café's
  resolver, at a private address the gateway will not forward to.

#### A home resolver, which also names the mesh

`--dns` takes an approved service by name, so the full-tunnel profile can use
your own resolver: ad blocking on the go, and **names for every service,
not just HTTP ones**. A resolver that runs on a node reads that node's
`/etc/hosts`, where the agent writes every service's name:

```sh
wireserve serve dns 53:53/udp 53:53/tcp     # on the node running the resolver
wireserve-admin approve-service homeserver dns
wireserve-admin export-config myphone --gateway vps1 --exit --dns dns --refresh --qr
```

`ssh backup.wg` and `jellyfin.wg:8096` then work from the phone while the
full tunnel is on. A domain set with `WIRESERVE_SERVICE_DOMAIN` works the same
way, and a resolver answering the mesh's names itself is not affected by
[rebinding protection](#if-the-name-resolves-on-one-network-but-not-another).

- **The resolver must pick up changes to `/etc/hosts`.** AdGuard Home
  (`dns.hostsfile_enabled`) does. dnsmasq, and so Pi-hole, read it at start
  and on `SIGHUP` only, so a service added later has no name until they
  reload. A path unit fixes that:

  ```ini
  # /etc/systemd/system/wireserve-hosts.path
  [Path]
  PathChanged=/etc/hosts
  [Install]
  WantedBy=multi-user.target

  # /etc/systemd/system/wireserve-hosts.service
  [Service]
  Type=oneshot
  ExecStart=/usr/local/bin/pihole reloaddns   # or: /usr/bin/pkill -HUP dnsmasq
  ```

- **A resolver in a container does not see the host's names.** The agent
  replaces `/etc/hosts` atomically, and a single bind-mounted file keeps
  showing the old copy. Run it on the host, or give up the names.
- **Let it answer the mesh, and nothing else.** Queries arrive on the node's
  mesh address from the phones' mesh addresses. Pi-hole's "allow only local
  requests" may refuse them, but "permit all origins" on a node with a public
  interface is an open resolver: bind to the mesh address instead.
- A resolver on a LAN appliance works through a
  [LAN mapping](#devices-on-the-nodes-network) (`serve dns
  53:192.168.1.2:53/udp`), but it has no names of the mesh's own.

#### The same names without the full tunnel

The mesh profile can name the resolver too, so every service has a name on
the phone whether or not the full tunnel is on:

```sh
wireserve-admin export-config myphone --gateway vps1 --dns dns --mesh-dns --refresh --qr
# with the exit as well:  ... --exit --dns dns --mesh-dns ...
```

This is a trade-off, which is why it is opt-in. The phone apps cannot send
only the mesh's names to a resolver: a `DNS =` line takes **all** of the
device's DNS while the tunnel is on. So the resolver has to answer
everything, as a Pi-hole or AdGuard Home does, and if it goes down, so does
the phone's DNS until you switch the tunnel off. It must also be on the mesh
(a service, or a node's own address): the mesh profile carries nothing else,
so a public resolver would be asked outside the tunnel and name nothing.

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
wireserve transit on   # on the node: willing to carry traffic for others
wireserve transit off  # stop — takes effect on the next poll, no rejoin

wireserve-admin approve-transit homeserver   # on the admin side: trusted to
wireserve-admin deny-transit homeserver      # withdraw it again
```

The admin half is there because of what a carrier can do. Unlike an
ordinary connection, which is end-to-end between the two nodes involved,
a carrier sees the mesh-layer plaintext of whatever pairs route through
it, and can send packets that appear to come from either end. What a node
says about itself (that it is willing, which peers it reaches) cannot be
verified, so without approval a single compromised node could offer to
carry every pair in the mesh. Until it is approved, `wireserve
list` on that node says `Transit: on, waiting for an admin to approve
this node as a carrier`. Revoking or rejoining a node withdraws its
approval, and `list-peers` shows who currently has one
(`transit=approved`).

`wireserve list` shows the outcome, both for a peer this node can't
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

On a node, talking to the local daemon over a Unix socket. `install`, `join`
and `daemon` need root; the others need only access to the socket, which
members of the `wireserve` group have (see "Using it without sudo"):

| Command | What it does |
| --- | --- |
| `wireserve install [url] [--instance name]` | installs the binary + systemd unit, then joins — one command, needs root. On a node that already joined, with no URL or token: upgrades and restarts the agents instead |
| `wireserve join [url] [token]` | one-time bootstrap, generates the keypair — prompts for either if omitted |
| `wireserve serve <name> <[public:][address:]target[/tcp\|/udp]>...` | publish a service on its own address — on this node, or on an address it reaches |
| `wireserve daemon --proxy caddy` | publish this mesh's 443 services as vhosts on the reverse proxy running here |
| `wireserve unserve <name>` | withdraw one |
| `wireserve transit on\|off` | opt in/out of carrying traffic for two other nodes that can't reach each other directly (also needs `approve-transit`) |
| `wireserve exit on\|off` | opt in/out of sending the internet traffic of devices exported with `--exit` through this node (also needs `transit on` and approval) |
| `wireserve list [--json]` | services (name, address, ports, owner, state), peers (with each one's route — direct or via a carrier) and anything not published, from the last poll |
| `wireserve leave` | tear down interface, firewall, hosts block |

On the coordinator host, as root:

| Command | What it does |
| --- | --- |
| `wireserve-coordinator install` | asks a few questions, then installs both binaries, the `wireserve-coordinator` user and the unit, and starts it. On a host where it is installed: upgrades and restarts instead |
| `wireserve-coordinator install --reconfigure` | asks again, with the current settings as defaults |

Against the admin port (loopback-only by default; run from the coordinator
host, or point `--coordinator-url`/`WIRESERVE_COORDINATOR_URL` at it from
anywhere that can reach it):

| Command | What it does |
| --- | --- |
| `wireserve-admin create-node <name>` | create a node, print a join token |
| `wireserve-admin export-config <name> [--gateway <node>] [--dns <svc\|ip> [--exit] [--mesh-dns]] [--refresh] [--qr]` | create (or re-issue) a static peer's `.conf`; `--exit` adds a full-tunnel profile, `--mesh-dns` names the resolver in the mesh profile too |
| `wireserve-admin list-peers` | the full directory |
| `wireserve-admin via-gateway <name> on\|off` | exported phones reach this node through their gateway, not directly |
| `wireserve-admin revoke <name>` | cut a node off, keep its name reserved |
| `wireserve-admin rejoin <name>` | fresh join token, same name and address; the old key stops working at once |
| `wireserve-admin delete-node <name>` | remove the record, free the name |
| `wireserve-admin clear-endpoint <name>` | drop a stale advertised endpoint |
| `wireserve-admin list-services [--pending]` | declared services and their approval state |
| `wireserve-admin approve-service <node> <svc> [--auth]` | let a declaration reach the mesh, behind the proxy's sign-in with `--auth` |
| `wireserve-admin service-auth <svc> on\|off` | publish a service behind the proxy's sign-in, admitting only the proxy |
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

At **runtime**, `wireserve` needs the `nft` binary (the `nftables`
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
needs host networking, or the mesh exists only inside that container. The
systemd unit also grants `CAP_CHOWN`, which it uses for one thing: handing
its socket to the `wireserve` group.

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
nothing is opened for outgoing traffic. Forwarded traffic is opened in two
narrow cases only. A transit-capable node gets
`iifname "wireserve0" oifname "wireserve0"` (mesh back into the mesh). A
node serving a device on its network gets `iifname "wireserve0"` and
`oifname "wireserve0"`, each with `ct mark & 0x01000000 == 0x01000000`
(iptables: `-m connmark --mark 0x1000000/0x1000000`), which matches only
connections the agent's own table rewrote to a declared target. The
firewalld guard gets the same exceptions ahead of its drop. The agent keeps it in
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
sudo wireserve install https://wireserve.example.com --instance work
wireserve --instance work serve git 3000     # no sudo needed once you are in the group
wireserve --instance work list
```

Or, by hand:

```sh
sudo wireserve --instance work join          # prompts, as above
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

Each instance's socket is shared with the `wireserve` group separately, by
that instance's own daemon, so one group covers all of them.

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
podman build -f deploy/docker/agent.Dockerfile -t wireserve-agent .   # the image runs /usr/local/bin/wireserve
podman builder prune --all   # if a build ever looks like it reused something stale
```
