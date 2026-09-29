# WireServe — v1 Design Spec

Minimal, self-hosted WireGuard mesh with a declared-service directory. No ACLs,
no relay, nothing fighting your existing DNS. One coordinator per net. CLI only.

---

## 1. Architecture

```
                 ┌────────────────────┐
   admin CLI ───▶│   coordinator      │◀─── agent poll (HTTPS, bearer token)
                 │  (Rust, axum,      │
                 │   SQLite)          │
                 └────────────────────┘
                          ▲
                          │ one-time join token (out of band)
                          │
                 ┌────────────────────┐
                 │   agent (Rust)     │
                 │  - defguard_wireguard_rs → kernel WG interface
                 │  - FirewallBackend → host firewall (nftables on Linux)
                 │  - /etc/hosts managed block
                 │  - local unix-socket state for `wireserve list`
                 └────────────────────┘
```

The coordinator never touches private key material and is not itself a WireGuard
peer. It is a plain HTTPS API sitting behind the operator's own reverse proxy.

---

## 2. Cargo workspace layout

```
wireserve/
├── Cargo.toml                 # workspace
├── crates/
│   ├── wireserve-types/       # shared structs, serde, shared between coordinator & agent
│   ├── wireserve-coordinator/ # axum + sqlite binary
│   ├── wireserve-agent/       # daemon + CLI; the binary is `wireserve`
│   └── wireserve-admin/       # separate CLI binary — distinct trust surface
│                               # (authward-delegated, not the agent's bearer
│                               # token), kept out of wireserve-agent so the
│                               # two auth paths can't blur together in code
├── deploy/
│   ├── systemd/
│   │   ├── wireserve-coordinator.service
│   │   └── wireserve-agent.service
│   ├── docker/
│   │   ├── coordinator.Dockerfile
│   │   └── agent.Dockerfile
│   └── quadlet/
│       ├── wireserve-coordinator.container
│       └── wireserve-agent.container
```

`wireserve-types` holds every struct in section 4 below, derives `Serialize`/
`Deserialize`, and is the single source of truth for the wire format — no
hand-duplicated structs on either side.

---

## 3. Data model (coordinator's SQLite)

```sql
CREATE TABLE nodes (
    id              INTEGER PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,       -- set at `wireserve-admin create-node`
    kind            TEXT NOT NULL DEFAULT 'agent'
                    CHECK (kind IN ('agent', 'static')),
                    -- 'static' = consumer-only peer (e.g. a phone via the
                    -- official WireGuard app) that never runs the agent,
                    -- never polls, and has no firewall/hosts-file sync
    pubkey          TEXT UNIQUE,                -- NULL until node completes registration
    ip4             TEXT UNIQUE,                -- e.g. 100.90.0.3
    ip6             TEXT UNIQUE,                -- ULA, e.g. fd00::3
    bearer_token_hash TEXT UNIQUE,              -- SHA256(token); plaintext never stored
                    -- issued even for 'static' kind for schema uniformity,
                    -- but never actually used — a static peer never polls
    join_token_hash TEXT UNIQUE,                -- one-time, NULL'd after redemption
    join_token_used BOOLEAN NOT NULL DEFAULT 0,
    endpoint_addr   TEXT,                       -- self-reported or observed, "host:port"
                    -- always NULL for 'static' kind — never dialed into,
                    -- only ever initiates
    listen_port     INTEGER,                    -- self-reported; required for
                    -- 'agent' kind, meaningless/omitted for 'static'
    revoked         BOOLEAN NOT NULL DEFAULT 0,
    revoked_at      TIMESTAMP,
    last_seen       TIMESTAMP,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE services (
    id          INTEGER PRIMARY KEY,
    node_id     INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    name        TEXT NOT NULL UNIQUE,           -- collision = reject at declare-time
    port        INTEGER NOT NULL,
    proto       TEXT NOT NULL CHECK (proto IN ('tcp', 'udp')),
    declared_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

`name` unique across the whole table (not per-node) — this is what makes the
"reject collisions" rule enforceable with a single constraint.

**On `bearer_token_hash`/`join_token_hash`: hashed, deliberately unsalted.**
Hashing defends against DB-at-rest leaks — a stray backup, a misconfigured
permission — turning a leaked credential into a useless digest, since the
coordinator only ever accepts the raw token and compares its hash. No
per-token salt is added on top, and that's intentional rather than an
oversight: salting exists to defeat rainbow tables and reuse patterns
against *low-entropy, human-chosen* secrets (passwords). These tokens are
CSPRNG-generated with ~256 bits of entropy, unique by construction — the
randomness already makes precomputation infeasible, so a salt adds
negligible real security. Plain `SHA256` (fast) is deliberate too, for the
same reason: slow KDFs like bcrypt/argon2 exist to make brute-forcing a
*small* guessable space expensive, which doesn't apply here and would just
cost CPU on every poll. This mirrors how GitHub/GitLab-style API tokens are
typically stored. A further hardening step, if ever wanted: HMAC with a
server-side pepper (`HMAC-SHA256(token, server_pepper)`, pepper kept out of
the DB, e.g. in coordinator config/env) — narrower in scope, defending
specifically against "DB leaks but config doesn't," not a gap in the
approach above.

**Naming rule (applies to both `nodes.name` and `services.name`):**
DNS-label-safe — lowercase alphanumeric and hyphens only, must start/end
with an alphanumeric, ≤63 characters. Enforced identically in three
places: the coordinator (on `/admin/nodes` and on `services` entries in
`/poll`), `wireserve-admin`'s own argument parsing (fail fast, don't round
trip to the server for an obvious violation), and implicitly relied on by
the agent's `/etc/hosts` writer (§6), which assumes every name it's given
is already a valid label. One validation function in `wireserve-types`,
called from all three places, rather than three separate regexes drifting
apart.

---

## 4. Wire API

All node-facing endpoints require `Authorization: Bearer <token>` except
`/register`. All admin endpoints are separate and CLI-only (no token reuse
between the two surfaces).

### 4.0 Admin authentication

`/admin/*` requires `Authorization: Bearer <admin_token>`, where
`admin_token` is a single static secret (`WIRESERVE_ADMIN_TOKEN`) — not
issued or stored per-request. By default the coordinator generates it
itself on first start (CSPRNG, same shape as `openssl rand -hex 32`) and
persists it alongside the database; an operator who sets the environment
variable explicitly overrides that unconditionally, for those who'd rather
manage the secret themselves out of band. Either way this is a hard
requirement for v1, not a later addition: the revoke endpoint (§4.4) is
meaningless if the admin surface itself isn't gated.

- Compared using a constant-time check (§7), same as every other token in
  this spec — no timing side-channel on the one credential that can revoke
  any node.
- **Loopback-only binding kept as a second, independent layer**: the
  coordinator's admin listener binds to loopback/an internal-only
  interface, never `0.0.0.0`, regardless of the token check. This isn't
  redundant with the token — it's defense against the token itself leaking
  (shell history, a misconfigured log line, a copy-pasted support message)
  by ensuring the admin surface still isn't reachable from outside the
  host/private network even if the secret does.
- **Single shared secret means no per-admin attribution.** With one static
  token, the audit log (§7) can record *that* an admin action happened,
  not *who* performed it — there's no concept of separate admin identities
  in this model. Worth stating plainly rather than implying more
  granularity than the design actually has. If per-admin attribution
  matters later, that's what an OIDC-backed admin layer (deferred, see
  below) would add — not something this static-token model can provide.

`wireserve-admin` reads the token from local config/env
(`WIRESERVE_ADMIN_TOKEN`) and sends it as a standard
`Authorization: Bearer <token>` header on every admin request — no
custom header name, no proxy-mediated identity headers, no second system
to stand up before the admin CLI works.

Node-facing endpoints (`/register`, `/poll`) are unaffected by this and
keep their own opaque bearer tokens as specified in §4.2–4.3 — a
completely separate credential from the admin token, never reused between
the two surfaces.

### 4.1 Admin: create node

```
POST /admin/nodes
{ "name": "homeserver" }

→ 201
{ "name": "homeserver", "join_token": "jtk_9f2c..." }
```

### 4.2 Node: register (redeem join token, once)

```
POST /register
{
  "join_token": "jtk_9f2c...",
  "pubkey": "base64 WG pubkey",
  "kind": "agent",                                // optional, default "agent"; "static" for §9
  "listen_port": 51820,                            // required for kind=agent, omitted for kind=static
  "endpoint_addr": "duckdns.example.com:51820"     // optional, self-reported; always absent for kind=static
}

→ 200
{
  "bearer_token": "brt_7a1e...",
  "ip4": "100.90.0.3",
  "ip6": "fd00:90::3"
}
```

Coordinator behavior: reject if token already used or unknown. If
`endpoint_addr` is absent, fall back to the request's observed source IP +
the reported `listen_port` as the initial endpoint candidate (kernel WG
roaming corrects this once traffic flows) — this fallback only applies to
`kind=agent`; a `kind=static` node's `endpoint_addr` simply stays NULL
forever, since it's never meant to be dialed into (§9).

### 4.3 Node: poll (push own state, pull full directory)

This single call both reports what changed locally and returns the current
mesh + service directory — this is the "services piggyback on the poll"
decision, not a separate fetch.

```
POST /poll
Authorization: Bearer brt_7a1e...
{
  "endpoint_addr": "duckdns.example.com:51820",   // may change (dynamic DNS etc.)
  "services": [
    { "name": "plex", "port": 32400, "proto": "tcp" }
  ]
}

→ 200
{
  "peers": [
    {
      "name": "homeserver",
      "pubkey": "...",
      "ip4": "100.90.0.3",
      "ip6": "fd00:90::3",
      "endpoint_addr": "duckdns.example.com:51820",
      "last_handshake": "2026-09-16T10:02:11Z"     // null = never / stale
    }
  ],
  "services": [
    {
      "name": "plex",
      "node": "homeserver",
      "ip4": "100.90.0.3",
      "port": 32400,
      "proto": "tcp",
      "online": true                                 // derived from last_handshake freshness
    }
  ]
}
```

Coordinator behavior on `services` in the request body: diff against current
DB state for that node, insert/delete rows accordingly, reject with `409` +
the conflicting name if a new entry collides with another node's service.

The agent poll loop is the single place that:
1. sends this request,
2. reconciles the returned `peers` against the local WireGuard interface (via `defguard_wireguard_rs`),
3. reconciles the returned `services` for *this node only* against the local `FirewallBackend`,
4. rewrites the `/etc/hosts` managed block,
5. writes the merged result to local state for `wireserve list` to read.

### 4.4 Admin: revoke node

```
POST /admin/nodes/{name}/revoke

→ 200
```

Effect, applied immediately in the DB: `revoked = 1`, `revoked_at` set,
`bearer_token_hash` cleared (any further `/poll` from this node now gets
`401`), and its rows in `services` cascade-deleted. The node record itself
is kept (not hard-deleted) so the name stays reserved and there's a
historical trail — pair with structured audit logging (§7).

**Propagation is bounded by the poll interval, not instant.** Every *other*
node stops seeing the revoked node in `peers` on its own next poll, at
which point its agent removes that WireGuard peer locally. Pick the poll
interval (e.g. 15–30s) with this latency in mind, and document it as a
known bound rather than implying immediate network-wide removal. For a
faster-than-that response during an active incident, pulling the machine
off the network at the host/firewall level is the honest fallback, not
something the coordinator can guarantee.

### 4.5 Admin: rejoin node

```
POST /admin/nodes/{name}/rejoin

→ 201
{ "name": "homeserver", "join_token": "jtk_a41f..." }
```

Issues a fresh one-time join token for an existing node record (typically
one that was just revoked, or whose key is suspected compromised but the
physical machine is still trusted) without freeing its name or IP. The
node re-registers with a new keypair via `/register` as normal, replacing
`pubkey` and `bearer_token_hash`; `revoked` clears back to `0` on
successful re-registration.

### 4.5.1 Admin: list peers

```
GET /admin/peers

→ 200
{
  "peers": [ /* same shape as the `peers` array in §4.3's /poll response */ ]
}
```

Read-only, authenticated the same way as every other `/admin/*` endpoint
(§4.0). Exists so `wireserve-admin` can render a full peer directory
without needing a running agent or a node's own bearer token to do it —
used by `export-config` (§9), and generally useful for any future
`wireserve-admin list-nodes`-style command.

### 4.6 Agent-local (not coordinator-facing)

```
wireserve serve <name> <port> [tcp|udp]   # queues a local declare, applied on next poll
wireserve unserve <name>                  # queues a local withdrawal
wireserve list                            # reads local cached state, no network call
wireserve leave                           # tears down interface, firewall, hosts block
```

`serve`/`unserve` talk to the running agent over a local Unix socket
(`/run/wireserve/agent.sock`), which is also what `list` reads from.

The socket is root-only (0600, in a 0700 directory) unless a `wireserve`
group exists when the daemon starts; then it is 0660 and 0750, owned by
that group, and its members can run every command above as themselves.
Membership means "operator of this node" (they can publish, withdraw and
`leave`, but approval still happens at the coordinator, and keys never
leave the root-only state file). `daemon`, `install` and `join` need root.
The binary is `wireserve`; the systemd unit remains `wireserve-agent`.

---

## 5. Firewall rule derivation

On every poll cycle, after reconciling WireGuard peers:

```rust
trait FirewallBackend {
    /// Replace the current WireGuard-interface ruleset with exactly these rules.
    /// Default-deny everything else on that interface.
    fn apply(&mut self, rules: &[ServiceRule]) -> Result<()>;
    fn teardown(&mut self) -> Result<()>;
}

struct ServiceRule {
    proto: Proto,   // Tcp | Udp
    port: u16,
    sources: Option<Vec<Ipv4Addr>>,   // None: every node (M36)
}
```

- `rules` = this node's own currently-declared services (from the `services`
  array in the request the agent just sent, not the coordinator's response —
  a node only ever firewalls itself).
- **Who may (M36)**: the coordinator's response narrows each rule to the
  addresses its grants name (`PollResponse.access`), matched per packet
  before the service address is rewritten, so a source left out meets the
  refusal of an unpublished port and loses an open connection at its next
  packet. It only ever narrows: a declared service with no access entry is
  not opened at all. A restricted terminated 443 whose access says `sign_in`
  is open to every node — its terminator decides (§6.1). The node's own
  clients are never filtered: they reach the backend directly anyway. A
  transit carrier can send with the addresses of the peers it carries, so a
  grant to a transited peer trusts its carrier.
- **Linux v1**: `NftablesBackend` via the `nft` binary's JSON API (one
  atomic `nft -j -f -` transaction per `apply()`), scoped to the WireGuard
  interface, default `DROP`. (Originally netlink via `rustables` with "no
  shelling out to `nft`"; reversed — see PLAN.md decisions log #69.)
- **Windows v1.1**: `WindowsFirewallBackend` implementing the same trait —
  backend swap only, no change to the sync logic that calls `apply()`.
- **Startup ordering**: `teardown()`-then-deny-all must run *before* the
  first successful `apply()` — the interface should never come up
  permissive-by-default while waiting on the first poll response.
- **Crash behavior**: if the agent process dies, the last-applied nftables
  state persists untouched (nftables state lives in the kernel, independent
  of the agent) — a dead agent leaves the node exactly as restricted as it
  last was, not open.

---

## 6. Hostname resolution — managed `/etc/hosts` block, not a resolver

Deliberate rejection of MagicDNS-style resolution: WireServe never becomes
the system resolver, never touches `resolv.conf`/systemd-resolved, and never
listens on port 53. Every other domain on the host resolves exactly as it
did before the agent existed — this is what avoids the DNSSEC-breaking
failure mode MagicDNS-style setups can hit (a resolver in the query path
that doesn't preserve validation for queries it forwards).

Instead, each poll cycle the agent writes a static, local lookup table:

- **Suffix**: every declared service gets a synthetic hostname
  `<service-name>.wg` (not `.local` — that's mDNS-reserved). Since service
  names are already unique across the net (enforced by the DB constraint in
  §3), these hostnames can't collide with each other.
- **Managed block**: entries are written between fixed markers so the sync
  can safely wipe-and-rewrite just that block on every poll, without
  touching anything else already in the file:

  ```
  # BEGIN WIRESERVE
  100.90.0.3 plex.wg
  100.90.0.5 homeassistant.wg
  # END WIRESERVE
  ```

- **Path per OS**: `/etc/hosts` on Linux/macOS/BSD,
  `C:\Windows\System32\drivers\etc\hosts` on Windows (same mechanism, no
  backend swap needed here — unlike WireGuard/firewall, hosts-file format
  and NSS priority behavior are effectively identical across platforms).
- **Privilege**: no new privilege required — the agent already runs with
  the elevation needed to manage the WireGuard interface.
- **Scope of what this solves**: resolves `<name>.wg` → node IP only. It does
  *not* encode the port — `wireserve list` (or the person's own memory/notes)
  is still how the port is known. This is a deliberate non-goal, not a gap:
  a scoped stub resolver was considered and rejected specifically because it
  reintroduces the "resolver in the query path" problem this design exists
  to avoid.

### 6.1 Real names, public records and TLS on each node (M25, M32–M34)

`.wg` solves naming for anything that runs the agent and for nothing else,
which is the whole of the problem a phone has. An optional mesh-wide domain
(`WIRESERVE_SERVICE_DOMAIN`) **replaces** the suffix rather than
supplementing it: `<name>.int.example.com` instead of `<name>.wg`. Two
working names would give an application two base URLs, and anything with a
single configured one — `ROOT_URL`, `root_url`, an OIDC `redirect_uri` —
then emits redirects and sets cookies that bounce between them. One service,
one name, and it points at the service's own address from everywhere.

**Public records, written by the coordinator (M32).** With a DNS provider
configured (`WIRESERVE_DNS_PROVIDER`: RFC 2136, Cloudflare, deSEC, Hetzner or
Porkbun), the coordinator keeps one A record per approved service — the rule
is one function in `wireserve-types`, used by the agents' hosts files and the
coordinator alike, so the two cannot disagree. It is a reconcile loop, never
part of a request: a provider outage costs a warning and a retry. It deletes
only records listed in its own `dns_records` table and replaces a clashing
record at a service's name, so the service domain is the coordinator's to
manage. A changed address is written only after it has held for 20 seconds.
The credential lives in `coordinator.env`, never in the database.

This does not walk back §6. WireServe still never listens on 53, never
touches `resolv.conf`, and never enters anyone's query path: a phone's name
resolution is ordinary public DNS.

**TLS on the service's own node (M33).** Publishing TCP 443 is the opt-in —
an existing field, so an SSH or Postgres service never acquires a
certificate nobody asked for. Such a service is served with HTTPS by
`wireserve tls-serve` on its owner node, as its own user with no
capability, on the service address, which the agent routes to the host
itself (`local` route, protocol 247). The terminator listens on an
unprivileged port of every address (11443 by default, M35), held by
`wireserve-tls.socket` so no other local user can take it, and tells its
services apart by the address a connection arrived on; the agent rewrites
the service address's 443 to that port, marked like any other mapping, so
the existing accept and host-firewall openings cover it, leaving 443 free
for other software on the host. It drops the address, and the port, from
any interface but the mesh and loopback. The terminator holds the private
key; the coordinator, holding the DNS credential, publishes the DNS-01
challenge for the owner's own approved names only (`/tls/challenge`). A
service is `terminated` in the directory only while its owner reports it
ready. The terminator talks to the agent over a second socket that decodes
nothing but a check-in and a challenge request, and tells the backend who is
calling (`X-Wireserve-Node`, `X-Forwarded-For`), removing any copies a client
sent.

**Who can reach what (M36), and the sign-in (M34).** Every service is in
one or more service groups — its explicit ones, stored per *name* outside the
service rows so a withdraw and re-declare cannot quietly drop one, or else
the built-in `default`. A grant lets a source reach every service in a group:
`everyone`, `tag:<tag>` (an admin's node tag) or `oidc:<group>` (an identity
provider's group, proven by signing in). A fresh mesh has `everyone → default`,
so nothing is restricted until an admin restricts it. Only the admin changes
groups, grants and tags; a declaration's `group` becomes membership once, when
a new name is first approved, and a declaration naming a group that does not
exist is not published. The coordinator computes each service's access —
open, or the granted nodes' addresses (always with its owner's), whether the
sign-in applies and with which groups — and sends it to the service's owner
alone (`PollResponse.access`), which enforces it: see §5, and the terminator
below.

A terminated service's terminator checks every request, not every
connection: an open service, or a caller whose address the access names,
goes on. Anyone else, where a grant names an `oidc:` group and a provider is
configured (`WIRESERVE_AUTH_SERVICE` on `WIRESERVE_AUTH_NODE`, trusted on
that node only), is asked about — Caddy's `forward_auth`, built in: a
headers-only copy of the request to `https://<provider>.<domain>/verify` on
the provider's own address, verified TLS, with `X-Forwarded-Method`,
`X-Forwarded-Uri`, the service's own name as `X-Forwarded-Host` (`Host` is
the provider's, whose own terminator answers for that name only) and the
calling device's mesh address as the single `X-Forwarded-For` value — a request
whose `Host` names another service gets 421 first. A 2xx says who
it is; one of the granted groups in its groups header passes the request on
with the identity headers copied on, anything else is 403. A 401 with
`X-Login-Url` redirects a GET; anything else is returned as is. The provider
authenticates; the grants authorize. A 2xx naming a user is reused while the
provider's `Cache-Control: max-age` allows, keyed by the hashed values of its
`Vary` headers, which must include the cookie or `Authorization` (M37);
`stale-if-error` covers a provider that is down. Everyone else gets 403. The identity
headers (`WIRESERVE_AUTH_{USER,EMAIL,GROUPS}_HEADER`) are removed from every
request on every service, and the provider's domain-wide session cookie from
every request but the provider's own. The provider's own service is always
open and cannot be put in a group.

**Device owners (M38).** With an identity provider configured
(`WIRESERVE_OIDC_*`), a node may belong to a person, whose groups then count
among its principals (`oidc:<group>`) for every protocol. Only an admin makes
a claim link (`POST /admin/nodes/{name}/claim`, also handed out by
`create-node`): single-use, ten minutes, stored hashed. The coordinator runs
the code flow with PKCE (`/claim/{code}`, `/claim/callback`), checks the ID
token and its nonce, and binds the owner only after the person confirms on a
page naming the node, its tags and its current owner (`POST /claim/confirm`,
which uses the link up atomically). Flow state is in memory, bound to the
browser by a cookie; the pages forbid framing, scripts and caching. The owner's
refresh token is sealed (XChaCha20-Poly1305, key in `coordinator-secrets.env`,
the node as associated data) and exchanged every refresh interval for current
groups: `invalid_grant` ends the ownership, other failures leave the groups
counting for an hour. Revoke and rejoin clear the owner. A node with
terminated services also gets `PollResponse.identities` — the owners of the
devices allowed in — and its terminator names them to backends in the
identity headers.

### 6.2 A resolver in a full tunnel (M27)

A phone's `DNS =` line captures every query the phone makes (PLAN.md #104),
which is why the mesh profile of §9 has none. The full-tunnel profile of
§9 changes that premise rather than contradicting it: every packet already
goes through the gateway, so every query going to one resolver is the point,
not a side effect. That resolver is the operator's own — a Pi-hole or
AdGuard Home published as an ordinary service, or a public one — and
WireServe still never listens on 53 or runs one. A resolver that runs on a
node reads that node's `/etc/hosts`, so it answers every service's name,
including the non-HTTP ones §6.1 leaves nameless on a phone.

M28 lets the *mesh* profile name the same resolver, opt-in (`--mesh-dns`).
What #104 ruled out was a resolver answering only the mesh's names, which
would break everything else once it captured all of the phone's DNS. A full
resolver on the mesh answers everything, so capturing it all is correct — the
shape MagicDNS has too. The cost is that the phone's DNS depends on that
resolver while the tunnel is up, which is why it is the operator's choice
and never a default, and why the resolver must be on the mesh: the mesh
profile routes nothing else, so any other would be asked outside the tunnel.

## 7. Security requirements (v1, non-negotiable)

These are treated as core requirements, not hardening to add later:

- **Admin auth exists from day one** (§4.0) — a self-issued static bearer
  token, constant-time compared, plus loopback-only binding as an
  independent second layer. No admin endpoint ships reachable without
  both in place.
- **Bearer and join tokens stored hashed** (`SHA256`) in SQLite, never
  plaintext — a leaked DB should require rotating exposed secrets, not
  hand over every node's identity at once.
- **Constant-time comparison** on all token checks (e.g. the `subtle`
  crate), to close timing side-channels on the auth path.
- **All external paths to the coordinator are TLS-terminated at the
  reverse proxy — the coordinator itself never holds a certificate or
  speaks TLS.** (Service certificates, M33, are held by each owner node's
  terminator; the coordinator only publishes their challenge records.) It
  listens on plain HTTP, on an address only the proxy can reach (loopback, or an internal Docker network — same principle as the
  admin listener in §4.0), and the proxy forwards plain HTTP internally
  after terminating TLS. What's required is that this is the *only* path
  in: the coordinator's plain-HTTP listener must never be directly
  reachable from an untrusted network (the open internet, an untrusted
  LAN) — bearer tokens are long-lived passwords in transit, so a
  misconfiguration that exposes the coordinator's HTTP port directly
  bypasses TLS entirely, not just for the operator's convenience but for
  every node's credential.
- **Basic rate limiting** on `/register` and on failed-auth responses from
  any endpoint — join and bearer tokens are the entire trust boundary, so
  brute-forcing them shouldn't be free.
- **Minimal structured audit log** (`tracing` to stdout is sufficient, no
  separate audit table needed) for: node creation, registration, revoke,
  rejoin, and service declare/withdraw. Cheap to add now, and it's the
  first thing anyone investigating a suspected compromise will want.
- **Local state file permissions**: bearer token, WireGuard private key,
  and agent state on the node's own disk are root-only readable (mode
  `600`), not merely relying on directory permissions.

## 8. Deployment

- **systemd**: both binaries ship a `.service` unit; agent unit requests
  `CAP_NET_ADMIN` and access to `/dev/net/tun`, not full root where avoidable.
- **Docker**: `--cap-add=NET_ADMIN --device /dev/net/tun`, not `--privileged`.
- **Quadlet**: thin declarative wrapper around the same capability set —
  written once both the systemd and Docker paths exist, so they can't drift.

---

## 9. Static peers (any device that only consumes services)

Not every peer needs to run the agent. A laptop, desktop, or phone that
only wants to *reach* declared services — never host one itself, never
need firewall or hosts-file sync — doesn't need `wireserve` at all.
`wireserve-admin` generates a standard WireGuard `.conf` for import into
whatever official WireGuard client fits the device (Windows/macOS/Linux
desktop app, or the Android/iOS app; import by file or QR scan). No native
app, no new protocol, and it's the same `kind: 'static'` node type from §3
regardless of which device it ends up on.

```
wireserve-admin export-config <name> [--out <path>]
```

What it does, end to end:

1. Generates a WireGuard keypair **locally, in `wireserve-admin`'s own
   process** — never transmitted anywhere. Same invariant as every other
   node: the coordinator only ever sees the public key.
2. Creates the node record (`POST /admin/nodes`, `kind: "static"`) and
   immediately redeems the resulting join token itself, via `/register`,
   submitting the generated pubkey with `listen_port`/`endpoint_addr`
   omitted. This collapses "create node" + "join" into one CLI call,
   since there's no separate agent process to run `wireserve join` the
   way a normal node would.
3. Calls `GET /admin/peers` (§4.5.1) to fetch the current full peer
   directory.
4. Renders a `.conf` with one `[Peer]` block per existing node:

   ```ini
   [Interface]
   PrivateKey = <generated locally, step 1>
   Address = 100.90.0.7/32, fd00:90::7/128

   [Peer]                                  # one block per node in the net
   PublicKey = <that node's pubkey>
   AllowedIPs = 100.90.0.3/32, fd00:90::3/128
   Endpoint = duckdns.example.com:51820    # omitted if that node's endpoint_addr is NULL
   PersistentKeepalive = 25                # this device likely roams networks/NAT
                                            # (wifi/cellular switching, laptop suspend) —
                                            # keep the mapping alive so return traffic
                                            # works, same mechanism as the NAT discussion
                                            # earlier in this spec
   ```

   Each peer gets its own `/32` + `/128`, and by default not the mesh's
   full CIDR on any block: a whole-mesh block means some node is acting as
   a router for the others, which v1 did not want.

   **Correction (M24).** This paragraph used to say WireGuard "requires
   non-overlapping `AllowedIPs` across peers on one interface." That is
   true only of *identical* prefixes — assign `10.1.0.5/32` to two peers
   and the later one takes it, leaving the first with `(none)`. Prefixes of
   *different* lengths coexist: cryptokey routing is a longest-prefix-match
   trie, so a peer holding `10.1.0.0/24` and another holding `10.1.0.5/32`
   both keep their entries, and the /32 wins for that one address.
   Kernel-verified, not inferred. The router objection stands on its own
   and is what M24's gateway makes deliberate and opt-in; the claim about
   what WireGuard permits was simply wrong.

   Note the corollary, which the gateway design turns on: WireGuard has no
   failover. The longest matching prefix wins whether or not that peer is
   reachable, so a /32 pointing at a dead path black-holes rather than
   falling through to a covering route.

5. Writes the file (or prints it) for the operator to transfer to the
   device — or renders a QR code to the terminal with `--qr` (M24; v1
   deferred this to any external tool fed the `.conf`). The limit there is
   terminal *width*, not QR capacity: a code is `4·version + 17` modules
   square plus a quiet zone, and half-blocks only halve the vertical
   extent, so a config well inside the 2953-byte byte-mode ceiling would
   still need ~185 columns and scan off nothing. `--qr` refuses past 116
   columns and points at `--out`.

**Consequences of this shape, stated plainly:**

- **No `<name>.wg` resolution on unrooted mobile clients.** A desktop/
  laptop agent-less client *can* usually still get a hosts-file entry
  added manually by the operator if they want it — nothing stops that —
  but there's no automated sync for a `kind: 'static'` peer regardless of
  device, since §6's managed block is written by the agent, and static
  peers don't run one. On Android/iOS specifically, the OS doesn't allow
  it at all. Either way, IP:port is the guaranteed baseline — exactly the
  "IP+port is enough" premise from the very first version of this design.
- **Staleness was accepted for v1, and is fixed in M24 by a gateway.**
  The config is a snapshot: listing every peer individually means a node
  joining later is unroutable from the device until `export-config` is
  re-run and reimported. Assigning a gateway routes the whole mesh range
  to one peer instead, so anything new is reachable without re-exporting.
  Nodes that are reachable from anywhere keep their own direct entry.

  Gateway forwarding is transit forwarding (M23) and is gated on the same
  approval, for the same reason — the carrier sees the traffic in the
  clear. There is no separate gateway flag.

  Two things about this are load-bearing and easy to get wrong. The
  coordinator must set `transit_via` on the device for **exactly** the
  peers absent from its config: `wg::desired_peers` deletes a transited
  peer's entry rather than merely hinting a route, so naming a peer that
  *is* in the config makes that peer drop the device while the device
  still dials it — a black hole, given no failover. And config membership
  must be **recorded at export time**, not recomputed from live endpoint
  state, because the file is a snapshot and the two would drift. The
  direction that bites is a node that gains a routable endpoint after
  export: recomputing would stop routing it through the gateway while the
  device still has no direct entry for it, breaking that path both ways.

- **A full-tunnel profile, with the gateway as the exit** (M27,
  `--exit`). Rendered in the same export as the mesh profile — one keypair,
  since a second export would rotate it — with the gateway's `AllowedIPs`
  widened to `0.0.0.0/0, ::/0` and a `DNS =` line (§6.2). The direct peers
  keep their /32s, which outrank the default route, so the mesh stays as
  direct as before. Two consents, like transit: the gateway's own `exit on`,
  and the admin's export, recorded per export like config membership since
  it describes the files on the device. The gateway forwards only new flows
  from its exit clients to public IPv4 destinations, marks them with a
  conntrack bit of their own, masquerades them, and guards the egress
  interface's forwarding switch the way a LAN target's is guarded. IPv6 is
  captured, so nothing leaks around the tunnel, and dropped: forwarding it
  would need NAT66 and a per-interface switch only Linux 6.17 has.

- **Re-issuing a config keeps the device's name and address** (M24,
  `--refresh`): `reissue_join_token` preserves `ip4`/`ip6` and `/register`
  reuses them, so only the keypair changes. `rejoin` checks the node's
  `kind` *before* mutating, since it nulls the pubkey and a mismatch
  discovered at `/register` would already have dropped a live agent node
  out of every other node's directory.
- **Losing the device reuses revoke exactly as-is (§4.4).** A `kind:
  "static"` node is still just a row in `nodes` — `POST
  /admin/nodes/{name}/revoke` cuts it off the same way it would any
  compromised agent-running node. No new mechanism needed for "I lost my
  laptop/phone."

## Open items intentionally deferred (not v1)

- Windows/BSD firewall backends (trait exists now, implementations later)
- Multi-tenant coordinator, web UI
- OIDC-backed admin auth with per-admin attribution (e.g. delegating to
  authward, revisited later) — v1 uses a single shared static admin token
  (§4.0), which is enough for a single operator but doesn't distinguish
  between multiple admins
- STUN, relay/hairpin fallback for symmetric NAT
- ~~Reverse-proxy auto-publish integration~~ — built in M25, replaced in
  M33–M34 by TLS on each service's own node, see §6.1
