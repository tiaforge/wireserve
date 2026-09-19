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
│   ├── wireserve-agent/       # daemon + CLI binary (serve/unserve/list/leave)
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
}
```

- `rules` = this node's own currently-declared services (from the `services`
  array in the request the agent just sent, not the coordinator's response —
  a node only ever firewalls itself).
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
  speaks TLS.** It listens on plain HTTP, on an address only the proxy can
  reach (loopback, or an internal Docker network — same principle as the
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
need firewall or hosts-file sync — doesn't need `wireserve-agent` at all.
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

   Each peer gets its own `/32` + `/128`, not the mesh's full CIDR on one
   block — WireGuard requires non-overlapping `AllowedIPs` across peers on
   one interface, and a single "whole mesh" block would mean this peer is
   acting as a router for the others, which isn't the goal here.

5. Writes the file (or prints it) for the operator to transfer to the
   device — by QR code for mobile, or just copying the file for
   desktop/laptop clients, whichever's easiest; generating a QR code isn't
   part of v1 scope, any external tool fed the `.conf` contents works fine.

**Consequences of this shape, stated plainly:**

- **No `<name>.wg` resolution on unrooted mobile clients.** A desktop/
  laptop agent-less client *can* usually still get a hosts-file entry
  added manually by the operator if they want it — nothing stops that —
  but there's no automated sync for a `kind: 'static'` peer regardless of
  device, since §6's managed block is written by the agent, and static
  peers don't run one. On Android/iOS specifically, the OS doesn't allow
  it at all. Either way, IP:port is the guaranteed baseline — exactly the
  "IP+port is enough" premise from the very first version of this design.
- **Staleness is accepted for v1.** The config is a snapshot; new nodes
  joining later don't appear on a static peer until `export-config` is
  re-run and reimported. No live sync for static peers in v1.
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
- Reverse-proxy auto-publish integration
