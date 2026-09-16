# WireServe — Implementation Status

Living status document. Update the checkboxes and the "Currently working on"
line as part of the commit that makes progress, so work can pause and
resume across sessions without re-deriving context. Full design is in
`wireserve-design-spec.md`; the detailed step-by-step plan that produced
this checklist lives in the session that created it — this file is the
source of truth for *current status*, the spec is the source of truth for
*requirements*.

**Currently working on:** Milestone 6 — deployment artifacts

## Milestones

- [x] **M0 — Workspace scaffolding**: Cargo workspace, per-crate stub
      crates, `.gitignore`, `rust-toolchain.toml`, empty `deploy/` tree,
      this file.
- [x] **M1 — `wireserve-types`**: shared wire structs (§4), the single
      `is_valid_dns_label` validator (§3), `FirewallBackend`/`ServiceRule`
      (§5), token hashing helper. 24 unit tests, `cargo clippy` clean.
- [x] **M2 — `wireserve-coordinator`**: SQLite schema + migrations, IP
      allocation, `/register`, `/poll`, `/admin/*` routes, two separate
      listeners (node-facing vs admin), rate limiting, audit logging.
      43 tests (31 unit + 12 integration), `cargo clippy -D warnings` clean.
- [x] **M3 — `wireserve-agent`**: poll loop, WireGuard reconciliation
      (`defguard_wireguard_rs`), nftables firewall backend (`rustables`,
      behind a default-on `nftables` feature — see decisions log #15),
      `/etc/hosts` managed block, Unix-socket IPC for
      `serve`/`unserve`/`list`/`leave`, join/bootstrap command. 36 unit
      tests, clippy clean. `firewall/nftables.rs`'s real `rustables` calls
      are verified against the crate's own source/examples but NOT by a
      compile in this sandbox (missing system `libclang`) — worth a real
      build/test on a dev machine with `clang` installed before trusting
      it in production.
- [x] **M4 — `wireserve-admin`**: `create-node`, `revoke`, `rejoin`,
      `list-peers`, `export-config` (§9). 19 tests (14 unit + 5 integration
      against a real mock-HTTP-server coordinator), clippy clean.
- [x] **M5 — Security hardening review pass**: verified constant-time
      admin-token comparison, admin-listener bind enforcement, mode-600
      file handling (agent state/socket + newly added coordinator DB),
      rate limiting on all failed-auth paths, and all six audit events —
      all confirmed already in place from M2–M4. Two additions: coordinator
      DB file now hardened to mode 600 on open, and a startup warning logs
      when the node-facing listener isn't loopback/private (see decisions
      log #23-24 for why it's a warning, not a hard restriction, here).
- [ ] **M6 — Deployment artifacts**: systemd units, Dockerfiles, Quadlet
      files.
- [ ] **Final end-to-end verification**: manual/scripted smoke test across
      two agents + one coordinator (see spec verification notes).

Security-sensitive paths (tokens, auth, firewall default-deny, file
permissions) get test coverage inline with each milestone that introduces
them, not deferred to a final pass — see each milestone's commit for its
test additions.

## Decisions log

Spec leaves some things unspecified; resolved here so implementation
doesn't stall or drift:

1. **Token encoding**: 32 CSPRNG bytes, hex-encoded, after the `jtk_`/`brt_`
   prefix. `WIRESERVE_ADMIN_TOKEN` format is operator-chosen (spec
   suggests `openssl rand -hex 32`), compared as opaque bytes either way.
2. **Mesh addressing**: default `100.90.0.0/24` (v4) / `fd00:90::/64`
   (v6), both configurable via coordinator env
   (`WIRESERVE_NET_V4_CIDR` / `WIRESERVE_NET_V6_PREFIX`); first-free-slot
   allocation, `.0`/`.1` network address reserved.
3. **`online` / `last_handshake` derivation**: the coordinator is
   explicitly never a WireGuard peer and never touches WG state, so it
   cannot observe real handshake times without a wire-schema change the
   spec doesn't define. Decision: use the coordinator's own `last_seen`
   (updated on every successful `/poll`) as the `last_handshake` value,
   with `online` = `now - last_seen < WIRESERVE_ONLINE_THRESHOLD_SECS`
   (default 180s). Documented as a deliberate approximation, not a true
   WireGuard handshake observation.
4. **Unix socket protocol (agent-local, §4.6)**: newline-delimited JSON,
   one request/response per connection.
5. **Agent bootstrap command**: `wireserve-agent join <coordinator-url>
   <join-token>` (name not given in spec's §4.6 list, which only covers
   post-join usage).
6. **Migrations**: `rusqlite_migration` from day one, even though v1 has
   only one migration.
7. **Rate limiting**: hand-rolled in-process sliding window keyed by
   source IP, no external dependency.
8. **Keypair generation**: both `wireserve-agent` and `wireserve-admin`
   use `defguard_wireguard_rs::key::Key::generate()` /
   `.public_key()` (confirmed real API — wraps `x25519-dalek`
   internally) for WireGuard keypairs, rather than a separate keygen
   dependency, so the two sides can never disagree on key encoding.
9. **`rustables` is GPLv3-licensed.** The spec names it explicitly (§5,
   "netlink, no shelling out to `nft`"), so this is a spec directive, not
   a choice made here — but it's worth flagging plainly: linking it into
   `wireserve-agent` means that binary's distribution terms are
   effectively governed by GPLv3, which may affect the license the
   `wireserve-agent` crate/binary ships under (this doesn't affect
   `wireserve-coordinator`/`wireserve-admin`, which don't depend on it).
10. **Build-time system requirement**: `rustables` uses `bindgen` against
    Linux kernel netfilter headers, which requires `clang`/`libclang` at
    build time (but no `libnftnl`/`libmnl` runtime linking — it talks to
    netlink directly). Document this as a build prerequisite for anyone
    building `wireserve-agent` from source.
11. **`RegisterRequest.kind` vs. the node's kind at creation time**: the
    node's `kind` is fixed at `POST /admin/nodes` and treated as
    authoritative; `/register` 400s if the request's `kind` doesn't match
    it, rather than letting a register call silently change a node's kind.
12. **`/poll`'s `peers` array includes the polling node's own entry** —
    spec's example doesn't clarify either way; including self is simpler
    and harmless.
13. **Rate limiting is consulted only on failure paths**: bad/unknown join
    token on `/register`, bad admin token, bad/revoked bearer token —
    never on successful requests, so legitimate high-frequency polling is
    never throttled by it.
14. **Admin token comparison hashes both sides first** (`SHA256` then
    `subtle::ConstantTimeEq` on the digests) rather than comparing raw
    token bytes directly, to avoid a length-based timing signal when
    candidate and real token lengths differ.
15. **`rustables` is an optional Cargo feature (`nftables`), default-on.**
    Purely so `wireserve-agent`'s non-firewall logic (poll loop, hosts
    writer, IPC, state, WireGuard peer diffing) can be built/tested in an
    environment lacking `rustables`' build-time `libclang` dependency. A
    normal `cargo build -p wireserve-agent` still pulls in the real
    backend by default — `--no-default-features` is a dev/CI-only escape
    hatch, never a supported production configuration, and falls back to
    a `NoopFirewall` that logs a loud warning rather than silently
    skipping firewall enforcement.
16. **Agent-local IPC JSON shape**: internally-tagged enums —
    `{"op": "...", ...fields}` for requests, `{"status": "...", ...fields}`
    for responses (serde's `#[serde(tag = "...")]`) — a concrete schema
    the spec doesn't specify beyond "newline-delimited JSON."
17. **`wireserve list`'s local/remote distinction**: a service queued via
    `serve` but not yet confirmed by a poll still shows up immediately
    (marked not-yet-online), rather than being invisible until the next
    successful poll — so a just-issued `serve` doesn't look like it
    silently failed.
18. **`leave` over IPC acknowledges immediately and signals the daemon's
    main loop to tear down asynchronously** afterwards, rather than
    blocking the IPC response on WireGuard/firewall teardown completing
    (which depends on netlink/kernel timing the IPC handler shouldn't be
    stuck waiting on).
19. **A node's own `endpoint_addr`, set at `join` time, is persisted in
    local agent state and resent on every `/poll`** (not just the initial
    `/register`) — spec §4.3 explicitly models this field as something
    that "may change (dynamic DNS etc.)" and resendable per cycle; without
    persisting it, the agent would have no way to report anything but
    `None` after the first registration.
20. **`wireserve-admin`'s admin-token/config resolution precedence**:
    `--admin-token` CLI flag > `WIRESERVE_ADMIN_TOKEN` env > a plain
    trimmed-text token file (`WIRESERVE_ADMIN_TOKEN_FILE` env, default
    `~/.config/wireserve-admin/admin_token`) — no structured TOML/YAML
    config, since there's exactly one secret to store. Same precedence
    shape for `--coordinator-url` / `WIRESERVE_COORDINATOR_URL`.
21. **`export-config`'s self-exclusion from its own peer list** is done by
    comparing pubkeys (skip any `/admin/peers` entry matching the
    just-generated key), defensively handling either timing outcome of
    whether the newly-registered static node already appears in that
    directory by the time it's fetched.
22. **`wireserve-admin list-peers` output format**: one tab-separated line
    per peer (`name  pubkey  ip4  ip6  endpoint=...`) — spec only says
    "render," no format specified.
23. **Coordinator SQLite file hardened to mode 600 on every `open()`**
    (added during the M5 review pass). Not spec-mandated — §7's mode-600
    requirement is explicitly scoped to "the node's own disk" (the
    agent), and the DB only ever holds *hashed* tokens by design — but a
    cheap second layer for pubkeys/IPs/hashed-credential metadata against
    other local users on a shared host.
24. **Node-facing listener bind address is intentionally NOT
    hard-restricted to loopback/private the way the admin listener is.**
    Spec frames the admin listener's restriction as a hard, code-level
    invariant regardless of deployment topology (§4.0), but frames the
    node-facing listener's safety as depending on deployment topology
    (§7: "an address only the proxy can reach... loopback, or an internal
    Docker network") — a `0.0.0.0` bind is the *correct* choice inside an
    isolated Docker network where the reverse-proxy container reaches it
    over the bridge network rather than loopback, so hard-coding a
    loopback-only check here would break that legitimate topology.
    Instead (M5 addition): the coordinator logs a `tracing::warn!` at
    startup whenever this listener isn't bound to a loopback/private
    address, naming the §7 requirement explicitly, so the unsafe case is
    loud rather than silent — without breaking the safe containerized
    default.
