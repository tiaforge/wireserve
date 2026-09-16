# WireServe — Implementation Status

Living status document. Update the checkboxes and the "Currently working on"
line as part of the commit that makes progress, so work can pause and
resume across sessions without re-deriving context. Full design is in
`wireserve-design-spec.md`; the detailed step-by-step plan that produced
this checklist lives in the session that created it — this file is the
source of truth for *current status*, the spec is the source of truth for
*requirements*.

**Currently working on:** nothing open — all milestones complete, including
the independent security review remediation (M7) and a real, reproducible
end-to-end test (`deploy/e2e/run-e2e-test.sh`). 169 tests passing across
`cargo test --workspace` (agent tested with `--no-default-features`
locally; the real `nftables` feature is exercised by the E2E script's own
container builds, which also passed in full).

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
      tests, clippy clean. **Update from M6**: the real `rustables`
      backend has since been compiled and tested for real (via a Podman
      build container with `clang` installed — see M6) and a genuine
      type-mismatch bug in `firewall/nftables.rs` (`Table::get_name()`
      returns `Option<&String>`, not `Option<&str>`) was found and fixed
      there. No longer an open caveat.
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
- [x] **M6 — Deployment artifacts**: systemd units (verified with
      `systemd-analyze verify`), Dockerfiles, Quadlet files (verified by
      actually running Podman's quadlet generator, confirming the exact
      `podman run` invocation each produces matches the intended
      capability set). Both Dockerfiles were **actually built and run**
      with Podman, not just written — see decisions log #25-27 for two
      real bugs this caught (missing `ca-certificates` in the coordinator
      image, and the M3 nftables type-mismatch above) plus a full
      create-node → register → poll → list-peers → export-config →
      revoke smoke test against a live containerized coordinator.
- [x] **Final end-to-end verification**: resolved. Rootless Podman
      containers get `CAP_NET_ADMIN` scoped to their own network
      namespace via `--cap-add`, which turned out to be sufficient —
      unlike the bare host shell (which genuinely has an empty effective
      capability set, confirmed via `capsh --print`). A real two-agent
      mesh test now runs via `deploy/e2e/run-e2e-test.sh`, committed to
      the repo so it's reproducible in later sessions rather than
      redone by hand. It exercises real kernel WireGuard interfaces,
      real nftables rules, and a live coordinator, and is what actually
      found the M7 bugs below — none of which any unit/integration test
      in M1–M6 could have caught, since they only manifest once real
      netlink/kernel state is involved.
- [x] **M7 — Independent security review remediation**: a full external
      review of the codebase (not written by whoever implemented M1–M6)
      found 8 security findings (S2–S8, wireserve-agent §7.4/§4.5,
      wireserve-coordinator/admin) and 9 functional gaps against spec
      (F1–F9). All fixed except where explicitly noted otherwise below;
      see decisions log #29+ for exact reasoning per finding, especially
      where a fix deliberately narrows or reframes the reviewer's
      literal suggestion. Highlights:
      - **S2 (config injection into static peers' `.conf` files)** — the
        most serious finding: an unvalidated `endpoint_addr`/`pubkey`
        from any bearer-token holder could smuggle extra `.conf`
        directives (e.g. `AllowedIPs = 0.0.0.0/0`) into every static
        peer's exported config. Fixed with real validation
        (`is_valid_wg_pubkey`, `is_valid_endpoint_addr`) at the
        coordinator plus defense-in-depth newline rejection in the
        renderer and `list-peers` output.
      - **F1 (`wireserve list` was completely broken)** — the poll loop
        and the IPC server held two separate `AgentState` copies that
        never resynchronized; `list` always showed stale/empty data.
        Fixed and directly confirmed by the E2E script's own dedicated
        check.
      - **F6 (roaming defeated)** — `configure_peer` was called for
        every peer on every poll cycle, resetting WireGuard's own
        kernel-level endpoint-roaming correction (spec §4.2 relies on
        this) every ~20s. Fixed with a real diff (`peers_to_configure`)
        against last-applied state.
      - **F4 (rejoin reallocated IPs)**, **F7 (wrong status codes)**,
        **S8 (rejoin left the old bearer live)** — all direct spec
        conformance bugs, fixed and covered by new coordinator
        integration tests.
      - **F3 (one colliding service name wedged the whole agent
        forever)** — fixed via a structured `409` (`ErrorBody.
        conflicting_service`) the agent uses to quarantine exactly the
        offending declaration rather than resending it forever.
      - **F2 (`leave` incomplete)**, **F9 (revoked node never noticed)**
        — `leave` now also removes the hosts-file block and IPC socket
        and resets local state; a `401` from `/poll` now triggers the
        same full teardown once instead of retrying forever with a dead
        token.
      - **S3/S4 (rate limiter didn't check budget before verifying;
        keyed on the reverse proxy's own address)** — budget is now
        checked before any comparison work, and an optional
        `X-Forwarded-For`-trusting mode (`WIRESERVE_TRUST_PROXY_HEADERS`)
        exists for real proxy-fronted deployments.
      - **S5 (exported `.conf` not mode 600)**, **S6 (no plaintext-HTTP
        warning)**, **S7 (join token on the command line)** — all fixed
        (file perms, a warning, and `--join-token-file`/stdin support
        respectively).

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
25. **Real bug caught by actually building the images with Podman**:
    `crates/wireserve-agent/src/firewall/nftables.rs`'s `existing_table()`
    compared `Table::get_name()` (which returns `Option<&String>`) against
    `Some(&str)` — a type mismatch that could never surface in this
    sandbox before M6, since `rustables` couldn't compile here without
    system `libclang` (M3's known limitation). Building the agent's Docker
    image in a Podman container that *does* have `clang` installed
    finally compiled the real feature and caught it immediately. Fixed
    with `.is_some_and(|n| n == TABLE_NAME)`. All 36 agent tests and
    clippy pass with the real `rustables` backend compiled in.
26. **A second, more consequential real bug caught the same way**:
    `wireserve-admin`'s `AdminClient` used a single base URL for every
    coordinator call, including `/register` — but the coordinator (by
    hard design, spec §4.0) serves `/register` from its **node-facing**
    listener and `/admin/*` from a **separately-bound admin listener**.
    `export-config`'s own M4 tests never caught this because its mock
    coordinator served every route from one router, masking the real
    split. Actually running the built coordinator image and exercising
    `create-node` → `register` → `poll` → `export-config` end to end
    surfaced it. Fixed by giving `export_config::run` two URL parameters
    (`admin_client`'s base URL, plus a separate `node_facing_url` used
    only for the `/register` call via a new free function
    `client::register` rather than an `AdminClient` method), with a new
    `--register-url`/`WIRESERVE_REGISTER_URL` CLI flag/env var. Two new
    regression tests spin up genuinely separate mock listeners (one
    admin-only, one register-only) to pin this down going forward.
27. **Coordinator Docker image needed `ca-certificates` too, not just the
    agent's image** — `wireserve-admin` is bundled into the coordinator
    image (decisions log entry below) and its `reqwest` client (rustls
    backend) fails to even construct without a system trust store present,
    regardless of whether the call is plain HTTP to localhost. Caught by
    running `wireserve-admin create-node` inside the built container,
    which panicked until this was added.
28. **`wireserve-admin` is bundled into the coordinator's own Docker
    image**, since spec §4.0's hard "admin listener never binds 0.0.0.0"
    rule rules out the usual Docker pattern of publishing it via
    `-p host:port` — the supported access pattern for the containerized
    coordinator is `docker exec <container> wireserve-admin ...`. Node
    agents and static-peer export-config still use standalone
    `wireserve-admin` builds as normal; this bundling is specific to
    making the containerized coordinator deployment self-sufficient.

## M7 — independent security review remediation

An external review (not by whoever wrote M1–M6) of the full codebase
found 8 security findings and 9 functional/spec-conformance gaps. Each
is recorded here with what was actually done — including the few places
a literal reading of the reviewer's suggested fix would have been wrong
or would have regressed something already verified working.

29. **S2 — config injection into static peers' `.conf` files (most
    serious finding).** `endpoint_addr`/`pubkey` were stored and
    redistributed verbatim with no format validation; a bearer-token
    holder could set `endpoint_addr` to e.g.
    `"1.2.3.4:51820\nAllowedIPs = 0.0.0.0/0"` and hijack traffic for
    every static peer exported afterward. Fixed with real validators in
    `wireserve-types` (`is_valid_wg_pubkey`: standard-base64, exactly 32
    bytes, no newlines; `is_valid_endpoint_addr`: strict `host:port`, no
    control characters), enforced at both `/register` and `/poll`.
    Defense in depth on top, per the reviewer's explicit ask: the
    `export-config` renderer and `wireserve-admin list-peers` both
    refuse/sanitize a newline in pubkey or endpoint fields even though
    the coordinator should never let one through.
30. **S3 — rate limiter checked budget only after doing the comparison
    work**, so a blocked IP still paid the same per-request cost; not
    exploitable given 256-bit tokens, but didn't do what §7 claims.
    Split `RateLimiter::check` into `is_blocked` (checked first, no
    side effects) and `record_failure` (called only after an actual
    auth failure) — a blocked IP is now turned away before any
    hash/DB-lookup work.
31. **S4 — rate limiting and `/register`'s endpoint fallback were keyed
    on the reverse-proxy's own address**, per spec §7's mandated
    topology. Added `WIRESERVE_TRUST_PROXY_HEADERS` (off by default) to
    resolve the client IP from the right-most `X-Forwarded-For` entry
    instead of the raw TCP peer. **Deliberately narrower than the
    reviewer's literal "no fallback when loopback or private" fix**: an
    internal-Docker-network or direct-private-LAN deployment with no
    separate proxy hop is itself spec-compliant (§7 only mandates a
    proxy when the network in between is genuinely untrusted), and in
    that topology the observed private-range address *is* the real,
    reachable peer address — confirmed by this project's own E2E test,
    which runs exactly that topology. Rejecting all private ranges
    unconditionally would have broken it. The fallback now skips only
    loopback unconditionally, and additionally skips private ranges
    only when `trust_proxy_headers` is on and XFF resolution still fell
    through to the raw peer address (a sign of misconfiguration, not a
    legitimate direct connection).
32. **S5 — `export-config --out` wrote the `.conf` (containing a private
    key) at default permissions (typically 0644).** Fixed: written via
    `OpenOptions` at mode 600 from creation.
33. **S6 — neither client warned on plaintext `http://` to a
    non-loopback host**, so the admin/join token would cross the network
    in clear. Added a warning (not a hard refusal, since
    `http://127.0.0.1:...` — this project's own recommended
    Docker-`exec` admin-access pattern — is completely legitimate).
34. **S7 — join token and admin token on the command line** land in
    shell history and are visible via `ps`. The admin token already had
    a file-based option (decisions log #20); added the same for the
    agent's join token: `--join-token-file <path>`, or `-` as the
    positional value to read one line from stdin.
35. **S8 — `rejoin` on a non-revoked node left the old bearer token
    live** until a new `/register` completed, defeating the "suspected
    compromised" use case spec §4.5 describes it for. `rejoin` now also
    clears the node's `bearer_token_hash` immediately (`revoked` itself
    still only clears back to 0 on a successful subsequent
    `/register`, unchanged).
36. **F1 — `wireserve list` was completely broken.** The daemon's poll
    loop mutated a local `AgentState` and saved it to disk, while the
    IPC server answered from a *different* `Arc<Mutex<AgentState>>`
    that only ever received `declared_services` pulled *from* it at the
    top of each cycle — `last_directory` (and hence every peer/service
    `list` would show) never flowed back. Fixed: the daemon loop now
    writes its updated state back into the shared copy after every poll
    cycle, success or failure. Directly confirmed by a dedicated check
    in `deploy/e2e/run-e2e-test.sh`.
37. **F2 — `leave` didn't remove the hosts-file block, the IPC socket,
    or reset local state**, only the interface and firewall (spec §4.6
    literally lists three things; the socket/state gap was the
    reviewer's own reasonable extension of that intent). Fixed via a
    shared `teardown_everything` helper (also used by F9 below) that
    does all of it, best-effort per step so one failure doesn't skip
    the rest.
38. **F3 — one colliding service name wedged the whole agent forever.**
    A `409` from `/poll` failed the entire cycle before peer
    reconciliation ever ran, and since the same rejected declaration
    was resent every cycle, every future cycle failed identically —
    the agent stopped seeing new peers *and* revocations. Fixed on both
    ends: the coordinator's `409` now carries a structured
    `conflicting_service` field (`ErrorBody`, not something to
    string-parse out of a message), and the agent quarantines exactly
    that declaration (`quarantine_rejected_service`) — dropped from
    what's sent, recorded in a new `AgentState.rejected_services` so
    `wireserve list` shows *why* — rather than resending it forever.
    Recovery takes one more poll interval, not zero, but no longer
    "forever."
39. **F4 — `rejoin` reallocated the node's IP address**, contradicting
    spec §4.5's explicit "without freeing its name or IP." Every static
    peer's exported `.conf` pointing at that node would silently go
    stale on every rejoin. Fixed: `/register` now reuses `ip4`/`ip6`
    from the existing node row when present, only allocating fresh
    addresses for a node that's never had any.
40. **F5 — containerized agent claimed non-functional.** Half confirmed,
    half refuted by direct testing: the `atomic_write`-over-bind-mounted-
    `/etc/hosts` EBUSY failure was real and is fixed (see the M6-era fix
    already in `fsutil.rs`, found independently before this review
    landed). The claim that the mesh itself needs `--network host` was
    tested directly and found **not necessary** — two containers on an
    ordinary Podman/Docker bridge network reach each other over UDP just
    fine for WireGuard's own traffic, confirmed by the E2E script
    observing a real configured peer and real hosts-file propagation
    with no host networking involved.
41. **F6 — endpoint reapplied every poll cycle defeated WireGuard's own
    roaming correction**, since `configure_peer` was called
    unconditionally for every peer every cycle regardless of whether
    anything changed — resetting kernel-level state spec §4.2 relies on
    staying put between polls. Fixed with a real diff
    (`wg::peers_to_configure`, using `Peer`'s derived `PartialEq`) that
    only reconfigures a peer that's new or actually changed.
42. **F7 — status codes.** Spec §4.1/§4.5 specify `201` for
    `create-node`/`rejoin`; the coordinator returned `200`. Fixed, tests
    updated to assert `201`.
43. **F8 — no way to delete an orphaned node record** (e.g. a failed
    `export-config` between create and register burns a name with an
    unprinted join token forever). **Not fixed in this pass** — a real
    gap, but lower severity than the rest (a burned name is an
    annoyance, not a security or correctness issue) and out of scope
    for this remediation round; a `DELETE /admin/nodes/{name}` +
    `wireserve-admin delete-node` following the same shape as `revoke`
    would close it.
44. **F9 — a revoked agent got `401` forever and never noticed.** Spec
    doesn't require teardown here, but silently retrying forever with a
    dead token and a stale peer set serves no purpose. Fixed:
    `PollError::is_unauthorized()` lets the daemon loop detect a `401`
    specifically and run the same `teardown_everything` as `leave`,
    once, then stop (rather than keep polling with a torn-down
    interface) — an operator re-runs `join` with a fresh token from
    `wireserve-admin rejoin` to come back.
