# WireServe — Implementation Status

Living status document. Update the checkboxes and the "Currently working on"
line as part of the commit that makes progress, so work can pause and
resume across sessions without re-deriving context. Full design is in
`wireserve-design-spec.md`; the detailed step-by-step plan that produced
this checklist lives in the session that created it — this file is the
source of truth for *current status*, the spec is the source of truth for
*requirements*.

**Currently working on:** nothing open — all milestones complete through
M16. 208 tests passing across `cargo test --workspace`, plus three
container harnesses in `deploy/e2e/` that all pass on a real kernel:
`run-e2e-test.sh` (mesh, firewall, interface guard), `run-nat-test.sh`
(two NAT-ed sites) and `run-proxy-test.sh` (TLS-terminating reverse proxy,
the topology spec §7 actually mandates).

Everything that can be verified here now is. What remains unverified is
scale (three nodes, not thirty), real WAN paths, and long-running
behaviour.

**The next E2E run matters more than usual.** M11 fixed a bug that meant
the mesh never carried traffic at all (R1 below), and the reason it
survived three review rounds is that `deploy/e2e/run-e2e-test.sh` only
ever checked control-plane state — `wg show` output, `/etc/hosts`
contents, `wireserve list` — and never once sent a packet between the two
agents. The script now has a data-plane check and a default-deny check,
but neither has been run yet. Everything from M8 onward is still awaiting
its first live exercise: the F1 shared-state refactor, `Network=host`,
the RELATED conntrack rule, `block_in_place` around reconciliation, the
SIGTERM handler, and now M11's peer routing, interface-adoption guard and
firewall ordering.

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
- [x] **M8 — Security review, round 2**: the reviewer re-verified M7
      against the code and found five S/F items only partially closed.
      All closed here, unit/integration-tested (176 total), clippy clean;
      the E2E script was deliberately not re-run for this milestone.
      - **S3/S4 on `/register`** — the extractors had been fixed in M7
        but `/register` itself still recorded the failure *after* the
        token lookup (a correct guess was never throttled) and keyed on
        the raw TCP peer. Now checks `is_blocked` on the proxy-resolved
        client IP before the lookup and `record_failure` after. Two new
        integration tests: a correct token is refused with `429` once
        the failed-attempt budget is spent, and with
        `WIRESERVE_TRUST_PROXY_HEADERS` two clients behind one proxy get
        separate budgets.
      - **S6** — the plaintext-`http://` warning existed only in
        `wireserve-admin`. The check now lives in `wireserve-types`
        (`is_plaintext_http_to_remote_host`, unit-tested) and the agent
        warns on `join` too.
      - **F1** — M7's copy-back sync between the poll loop's private
        state and the IPC server's shared state still lost any
        `serve`/`unserve` issued while a poll request was in flight. The
        daemon now holds exactly one `Arc<Mutex<AgentState>>`;
        `poll_loop::run_once` snapshots what it sends, releases the lock
        across the network round trip, and writes back only the fields
        the cycle produced. The agent's HTTP client also gained a 30s
        timeout so a hung coordinator can't pin `leave` behind it.
      - **F5** — `Network=host` (see decisions log #40, corrected).
      - **F8** — `delete-node` (see decisions log #43).
      - Housekeeping: `.gitattributes` pins LF so a contributor's global
        `core.autocrlf` no longer rewrites every touched file;
        `WIRESERVE_TRUST_PROXY_HEADERS` documented in the coordinator
        unit's env comment.
- [x] **M9 — Remaining "worth fixing now" items** from the reviewer's
      post-M8 list. 180 tests, clippy clean. The `nftables` change was
      type-checked with the real feature (`cargo clippy -D warnings` in
      a `rust:1-slim-bookworm` + `clang` container); the E2E script was
      not re-run.
      - **G1 — hosts sync could destroy `/etc/hosts`.** Any read error
        (non-UTF-8 content, a transient permission failure) was treated
        as an empty file and the whole file rewritten as just the
        managed block. Now only `NotFound` is treated as empty; any
        other error aborts the cycle with the file untouched (tested
        with a non-UTF-8 hosts file, for both `sync` and `remove_block`).
      - **Firewall matched ESTABLISHED but not RELATED.** rustables'
        `established()` helper checks the ESTABLISHED bit alone, so ICMP
        errors tied to a tunnel flow — packet-too-big for path MTU
        discovery, routine at WireGuard's 1420 MTU — were dropped on
        `wg0`. Replaced with a hand-built `ct state established,related`
        rule mirroring the helper's expression shape.
      - **G5 — rate limiter memory growth.** `is_blocked` runs on every
        request and inserted an entry per source address, never evicted.
        Now strictly read-only; `record_failure` prunes expired
        timestamps and empty sources, bounding the table by sources with
        a live failure. The unused `check()` is gone. Tests pin both.
      - **G11 — no `.dockerignore`.** `target/` and `.git/` were copied
        into every image build context; this was a large part of the E2E
        script's build time.
      - **F9 follow-up — 401 self-destruct was too eager.** One 401 tore
        the node down and wiped its state, so a coordinator briefly
        running against the wrong database (backup restore, wiped
        volume) would have made every agent drop off the mesh at once.
        Teardown now requires three consecutive 401s (about a minute at
        the default interval) and, unlike `leave`, keeps the state file
        so the operator can inspect what the node last saw; `join` with
        a fresh token overwrites it anyway.
- [x] **M10 — Defense in depth, remaining functional items, cosmetics.**
      187 tests, clippy clean, both systemd units pass
      `systemd-analyze verify`. E2E not re-run.
      - **Defense in depth**: the agent's hosts-file writer re-validates
        every directory entry (strict DNS label + literal IPv4) and drops
        anything else with a warning, so a compromised or buggy
        coordinator cannot put attacker-chosen text into every node's
        `/etc/hosts`. Tested with name-injection, newline, and non-IP
        entries.
      - **Functional**: port `0` rejected for services (`/poll` and the
        agent's own `serve`) and for `listen_port`; `/poll` caps a node
        at 64 services (`MAX_SERVICES_PER_NODE`); IPAM no longer hands
        out the v4 broadcast address (decisions log #2 corrected); a
        duplicate pubkey on `/register` is a `409` that names the pubkey
        (`DbError::PubkeyTaken`, distinguished via SQLite's constraint
        message) instead of "name already in use"; `revoke` runs in one
        transaction; the coordinator Quadlet no longer publishes the
        admin port to nothing; the admin CLI's HTTP client has a 30s
        timeout; the agent handles SIGTERM/SIGINT by removing its socket
        and exiting *without* teardown (spec §5: a stopped agent leaves
        the node as restricted as it was).
      - **Cosmetic**: `tower` moved to the coordinator's dev-dependencies
        and `tower-http` dropped (neither was used by the binary); the
        agent unit gained `ProtectSystem=strict` + `PrivateTmp` (the
        existing `ReadWritePaths` was a no-op without it); the Windows
        hosts-path branch is gone (dead code on a platform the crate
        cannot build for); the poll loop's netlink/DNS/file steps run
        under `block_in_place` so the IPC server stays responsive.

- [x] **M11 — Security review, round 3.** A fresh full-codebase review,
      reading the actual dependency sources rather than trusting their
      names. 198 tests, clippy clean. Found one critical functional bug,
      two high-severity items, and a handful of smaller ones. The E2E
      script was not re-run (it gained new checks that need it).
      - **R1 (critical, functional) — the mesh never carried traffic.**
        The agent configured WireGuard peers and never installed a single
        kernel route. `AllowedIPs` is WireGuard's *cryptographic*
        routing table: it decides which peer an inbound packet belongs
        to, and puts nothing in the host's routing table. The interface's
        own address is assigned as a `/32` + `/128`, which creates a
        local route for this node alone, so there was no route toward any
        other member of the mesh — `plex.wg` resolved fine and then
        failed to connect. `wg-quick` does this step from `AllowedIPs`;
        this agent has to too. Fixed by calling
        `configure_peer_routing` when the peer set changes, which adds
        exactly one host route per peer (never a default route, since
        every peer's `AllowedIPs` is its own `/32` + `/128`). See
        decisions log #45.
      - **R2 (high, security) — `revoke` did not invalidate an
        outstanding join token.** `revoke` cleared `bearer_token_hash`
        but left `join_token_hash` redeemable, and `apply_redemption`
        sets `revoked = 0`. So revoking a node that had been created but
        not yet registered did not cut it off: whoever held the join
        token could redeem it afterwards and land on the mesh as a fully
        un-revoked member. That is exactly the case revoke exists for —
        a credential issued out of band and then found to have leaked.
        Now cleared in the same transaction; rejoin (§4.5) remains the
        way back in and issues a fresh token.
      - **R3 (high, operational) — the agent silently destroyed a
        pre-existing `wg0`.** `create_interface` treats `EEXIST` as
        success, and `configure_interface` then flushes every address
        from the interface, overwrites its private key and listen port,
        and sends WireGuard's `ReplacePeers` flag. On a host already
        running a `wg-quick`-managed `wg0` — a common way to reach a
        machine remotely — starting the daemon tore that tunnel down
        without a word, and `leave` deleted the interface outright. The
        agent now refuses to adopt an interface whose private key is not
        its own, naming `--ifname` in the error.
      - **R4 (medium, functional) — more than 64 `serve` calls wedged the
        agent permanently.** `MAX_SERVICES_PER_NODE` was enforced only at
        the coordinator, which returns a plain `400` with no
        `conflicting_service` field, so the agent could not quarantine
        anything: the oversized list was persisted, resent verbatim every
        cycle, and every future poll failed with it — no peer
        reconciliation, no firewall updates, no hosts sync. The same
        wedge shape F3 was reworked to eliminate. The constant moved to
        `wireserve-types` and `serve` now enforces it locally.
      - **R5 (medium, deployment) — the default mesh range overlaps
        Tailscale.** `100.90.0.0/24` sits inside `100.64.0.0/10`, the
        CGNAT block Tailscale allocates every address from. A host
        running both has an overlay route covering the whole `/10`, so
        mesh traffic can leave over the wrong interface. The default is
        unchanged (it is what the spec's own examples use throughout, and
        moving it would strand any deployment already addressed from it),
        but the coordinator now warns at startup when the configured
        range overlaps, and the README says what to set instead.
      - **R6 (low) — a database error during bearer auth was billed as a
        failed credential guess.** `find_by_bearer_hash(..).ok().flatten()`
        turned any DB error into `401` + `record_failure`, so a transient
        storage fault would rate-limit legitimately-polling nodes off the
        mesh while the real error stayed out of the logs. Now a distinct
        `500`, logged, and never charged to the caller's budget.
      - **R7 (low) — default-deny was installed after the interface came
        up.** Reordered to strictly before `bring_up`. The old order was
        not exploitable (a freshly configured interface has no peers, so
        the kernel drops everything inbound anyway), but that is a
        property of WireGuard rather than the guarantee §5 asks for.
      - **R8 (low) — `atomic_write` followed a symlink at the temp
        path** (`create` rather than `create_new`), and `AgentState::save`
        left the directory holding the key material at the umask default.
        Both now hardened; not exploitable under the shipped deployments,
        where the directories are root-owned, but this code should not be
        the part relying on that.
      - **Test coverage**: `deploy/e2e/run-e2e-test.sh` gained the two
        checks whose absence let R1 survive — a real route/connectivity
        check between the two agents, and a default-deny check that an
        undeclared port is refused across the tunnel.
      - **Reported, deliberately not fixed**: peer endpoint DNS
        resolution is serial and blocking on every cycle (decisions log
        #46), and a quarantined service is never retried automatically
        (#47).

- [x] **M12 — Deployment configuration, usable docs, and a logging gap.**
      200 tests, clippy clean, both images built and smoke-tested.
      - **R9 (medium, security/spec) — the audit log produced nothing.**
        Found while smoke-testing the rebuilt image: with `RUST_LOG`
        unset the coordinator emitted zero lines. `fmt::init()` derives
        its filter from `RUST_LOG`, and an unset `RUST_LOG` passes
        `ERROR` only — so all six of spec §7's required audit events
        (node creation, registration, revoke, rejoin, service
        declare/withdraw), which are emitted at `INFO`, were filtered out
        on every real deployment, along with every startup warning. The
        audit log existed in the source and nowhere else. Both binaries
        now floor the filter at `info`; `RUST_LOG` still overrides. The
        agent had the same defect, where it also hid "firewall rules are
        NOT being applied" and every failing poll cycle.
      - **Mesh ranges set in the deploy configs.** `WIRESERVE_NET_V4_CIDR`
        is `10.90.0.0/24` and `WIRESERVE_NET_V6_PREFIX` a randomly
        generated `fdb4:d481:7c21::/64`. The compiled-in defaults are
        unchanged, since they are what the spec's examples use throughout
        and a deployment already addressed out of them still works. The
        v6 change is for a different reason than the v4 one and nothing
        to do with Tailscale (whose own range, `fd7a:115c:a1e0::/48`,
        collides with neither): `fd00:90::` discards the 40 pseudo-random
        bits RFC 4193 requires, which is the entire mechanism by which
        independently-built ULA networks avoid collision. A startup
        warning now covers this case, symmetric with M11's CGNAT warning.
      - **`deploy/env/` added.** All three unit files referenced
        `/etc/wireserve/{coordinator,agent}.env` and nothing in the repo
        said what belonged in them — and the coordinator unit's
        `EnvironmentFile=` has no `-` prefix, so it is mandatory.
        Documented examples now exist, and are where the mesh ranges live
        for the systemd and Quadlet paths (deliberately not duplicated as
        `Environment=` lines, which would override the operator's own
        file rather than default it).
      - **Image builds are incremental.** Both Dockerfiles now use cache
        mounts for the cargo registry and target directory, shared
        between the two images, which previously compiled the common
        dependency graph twice and recompiled everything on any source
        change. Measured: coordinator 92s cold and 19s after a source
        edit, agent 37s and 20s. Building inside the container is kept
        deliberately — see decisions log #49.
      - **README rewritten around using the thing.** It opened with the
        crate layout and never said how to run a mesh. Now: what it is,
        how it fits together, then create coordinator → add node →
        publish service → add a phone → revoke, a command reference for
        both CLIs, and the ports and conflicts sections from M11.

- [x] **M13 — Fixed the E2E data-plane checks, then ran the mesh.** The
      checks added in M11 could not have worked and two would have passed
      unconditionally. See the commit; the short version is `sh -c` with
      `/dev/tcp` (a bash builtin, and /bin/sh is dash), `nc` absent from
      the runtime image so nothing was ever listening on the port being
      probed, and a mesh IP grepped for a range M12 had changed. First
      confirmation in the project's history that the mesh carries traffic.
- [x] **M14 — Simulated the two-NAT topology** (`run-nat-test.sh`). Two
      sites behind their own nftables routers, one port-forwarded and one
      not, plus a third node sharing the second router. Required marking
      every segment `--internal`: netavark masquerades traffic whose
      source is one of its non-internal subnets, so our routers' NAT was
      being NAT-ed a second time and handshakes half-completed. Findings:
      the NAT-ed to port-forwarded path works in both directions;
      **two nodes behind one router cannot reach each other** (needs NAT
      hairpinning, spec defers STUN); and the `/register` endpoint
      fallback records the node's self-reported `listen_port`, not the
      port the NAT mapped, so two nodes behind one router are recorded
      identically. It self-heals via WireGuard endpoint correction.
- [x] **M15 — Closed the three fixable items left open after M14.**
      204 tests, clippy clean, all three harnesses pass.
      - **R10 (high, availability) — the rate limiter could take the whole
        mesh offline, and this had been left as advice rather than fixed.**
        The budget check ran ahead of authentication and rejected on the
        budget alone. Keyed on a source address, with spec §7's mandated
        proxy in front, every node shares one key — so ten bad guesses
        from any stranger who could reach the coordinator took every node
        off the mesh until the window expired. Nodes behind one NAT share
        a key the same way. Corrected: being over budget no longer rejects
        a request that carries a genuinely valid credential, it only stops
        one from continuing to fail. This deliberately reverses part of
        S3; the cost is one SHA-256 and an indexed lookup for an
        over-budget source, against an availability failure in the default
        topology. The admin surface keeps strict early rejection, since it
        is loopback-bound with one credential and one operator, so it has
        no population of innocent callers to damage.
      - **R11 (high, functional) — found by the new proxy harness: a
        proxied node got no endpoint at all.** `/register`'s fallback
        skipped the observed address whenever `trust_proxy_headers` was on
        and the address was private — without checking whether the
        forwarded header had actually been used. On an internal network
        behind a proxy, which is the recommended deployment, the node's
        real forwarded address *is* private, so every node that omitted
        `--endpoint-addr` was recorded with no endpoint. A peer with no
        endpoint cannot be dialled, and a node only learns a peer's real
        address from traffic that peer sent first, so a mesh where nobody
        supplied one could never form. `client_ip::resolve_client` now
        reports whether the address came from the header, and the
        private-range skip applies only to the misconfiguration case it
        was always documented (decisions log #31) as being for.
      - **The interface-adoption guard now actually runs.** R3 was
        reasoned from library source and covered by nothing executable.
        `run-e2e-test.sh` now stands up a foreign `wg0` with its own key,
        confirms the agent refuses to start, confirms that interface kept
        its key and address, and confirms the same agent starts normally
        on `--ifname wg1`.
      - **The proxy path is no longer untested** (`run-proxy-test.sh`):
        real nginx, a private CA installed into each agent's trust store
        so certificate validation is genuine, the coordinator on an
        internal-only segment so "unreachable except through the proxy" is
        a property of the topology rather than a claim, and checks that
        `X-Forwarded-For` gives each node its own address and its own
        rate-limit budget.

- [x] **M16 — SQLite write path and request body cap.** 208 tests,
      clippy clean, E2E passes. Prompted by asking whether the single
      pooled connection was a bottleneck; it measurably is not, and
      saying so mattered more than the changes did.
      - **Measured first.** A poll-shaped transaction (one `UPDATE`, one
        `SELECT`, committed) cost about **0.05ms** in the default
        rollback journal at `synchronous=FULL`. A thirty-node mesh
        polling every twenty seconds offers 1.5 requests per second. The
        mutex was never close to being the limit, and a connection pool
        would have been complexity bought for nothing — every `/poll`
        writes, so SQLite would serialise the writes regardless of how
        many connections were available.
      - **WAL plus `synchronous=NORMAL`** (about 0.01ms on this machine,
        and a far larger difference wherever fsync is honest). Kept
        because it is one line, standard for server-side SQLite, and
        shortens the window during which the connection mutex is held.
        `synchronous=NORMAL` under WAL still survives an application
        crash; it trades only the durability of the newest transactions
        against power loss, and the newest transaction here is a
        `last_seen` timestamp that the next poll rewrites anyway.
      - **File-permission ordering was the actual bug this introduced,
        and it was caught before it shipped.** SQLite creates the `-wal`
        and `-shm` sidecars with whatever permissions the main database
        has at that moment, and those sidecars hold the same rows. The
        old code hardened the main file *after* migrating, which with WAL
        enabled would have left the sidecars at the umask default. The
        hardening now runs before WAL is switched on, with a second sweep
        afterwards, and a test asserts all three files are `600`.
      - **Request bodies capped at 64KB**, replacing axum's 2MB default.
        The largest legitimate body is a `/poll` declaring the maximum 64
        services, which measures **under 3KB**; the default let an
        unauthenticated caller have two megabytes of JSON parsed before
        any credential was examined, at roughly **7ms** against the
        ~0.05ms of database work behind it. That inversion, where the
        cheapest request to send was by far the most expensive to serve,
        was the real exposure on this path rather than the mutex. Not a
        substitute for rate limiting at the reverse proxy.

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
   allocation starting at host `1`. Reserved: the network address (`.0`)
   and, for v4 prefixes shorter than /31, the broadcast address (`.255`
   on a /24) — the latter added in M10; earlier text here claimed `.1`
   was reserved, which was never true (the coordinator is not a peer, so
   nothing needs it).
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
9. **(Superseded by #69 — `rustables` removed.)** **`rustables` is GPLv3-licensed.** The spec names it explicitly (§5,
   "netlink, no shelling out to `nft`"), so this is a spec directive, not
   a choice made here — but it's worth flagging plainly: linking it into
   `wireserve-agent` means that binary's distribution terms are
   effectively governed by GPLv3, which may affect the license the
   `wireserve-agent` crate/binary ships under (this doesn't affect
   `wireserve-coordinator`/`wireserve-admin`, which don't depend on it).
10. **(Superseded by #69 — no clang/bindgen anymore.)** **Build-time system requirement**: `rustables` uses `bindgen` against
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
15. **(Superseded by #69 — the feature is gone; the backend is gated on `target_os = "linux"` only.)** **`rustables` is an optional Cargo feature (`nftables`), default-on.**
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
40. **F5 — containerized agent claimed non-functional.** The
    `atomic_write`-over-bind-mounted-`/etc/hosts` EBUSY failure was real
    and is fixed in `fsutil.rs`. The `--network host` half was initially
    marked "not necessary" here because the E2E script's two agents
    reach each other over a bridge network — but that reasoning was
    wrong, and M8 corrected it: in the E2E harness each *container* is
    the node, so a private namespace is exactly right there, whereas in
    the shipped deployment the *host* is the node and `wg0` plus the
    nftables table must live in the host's namespace or nothing on the
    host can use or serve over the mesh. `Network=host` is now set in
    the Quadlet and documented as required in the Dockerfile's run
    example; the E2E harness intentionally keeps isolated namespaces.
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
    unprinted join token forever). Deferred in M7, closed in M8:
    `DELETE /admin/nodes/{name}` + `wireserve-admin delete-node`. The
    route refuses (`409`) while the node is registered and not revoked,
    so removing a live mesh member is always a deliberate revoke-then-
    delete, never a single slip. `services` rows go via the schema's
    `ON DELETE CASCADE` — the one path where that cascade fires.
44. **F9 — a revoked agent got `401` forever and never noticed.** Spec
    doesn't require teardown here, but silently retrying forever with a
    dead token and a stale peer set serves no purpose. Fixed:
    `PollError::is_unauthorized()` lets the daemon loop detect a `401`
    specifically and run the same `teardown_everything` as `leave`,
    once, then stop (rather than keep polling with a torn-down
    interface) — an operator re-runs `join` with a fresh token from
    `wireserve-admin rejoin` to come back.

## M11 — security review round 3

A third review, this time reading the actual source of `defguard_wireguard_rs`
and `rustables` rather than reasoning from their API names. That is what
turned up #45 — a bug that no amount of reading this project's own code
would have revealed, because the code looks correct right up until you know
what the library does and does not do on your behalf.

45. **Peer routing was missing entirely — the mesh carried no traffic.**
    The agent called `configure_peer` for each peer and stopped there.
    WireGuard's `AllowedIPs` is a *cryptographic* routing table: it decides
    which peer an inbound packet is allowed to have come from, and which
    peer an outbound packet gets encrypted to, once the packet has already
    been handed to the interface. It does not create a single entry in the
    kernel's routing table. The interface's own address is assigned via
    `IpAddrMask::host`, i.e. a `/32` and a `/128`, which gives a local
    route for this node and nothing pointing at any other node. So every
    piece of visible state was correct — `wg show wg0 peers` listed the
    peers, `/etc/hosts` had `plex.wg`, `wireserve list` showed the
    directory — and a connection to `plex.wg` got `ENETUNREACH`, or worse,
    on a host running an overlay that claims the surrounding range, was
    handed to that overlay's interface instead. Fixed by calling
    `configure_peer_routing` whenever the peer set changes. Deliberately
    not on every cycle: adding an existing route just logs a warning
    inside the library, and keeping it off the steady-state path preserves
    what F6 was about. The library's `add_peer_routing` has a special
    branch for a peer carrying `0.0.0.0/0` that rewrites the default route
    and installs policy-routing rules — it cannot trigger here, because
    every peer's `AllowedIPs` is its own `/32` + `/128` by construction
    (`peer_allowed_ips`), which is the same property spec §9 requires of
    exported static-peer configs for its own reasons.

    **Why three review rounds missed it**: `deploy/e2e/run-e2e-test.sh`
    asserted on control-plane state only and never sent a packet between
    the two agents. A test that checks `wg show` lists a peer is testing
    that configuration was accepted, not that anything works. The script
    now checks for a route via `wg0` and that an undeclared port is
    refused across the tunnel.

46. **Peer endpoint DNS resolution is serial and blocking on every cycle —
    reported, not fixed.** `desired_peers` calls `Peer::set_endpoint` for
    every peer on every poll, which resolves the hostname synchronously.
    A directory full of slow-resolving names makes a poll cycle take
    proportionally longer; it runs inside `block_in_place`, so the IPC
    server stays responsive and the runtime is never starved, but the
    cycle itself stalls. The obvious fix — only re-resolve when the
    endpoint *string* changed — is wrong for this design: spec §4.2
    explicitly wants a dynamic-DNS endpoint to be re-resolved so a peer
    that moved is found again, and caching by string defeats exactly that.
    A proper fix is an async resolver with a TTL-aware cache, which is
    more machinery than the problem currently justifies. Left as a known
    characteristic rather than papered over.

47. **A quarantined service is never retried — reported, not fixed.** F3's
    quarantine drops a colliding declaration and records why, and the only
    way out is the operator running `serve` for that name again (which
    clears the record). If the other node withdraws the colliding name,
    this node does not notice and does not reclaim it. Automatic retry
    would mean re-sending a declaration the coordinator already rejected,
    on some backoff, which reintroduces a weaker version of the wedge F3
    removed. `wireserve list` showing the rejection with its reason is the
    intended recovery path, and that is a documented limitation rather
    than an oversight.

48. **`kind=static` nodes are now refused at `/poll`.** Spec §9 says a
    static peer never polls, and §4.2 that its `endpoint_addr` stays NULL
    forever. Neither was enforced: `update_poll_state` would have written
    an endpoint onto a static node, and every exported `.conf` afterwards
    would carry an `Endpoint =` line for a device that is only ever meant
    to initiate. In practice nothing could reach that code — `export-config`
    generates the static node's bearer token during registration and drops
    it without printing or storing it anywhere — but an invariant that
    holds only because a value happens to be unreachable is not enforced,
    it is lucky.

## M12 — deployment configuration

49. **Container images are still built inside the container, on purpose.**
    The obvious speedup is to `cargo build --release` on the host and
    `COPY` the binary into a slim image, and it does not work here: the
    runtime images are `debian:bookworm-slim` (glibc 2.36) and this
    development host is Ubuntu with glibc 2.43. A binary linked against
    the newer glibc does not start in the image at all, and the failure is
    a `GLIBC_2.xx not found` at exec time rather than anything the build
    catches. Building in the same Debian release the binary will run on is
    what keeps that honest, and it is also the only thing that verifies
    the shipped Dockerfiles themselves still work — the property M6 was
    about, which found both the missing `ca-certificates` and the
    `rustables` type mismatch. Cache mounts get the speed back without
    giving either of those up: the cost being avoided was recompiling
    unchanged dependencies, not the container. A host-built binary would
    only be viable against a musl target or a runtime base matched to the
    host, both of which trade away more than they gain.

## M15 — what three rounds of review did not find

50. **Both bugs in M15 were found by running the code in a topology it had
    never been run in, not by reading it.** R10 had been *reported* a
    round earlier and consciously left as deployment advice; R11 was
    invisible until nginx was actually put in front of the coordinator,
    at which point it took about ninety seconds to spot, because the
    symptom was two nodes with `endpoint=-` in a table that should never
    have had any. Both are in code that had been read closely several
    times. The pattern across M11-M15 is consistent enough to write down:
    every serious defect in this project was found by executing something
    or by reading a dependency's source, and none was found by re-reading
    this project's own code.

51. **Three separate test-harness bugs were written during M11-M15**, each
    of which would have made a check pass without testing anything: `sh`
    versus `bash` for `/dev/tcp`, a listener that was never running
    because `nc` is absent from debian-slim, and a `grep` for
    `event="..."` against tracing output that puts ANSI escapes between
    the field name and the `=`. All three were caught by looking at why a
    result seemed too good, which is the only reason to distrust a passing
    test. Worth remembering that a new assertion is itself unverified code
    until it has been seen to fail for the right reason.

## M17 — review follow-ups

52. **The coordinator unit's `Environment=WIRESERVE_DB_PATH=` line was the
    trap its own comment warned about.** Two lines above it, the unit
    explains that an `Environment=` after `EnvironmentFile=` silently wins
    over the operator's env file — then set `WIRESERVE_DB_PATH` exactly
    that way, while `coordinator.env.example` documented it as settable.
    Removing the line alone would have regressed the bare-metal path,
    because the binary's compiled-in default is the *relative*
    `wireserve.db`, not the absolute path the unit was supplying; the
    example file listed the absolute path under "optional, shown with
    their defaults", which was simply untrue. Fixed by promoting
    `WIRESERVE_DB_PATH` to an explicit, uncommented setting in the env
    file. The container images were never affected — they set the same
    value as an image `ENV`.
53. **`fsutil::atomic_write` now falls back at the temp-file *create*
    step, not only at `rename`.** The original fallback existed for
    bind-mounted `/etc/hosts` (`EBUSY` at rename). The opposite
    arrangement — a read-only directory holding a writable bind-mounted
    file, which is what `ProtectSystem=strict` plus
    `ReadWritePaths=/etc/hosts` produces — fails earlier, at the
    `create_new` open with `EROFS`, before any rename is attempted, so
    checking only the rename error left it with no fallback at all. That
    is why the agent unit had to grant `ReadWritePaths=/etc` wholesale;
    it now grants the single file. Tested without privileges by making
    the *directory* mode 0500, which produces `EACCES` at the same step
    (and the test no-ops under root, where the mode bits do not bite).
54. **`is_valid_endpoint_addr` checked characters but not structure**, so
    `-x-.example.com:51820` and `...:51820` passed — every byte was in
    the allowed set. Now checked per label. Deliberately *not* reusing
    `is_valid_dns_label`: that function additionally requires lowercase
    because it governs names this project assigns and writes into
    `/etc/hosts`, whereas an endpoint hostname belongs to somebody else
    and DNS comparison is case-insensitive. One trailing dot is tolerated
    (`example.com.`), since dynamic-DNS configuration does get written
    that way.
55. **This repo is not `cargo fmt`-clean and that is not being "fixed".**
    26 of its source files deviate, consistently, in the direction of
    keeping short constructs on one line where rustfmt would split them
    (`assert_eq!(mode, 0o644, "…")` and similar). Running `cargo fmt`
    would produce a large diff unrelated to any change in flight and
    would bury it. New code matches the surrounding house style instead,
    and the verification gate is `cargo clippy -D warnings` plus the test
    suite — not `cargo fmt --check`.
56. **`clear-endpoint` is an admin action, not a wire change.** A node can
    set `endpoint_addr` but never unset one, because `update_poll_state`
    writes it with `COALESCE(?2, endpoint_addr)` — an omitted field means
    "no opinion, keep what you have". So a node that loses its port
    forward keeps advertising an address no peer can reach. The obvious
    fix, dropping the COALESCE, is actively harmful: `PollRequest`'s
    `endpoint_addr` carries `skip_serializing_if`, and a node that
    registered without `--endpoint-addr` had one inferred from its
    observed source address and never learned the value, so it sends no
    `endpoint_addr` on its first poll — dropping the COALESCE would wipe
    the inferred endpoint immediately and break exactly the NAT-ed
    deployment the register-time fallback exists for. The wire-level
    alternative (a genuine tri-state: absent = keep, null = clear, value
    = set) would work but needs `Option<Option<String>>` with a custom
    deserializer, a wire-format change, and a new agent CLI affordance to
    trigger a clear, for a case the operator is better placed to notice
    anyway. `DELETE /admin/nodes/{name}/endpoint` instead.
    **Documented limitation, tested rather than hidden**: this clears a
    stale value, it does not stop a node re-asserting one it still has
    configured locally.
57. **Join tokens expire after 30 minutes by default.** They were
    redeemable forever, which is the wrong property for a credential that
    is deliberately carried out of band — chat, a password manager,
    terminal scrollback — and so tends to outlive its purpose by months.
    A join token covers the gap between creating a node record and running
    `join` on the machine, which is a minutes-long errand, and `rejoin`
    mints a fresh one whenever the window is missed. So the cost of a
    short default is one extra command; the cost of no expiry is a live
    credential nobody remembers issuing. `WIRESERVE_JOIN_TOKEN_TTL_SECS`
    (0 disables), `--ttl` per token.

    Three details that are load-bearing rather than incidental:

    - **NULL means "never expires", and every pre-existing row gets NULL
      from `ADD COLUMN`.** Upgrading must not invalidate a token an
      operator sent out five minutes ago, and
      `migrating_an_existing_database_leaves_outstanding_join_tokens_redeemable`
      pins that.
    - **The expiry check is in Rust, not in the SQL predicate.**
      Lexicographic comparison of RFC3339 strings is correct only while
      every writer emits an identical format, including fractional-second
      width — not a property worth betting a credential check on. The row
      is fetched and the timestamps compared as parsed values.
    - **Expired returns `Ok(None)`, the same value as unknown and as
      already-redeemed.** That is what keeps all three indistinguishable
      in the response, so a caller cannot probe which of its guesses were
      ever real tokens. Asserted on whole response bodies, not just status
      codes. An *unparseable* expiry also returns `Ok(None)`: a timestamp
      this code cannot read is a corrupt or hand-edited row, and the safe
      reading of "I don't know when this expires" is "it has".

    `rejoin` gained an optional JSON body for `--ttl`, taken as
    `Option<Json<RejoinRequest>>` so a bodiless POST — which is what every
    admin CLI built before this change sends — keeps working instead of
    failing on a missing Content-Type.
58. **The rate limiter's comments claimed a bound it did not provide, and
    now it provides one.** `routes/register.rs` asserted that an
    over-budget source "is turned away even if its next guess would have
    been correct, which is what makes the limiter an actual brute-force
    bound rather than a response-code cosmetic" — ten lines above code
    doing exactly the reverse, and directly contradicting the comment
    immediately below it. `rate_limit`'s module doc claimed failed
    attempts "trip it" as though that stopped something. Both rewritten to
    describe what the per-source window actually does, which is select a
    status code.

    The decision that produced the gap was right and is unchanged:
    rejecting on the per-source budget cannot work when spec §7 mandates
    a proxy in front, because then every node shares one key and ten
    guesses from a stranger take the mesh offline. What was missing is
    that no bound replaced it. Added: a **global** failed-auth budget
    that delays *failure responses only* (250ms, capped at 1s, at most 64
    concurrently). A valid credential is never delayed, which is what
    makes this free of the collateral damage the per-source version had —
    the population slowed is exactly the population failing.

    **The delay must never be awaited while holding `state.db.conn`**,
    which is the process's single `Mutex<Connection>`. `/register` held
    that lock across its whole failure branch, so the naive placement
    would have queued every request in the mesh behind whoever was
    guessing — a far worse outcome than the guessing. The failure branch
    now drops the lock explicitly first; the success path deliberately
    keeps it, because dropping and re-acquiring there would open a window
    for two callers to redeem the same one-time join token. Pinned by
    `a_delayed_failure_never_holds_the_database_lock`, which was checked
    against a deliberately reintroduced bug.

59. **Blocking an abusive source is the proxy's job, and the coordinator's
    contribution is a log line.** The tempting alternative — since this
    project already manages nftables — does not survive contact with the
    architecture: the nftables code is in the *agent*, on a different
    machine. The coordinator runs unprivileged with an empty
    `CapabilityBoundingSet=` and never touches the host firewall (spec
    §8), and behind the mandated proxy the only address it can see is the
    proxy's own, so a block it applied would drop every node at once and
    stay dropped. Granting it CAP_NET_ADMIN to do that would trade the
    strongest privilege separation in the design for a mesh-wide outage
    button. Instead every failed auth emits
    `event="auth_failure"` with the resolved client address and a coarse
    reason (never any part of the credential), and `deploy/fail2ban/`
    ships a filter and jail for the proxy host.

    **Not covered by a test: the log line's exact format**, which the
    fail2ban filter depends on. Capturing tracing output needs a global
    subscriber and is flaky under parallel tests, and decisions log #51 is
    the record of this project already shipping a grep that matched
    nothing because of ANSI escapes. The filter's README says to run
    `fail2ban-regex` against real output rather than trusting it, which is
    the honest version of a check this suite cannot make.

## M18 — service approval

60. **Service declarations need admin approval before they propagate, and
    that is ON by default.** Service names are globally unique and
    first-come-first-served, so any node holding a valid bearer token
    could claim an unclaimed name — or re-claim one freed a moment earlier
    when its owner was revoked — and every other node's `/etc/hosts` would
    point `<name>.wg` at it. That is a credible way to intercept traffic a
    user believes is going somewhere else, and it needs exactly one
    compromised node. `WIRESERVE_REQUIRE_SERVICE_APPROVAL=false` turns it
    off for a single-operator mesh where the round trip is pure ceremony.

61. **The approval lives on the `services` row, as two nullable
    timestamps.** A row *is* the pair `(node_id, name)`, so binding
    approval to that pair is structural rather than a check that could be
    forgotten: there is no representable state "the name `plex` is
    approved" independent of who holds it. It also means approval dies
    with the node for free — `revoke()` already deletes a node's rows and
    `delete_node` gets them via the FK cascade — where a side table keyed
    on the name would have needed explicit cleanup in three places, one of
    them the security-critical one.

    `approved_at IS NULL` means pending, and that direction is the point:
    **fail-closed**. A future insert that forgets the column yields a row
    invisible to the mesh, never an approved one. A `status TEXT NOT NULL
    DEFAULT 'approved'` column would have given the migration backfill for
    free and auto-approved on that same mistake, silently, forever.

62. **The migration's backfill is the most dangerous line in the change.**
    Because approval defaults ON, upgrading an existing deployment without
    it would empty the directory — and every node's managed `/etc/hosts`
    block — on the first poll. `migration_grandfathers_existing_services_as_approved`
    was checked against a build with the backfill removed, and fails.
    Consequence worth stating: an operator enabling approval over a
    running mesh reviews nothing already there. `deny-service` on an
    approved name is the deliberate per-name re-review lever.

63. **A pending declaration is reported on a `200`, never as an error.**
    Any `/poll` error aborts the whole cycle — peer reconciliation,
    firewall and hosts sync all skipped — and since the agent resends the
    same declaration every cycle, an error for a pending declaration would
    fail identically forever, so the node would stop seeing new peers and
    would never see its own revocation. This project has hit that shape
    twice already (decisions log #47, and `MAX_SERVICES_PER_NODE`).
    Pending is a normal, possibly long-lived state. The two new
    `PollResponse` fields carry `skip_serializing_if`, so with approval
    disabled they are absent from the JSON entirely and "behaves exactly
    as before" holds at the byte level rather than by assertion.

64. **Approval gates the directory; a denial also closes the firewall
    hole, in the same cycle.** A *pending* service keeps its local hole
    open — the node is only firewalling itself (spec §5), and nothing
    resolves `<name>.wg` for it yet anyway. An explicit *denial* is
    different: the agent quarantines the name out of `declared_services`,
    and because `service_rules` derives from that list, the hole shuts.

    The ordering matters and is easy to get wrong. `run_once` used to
    compute `rules` from the pre-request snapshot; folding the verdict
    into persisted state alone would have left a denied service reachable
    for another poll interval — twenty seconds by default, which reads as
    a bug rather than a design. Verdicts are now applied *before* `rules`
    is computed, and `rules` is built from the post-denial list.

    This is the one place the coordinator's response influences a node's
    own firewall, amending the invariant documented on step 3 of the poll
    loop. It is safe in exactly one direction and must stay that way: a
    verdict can only ever remove a rule, never add one, so a compromised
    or buggy coordinator can close ports on a node but can never open one.

65. **Deny is for mistakes; revoke is for compromise.** A denied row still
    occupies its globally-unique name until the *declaring node*
    withdraws it — and a hostile node will not. Deleting the row outright
    instead would be worse: the node recreates it as pending on its very
    next poll and never learns it was denied, because the denial and the
    recreation race and the recreation always wins. So deny does not, and
    cannot, stop a compromised node parking a name; `revoke` deletes every
    one of its rows and kills its token, which is the actual answer. Said
    plainly in `deny`'s doc comment, the CLI help and the README rather
    than left for someone to discover. Real name-squatting resistance
    would be admin-side *reservation* — a separate design.

66. **`MAX_SERVICES_PER_NODE` needed no change, and denied rows are
    self-cleaning.** The limit counts `req.services.len()`, and after the
    withdraw-diff a node's row set is exactly what it declared, whatever
    state those rows are in. A denied name is quarantined out of the
    agent's `declared_services`, so the node stops declaring it, so the
    withdraw-diff deletes the row — no lockout from denials eating a
    node's quota, and no unbounded denied rows, without a second cap.

67. **The denial reason is logged with `?` (Debug), not `%` (Display).**
    It is operator-supplied free text entering an audit log, and `Debug`
    for `&str` quotes and escapes control characters, so a reason
    containing newlines or ANSI escapes cannot forge extra log lines —
    decisions log #51 is the record of this project already being bitten
    by ANSI escapes in tracing output. Bounded by `MAX_DENY_REASON_LEN`,
    enforced both in `wireserve-admin` (fail fast, no round trip) and at
    the coordinator.
68. **The e2e harness encoded the pre-approval expectation and had to be
    updated — which turned out to be the best coverage in the change.**
    `run-e2e-test.sh` declared a service and asserted it reached the other
    node's `/etc/hosts`; with approval defaulting on, that assertion was
    simply false. Rather than switch the flag off for the test, the step
    now checks the gate *holds* (the name must NOT appear before
    approval), that the declaring node reports its own service as pending,
    then approves and checks propagation. That is the only place the
    approval path is exercised against a real mesh, real nftables and a
    real `/etc/hosts`. `run-nat-test.sh` approves its two services and
    moves on, since it is about NAT traversal rather than approval.
    `run-proxy-test.sh` needed no change: it asserts on
    `service_declared` log events, which are emitted for a newly declared
    name regardless of approval state — confirmed by running it, not by
    reasoning about it.

    All three suites were run against real kernel WireGuard and nftables
    in Podman after the change, not just the unit suite.

69. **The nftables backend moved from `rustables` (netlink) to the `nft`
    binary's JSON API, reversing spec §5's "no shelling out to `nft`".**
    Forced by host-firewall interop (ufw/firewalld/native nftables
    coexistence, the NetBird-style approach): that needs inserting a rule
    at the *head* of another tool's chain, and `rustables` 0.8.8 hard-codes
    `NLM_F_APPEND` on every rule add with its message traits crate-private,
    so there is no way to insert from outside the crate. It also only
    partially decodes other tools' rulesets ("Ignoring unsupported
    attribute" on iptables-nft's `xt` rules), cannot express
    `ct original proto-dst`, cost a clang/bindgen build dependency and made
    the agent binary GPLv3 (#9, #10, #15). Mullvad's `nftnl` was checked
    and rejected: it also hard-codes APPEND, cannot list chains or rules,
    and links C libraries. Commands are built with the `nftables` crate's
    typed schema (MIT/Apache); anything read back from the kernel goes
    through our own tolerant structs, because that crate rejects a whole
    ruleset over one expression it doesn't model. `nft` is located at fixed
    absolute paths, never via `PATH` (the agent runs as root), and the
    daemon refuses to start without it — the firewall is not optional.
    Each `apply()` is still one atomic transaction (`nft -j -f -`), and
    "delete the table if present" is the `add table` + `delete table` pair,
    which also retires the empty-netlink-batch hang (the old `teardown()`
    special case). Kernel behavior is pinned by tests that feed the real
    JSON to real `nft` inside an unprivileged `unshare -rn` namespace (no
    root, nothing touches the host), skipped with a message where user
    namespaces are unavailable.

70. **Host-firewall interop, NetBird-style.** A host firewall's own
    base chains drop mesh traffic independently of our table (an accept
    only ends its own chain; a drop anywhere is final), so declared
    services were unreachable on ufw/firewalld/native-nftables hosts until
    an operator added `ufw allow in on wg0` by hand. Tailscale's approach
    (a jump into iptables `INPUT`) was compared against NetBird's
    `InterfaceAllower`; the latter was chosen because it also covers
    native nftables tables and firewalld. What the agent adds, all tagged
    `wireserve:<ifname>` and all runtime-only: a head-inserted
    `iifname <if> counter accept` in every foreign input-hook filter chain;
    `-I INPUT 1 -i <if> … -j ACCEPT` via the real `iptables` binaries for
    iptables-nft's `filter` table (recognised by its `INPUT` chain name —
    such tables carry no marker) and for a loaded legacy `filter` table
    (`/proc/net/ip_tables_names`; this closes a gap NetBird has); for
    firewalld, the `trusted` zone at runtime **plus a forward guard**
    (`inet wireserve-interop`, `iifname <if> drop` on the forward hook),
    because a zone target also accepts forwarded traffic and trusting the
    interface would otherwise let mesh peers route through the host. An
    operator's own zone binding (permanent, or runtime to another zone) is
    never changed. Never done: anything on another interface, anything on
    forward/output besides the guard's drop, writes into owner-flagged
    tables or iptables' other tables. Guard before trust, untrust before
    guard removal, and the executor skips the second step if the first
    failed; trust is not planned at all when the ruleset can't be read
    (the guard couldn't be verified). Reconciled by a dedicated thread on
    `nft -j monitor` events (debounced 500 ms; set/element churn and our
    own tables ignored) and on every poll tick (legacy iptables, firewalld
    reloads, a dead monitor). Always on with the nftables backend, no
    opt-out, per the same decision as before. Everything is logged and
    swallowed; our own table keeps default-denying regardless.

    Found while designing this, and fixed with it: the WireGuard
    ownership check ran inside `bring_up`, *after* the firewall was set
    up, so `--ifname eth0` (or the default `wg0` next to a wg-quick `wg0`)
    installed `iifname eth0 drop` — an SSH lockout — or cut off the other
    tunnel's inbound traffic, and the daemon then exited without cleaning
    up. `firewall::guarded_bring_up` now runs name validation and the
    ownership preflight before any firewall change, and undoes interop and
    our table if bring-up fails. `validate_ifname` restricts names to
    `[A-Za-z0-9_.-]{1,15}` because every rule is keyed on the name and
    iptables (`+`) and nft (`*`) read some characters as wildcards.

    Out of scope, recorded: on hosts without firewalld, a Docker-published
    port is reachable from the mesh through FORWARD whether declared or
    not, since our table only hooks INPUT. Unchanged by this work; closing
    it needs `ct original proto-dst` matching (possible now that the
    backend speaks nft JSON, see #69).

    Tests: the planner is pure and carries the contract (every insert is
    for exactly the configured interface and only in input-hook filter
    chains, skip rules, iptables-vs-nft routing, legacy, idempotency and
    settling, stale/duplicate/misshapen tags, reload recovery, firewalld
    operator choices, guard ordering, exact removal), run against
    fixtures produced by real nft/iptables-nft. Mutation checks were used
    to confirm the tests fail when the planner is broken (one gap — a
    duplicate *correct* rule — was found that way and covered). Real-kernel
    tests run inside `unshare -rn` without root: nft/iptables argv and JSON
    accepted as written, read back as the planner expects, and the full
    runtime (monitor, debounce, tick, stop) restoring rules after external
    reloads — this last one re-execs the test binary inside the namespace,
    with firewalld disabled because its D-Bus is not namespace-scoped.

## M19 — several agents on one host

71. **Named instances.** `--instance <name>` (or `WIRESERVE_INSTANCE`)
    selects everything that was a single fixed resource: state, socket,
    interface, listen port, firewall tables, host-firewall tags,
    hosts-file block. The default instance keeps every path and marker
    it had, so upgrading moves nothing on disk. Named state lives in
    `/var/lib/wireserve/instances/<n>/` (one directory and one container
    volume hold all keys); sockets in sibling `/run/wireserve-<n>/`,
    because systemd deletes a unit's `RuntimeDirectory` on stop and
    nesting would let the default's stop delete the others' sockets.
    `WIRESERVE_STATE_PATH`/`WIRESERVE_SOCKET_PATH` now apply to the
    default instance only — the agent image sets them, and applying them
    to every instance made all instances in a container share one state.
    Instance names are the explicit key rather than the interface name,
    because the interface is chosen automatically and the state path
    can't depend on the outcome.

72. **Two kinds of lock, scoped to what they protect.** An `flock` next to
    the state file makes `daemon` and `join` exclusive per instance
    (filesystem scope, like the state). Interface names are claimed with
    a listening socket at `@wireserve/if/<ifname>` in the abstract
    namespace: that is network-namespace scoped exactly like interface
    names and nft tables (so host-network containers with separate
    filesystems still see each other), atomic to take, and released by
    the kernel when the holder dies — no stale locks. Abstract sockets
    have no permissions, so a claim only counts when `SO_PEERCRED` says
    the holder runs as our euid; a squatter can make an agent skip a name
    but can't make a dead agent's rules look alive. The holder accepts
    and drops connections on a thread (probes would otherwise fill its
    backlog), and probes connect non-blocking so a squatter that never
    accepts can't hang the prober.

73. **Every firewall object is per interface, and cleanup is by
    liveness.** Before this, a second agent replaced the first's
    `inet wireserve` table on every poll, rebuilt the single guard, and —
    worst — deleted every `wireserve:*` rule not tagged with its own
    interface, which the first agent's monitor immediately restored: an
    endless rewrite loop. Now the tables are `inet wireserve.<if>` and
    `inet wireserve-interop.<if>`, every `wireserve*` table counts as ours
    (never inserted into, changes never trigger a reconcile), and a
    tagged rule for another interface is kept while a running agent holds
    that interface's claim and removed once none does — so crash and
    `--ifname`-change cleanup still work, done by whichever agent runs
    next. Another instance's guard is never touched: it only drops, and
    removing it could open forwarding while that interface is still
    trusted. The default instance removes a pre-instances agent's
    fixed-name table and guard (with the `wg0` firewalld trust the guard
    implies, unless a live agent now claims `wg0`).

74. **Interface names: `wireserve0` … `wireserve15`, sticky, pinnable.**
    `wg0` was a poor default because it is wg-quick's, so any host with a
    tunnel needed manual configuration. The chosen name is stored in the
    instance's state and reused; otherwise our own interface under any
    candidate wins (a run that died before saving must not be orphaned),
    then the first free one — skipping names claimed by a running agent,
    stored by another instance (even a stopped one), or held by any
    interface that isn't ours. `--ifname <name>` pins a name, with the old
    refuse-on-conflict behaviour; `--ifname auto` unpins. At start, this
    node's own interfaces under other candidate names, `wg0` or the
    previous name are removed with their firewall state. The choice is a
    pure function over a probe, so its rules are unit-tested; the probe
    itself is tested against real interfaces in a namespace.

    That namespace test found a real bug: interface existence was read
    from `/sys/class/net`, which shows the network namespace of whoever
    *mounted* sysfs. Under `nsenter`/`unshare -n` a taken name looked
    free and would have been configured over. Now `if_nametoindex`, with
    anything but `ENODEV` treated as taken.

75. **Listen ports and addresses.** `join` without `--listen-port` keeps
    the instance's previous port, else the first from 51820 that no other
    instance stored and nothing has bound (v4, and v6 where present). The
    daemon refuses to start when its own mesh address is on another
    interface — overlapping ranges between two meshes, the one clash that
    is certain; peer-route overlaps are not detected.

76. **Hosts file.** Each instance owns a labelled block
    (`# BEGIN WIRESERVE <n>`; the default keeps the bare markers). Markers
    now match whole lines only: the old substring search would have found
    the bare marker inside a labelled block. Read-modify-write runs under
    an `flock` on the file, re-validated against the path's inode after
    locking, since `atomic_write` replaces the file by rename. A rewrite
    that changes nothing is skipped.

77. **`deploy/e2e/run-multi-instance-test.sh`** runs the real binaries in
    an unprivileged user + network namespace — two coordinators, two
    instances on the "host" behind a drop-by-default host firewall and a
    foreign `wireserve0`, and a peer namespace over veth with one agent
    per mesh. It checks interface and port selection, per-instance
    tables and hosts blocks, real traffic reaching only what each
    instance declared, rule stability across polls (no fighting), crash
    cleanup by the surviving instance, sticky restart, clean stop, the
    pre-instances upgrade, and `leave`. No root, no containers.

    Also observed: defguard's `remove_interface` flushes systemd-resolved
    over D-Bus, which times out after 25 s where the bus is unreachable,
    so teardown is slow there.

78. **Peer routes are our own; endpoints get none.** Found by #77:
    defguard's `configure_peer_routing` always calls `configure_endpoints`,
    which routes every peer endpoint via the default gateway — and on a
    host with no default route installs a *blackhole* route to it,
    cutting the mesh (and a coordinator at a peer's address) off. That
    step exists for `0.0.0.0/0` peers, whose endpoint must be kept out of
    the tunnel; ours only ever carry their own `/32` + `/128`, so an
    endpoint is reached over the host's normal routes. `routes.rs` now
    adds the link-scoped host routes itself (netlink, same crates and
    route shape defguard used), and removes a departed peer's route,
    which defguard never did. Deletes carry the output interface so
    another mesh's route to the same address is never removed; an add
    that collides with such a route is a no-op (one route per prefix).
    Route failures are logged, not fatal: failing `reconcile` would leave
    `applied` stale and reconfigure every peer next cycle, resetting
    WireGuard's endpoint roaming. Routes previous versions pinned to
    endpoints are not removed — they can't be told apart from an
    operator's — and vanish with the link or a reboot. A kernel test
    reproduces the blackhole with the old call and passes with the new
    one; the multi-instance e2e now runs without default routes.

79. **Poll steps no longer block each other; a lost `/etc/hosts` mount
    restarts the agent.** Peers, firewall and hosts file (steps 2-4) were
    chained with `?`, so any step failing on every cycle froze the ones
    after it — the reported symptom was a hosts block written once,
    empty, while peers and routes kept tracking the directory. Each step
    now runs regardless, and a cycle reports every failed step together
    (`PollError::Incomplete`); `last_directory` is still saved only after
    a cycle applied in full.

    One way to get there, reproduced: the units grant `/etc/hosts` with
    `ReadWritePaths=` over a read-only `/etc`, which bind-mounts the file
    into the unit's namespace. When anything on the host replaces the
    file by rename (`sed -i`, an editor, cloud-init, the agent run by hand
    outside the unit), the kernel detaches that mount in every other
    namespace, leaving the read-only file underneath: every later write
    fails with `EROFS` until the unit restarts. The daemon now treats
    `EROFS` on the hosts file, *after* a write already succeeded in the
    same run, as exactly that — tears down and exits non-zero, and
    `Restart=on-failure` sets the mount up afresh. A hosts file that was
    read-only from the start (a `:ro` container mount) only logs, never
    loops. Checked with the real daemon in a namespace sandboxed like the
    unit. Each actual rewrite of the block is now logged with the names
    it holds.

    Also: removing the block no longer eats the file's final newline.

## M20 — service addresses and port mappings

80. **Each service has its own address.** `<name>.wg` resolved to the
    owning node, so services on one node shared its address and had to
    be reached on their real ports, and only one of them could ever sit
    on `:80`. Now the coordinator gives every declaration that carries
    port mappings an address from the mesh range (`services.vip4`,
    migration 0006), shared with node addresses so a static peer routing
    the range reaches it; peers add it to the owner's `AllowedIPs` and
    route it; the hosts file points the name at it. A declaration keeps
    its address across re-declarations and approval, and frees it when
    withdrawn. One from an agent that predates mappings gets none and
    loses any it had, since that agent can't serve it — so a mixed mesh
    degrades to the old behaviour per service instead of breaking. An
    exhausted range is logged and leaves the service on its node's
    address rather than failing the poll (which would resend forever).

81. **`serve <name> [PUBLIC:]TARGET[/proto]...`**: several mappings per
    service, TCP and UDP. Only the published ports answer — the target
    port is closed to the mesh on every address — at the user's request.
    `ServiceDecl` keeps `port`/`proto` (the first mapping's target) for old
    coordinators; `ports` absent means the identity mapping, so old agents,
    old state files and old CLIs all still mean what they meant. The
    agent refuses a target port already used by another mapping of the
    node (its replies would be ambiguous, see #82); the coordinator only
    checks each service's own mappings, because a declaration list from
    before mappings may legitimately alias one port under two names — the
    agent's rule generator maps such an alias once and warns.

82. **Kernel data path: a stateless rewrite before conntrack, not a DNAT,
    not a proxy.** The services must see the real client address and
    carry any protocol, which rules out a userspace proxy (it would also
    hand every mesh peer whatever trust a service gives localhost). A
    DNAT of ours doesn't compose with containers: a connection gets one
    destination NAT per direction, and a published port of rootful
    Podman (netavark) or Docker without its userland proxy *is* one — ours
    would win and the runtime's never run. So `svc-pre` (prerouting, raw
    −300) rewrites `vip:public` to `node:target` with nft payload
    statements before conntrack exists and sets a mark bit; `svc-out`
    (output, raw, a `route` chain so the kernel re-routes) does the same
    for the owner's own clients, whose initial lookup succeeds because the
    owner routes its own addresses into the mesh interface. Conntrack,
    the runtime's NAT and the service then see an ordinary
    `client → node:target` flow. `svc-mark-*` (mangle) copies the mark onto
    the flow; the input filter accepts marked flows only; `svc-rev-post`
    and `svc-rev-in` (priority 300, after every NAT hook) rewrite replies
    of marked flows from `node:target` back to `vip:public`. The mark is
    one bit (`0x01000000`), only ever OR-ed in and tested under its mask.
    A new `wireserve-fwd` chain default-denies what the mesh would reach
    *through* the node, which a container's published port is — that was
    open to every peer before, declared or not. Proven first with a
    hand-written ruleset against a netavark-style DNAT in three
    namespaces (`deploy/e2e/run-service-vip-spike.sh`), TCP and UDP, both
    directions, checksums verified.

83. **Rewriting needs the host's own user namespace.** Since the
    "netfilter: disable payload mangling in userns" hardening (in the 7.x
    kernels), nft payload writes fail with EPERM in any network namespace
    owned by a non-init user namespace. A real agent runs as root on the
    host and is unaffected; one in an unprivileged container (LXC,
    rootless podman) fails its firewall step with a message naming the
    cause, and a service with an address is unreachable there. Every e2e
    suite that serves now needs `sudo` (rootful podman, or `unshare -n`
    as root for the multi-instance one). Unit tests in an unprivileged
    namespace check that EPERM on the rewrite statements is the only
    error nft reports, i.e. it parsed and evaluated every statement; as
    root they check the rendered ruleset. A plain-DNAT fallback for
    unprivileged containers (keeping the client address, losing the
    container composition) was considered and left for later.

84. **Coordinator trust for addresses.** `vip::sanitize` is the single
    place the agent checks the addresses it received before WireGuard,
    the firewall and the hosts file act on them: implausible ones
    (loopback, multicast, link-local, …), one equal to any node's
    address, and one given to two services are cleared. A range check
    isn't possible (the agent doesn't know the range) and isn't needed
    for parity: the coordinator could already route any address to a
    peer through that peer's own `ip4`. The coordinator never chooses a
    port that is opened — rules take every port from the node's own
    declarations and only the destination address from the directory —
    and an address missing for a declared service falls back to opening
    its target ports directly, as before addresses existed.
