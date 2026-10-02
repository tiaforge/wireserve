# WireServe — Implementation Status

Living status document. Update the checkboxes and the "Currently working on"
line as part of the commit that makes progress, so work can pause and
resume across sessions without re-deriving context. Full design is in
`wireserve-design-spec.md`; the detailed step-by-step plan that produced
this checklist lives in the session that created it — this file is the
source of truth for *current status*, the spec is the source of truth for
*requirements*.

**Currently working on:** nothing in progress. M39–M41 (end-to-end
relaying: carry interface, phone relays through a carrier's public port, the
gateway retired; items 234–249) are done; plan
`~/.claude/plans/wobbly-roaming-karp.md` (not in the repo).
`run-phone-relay-test.sh`, `run-transit-test.sh`, `run-exit-test.sh` and
`run-nat-test.sh` all pass (2026-09-30).

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
5. **Agent bootstrap command**: `wireserve join <coordinator-url>
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

## M21 — NAT-hairpin fix via LAN-address candidates

85. **A second endpoint candidate: this node's own LAN address.** Two
    nodes behind the same router each used to learn only their WAN
    endpoint — the coordinator's observed address plus the node's own
    declared listen port — which only reaches the other if the router
    supports NAT hairpin/loopback, and plenty don't. Now every agent
    also enumerates its own private-range (RFC1918) IPv4 interfaces
    (`wg::local_lan_ifaces`, a `getifaddrs` walk skipping the mesh
    interface itself and anything that looks virtual — `docker`, `veth`,
    `tun`, `wg`, …) and reports the first one found as `lan_addr` on
    every register/poll, same singular, on-by-default pattern as
    `endpoint_addr_v4`/`_v6`. IPv4 only for v1 — real hairpin is an IPv4
    NAT problem. A receiving node prefers a peer's `lan_addr` over every
    WAN candidate, operator override included, whenever it falls inside
    one of its own local subnets (`wg::is_on_own_lan`) — a direct,
    router-free path is strictly better whenever it is actually offered.
    No coordinator-side negotiation exists or is needed: WireGuard's
    handshake is authenticated, so if one side successfully dials a
    peer's LAN address, that peer's kernel self-corrects its own view of
    the endpoint via ordinary roaming even if its own agent still thinks
    the far side is at its WAN address.

86. **Subnet collisions make a match a hint, not a fact, so the fallback
    had to be real from the start.** `192.168.1.0/24` is the single most
    common home-router default there is; two completely unrelated sites
    can both claim it, and blindly trusting a match would point a node
    at an address that is not its peer at all, wedging that connection
    forever with no recovery. `wg::resolve_lan_candidate` treats a match
    as an optimistic attempt, verified by an actual handshake within a
    60-second grace window (`LAN_GRACE_WINDOW` — long enough for a
    couple of `PersistentKeepalive`-triggered attempts): confirmed, it
    stays on the LAN candidate and resets backoff; not confirmed by the
    end of the window, it falls back to the WAN candidate and schedules
    a retry after an exponential backoff (`LAN_RETRY_BACKOFF_INITIAL` 2
    minutes, doubling to a `LAN_RETRY_BACKOFF_MAX` of 30 minutes) — so a
    persistent false positive costs one brief, infrequent probe rather
    than either permanent failure or hot flapping. A peer reporting a
    different `lan_addr` than last seen (it roamed networks) resets to a
    fresh optimistic attempt rather than inheriting its old failure
    history.

87. **Stays on the same pure/stateful split the rest of `wg.rs` already
    uses.** `local_lan_ifaces` is the one impure piece (the actual
    syscall); `pick_lan_address`, `own_lan_subnets`, `is_on_own_lan` and
    `resolve_lan_candidate` are pure functions over its result, unit
    tested directly including the deliberate subnet-collision false
    positive. The per-peer state itself (`LanEndpointTracker`, keyed by
    pubkey, in-memory only — never persisted, never compared across an
    agent restart) lives beside `WgInterface` in the poll loop, not
    inside it, with the same lifetime as its own `applied`/`routed`.
    `choose_peer_endpoint` gained a third parameter for the resolved
    candidate; the LAN candidate is a bare address, so it borrows its
    port from whichever WAN endpoint field is present rather than
    carrying its own. `desired_peers`/`WgInterface::reconcile` gained a
    `lan_candidates` map, resolved once per poll cycle in
    `poll_loop::run_once` from `tunnel_peers`' kernel handshake read (the
    same one `list` already uses) before reconciliation — proven end to
    end with a kernel-gated test asserting `reconcile` actually
    configures a peer's LAN address, not `endpoint_addr`.

88. **Coordinator side is the same shape as `endpoint_addr_v4`/`_v6`:**
    migration `0007_lan_addr.sql` adds `nodes.lan_addr`; set directly (not
    coalesced) on `/register`, coalesced on `/poll` so a cycle that can't
    read its own interfaces doesn't erase a previously-known-good value;
    validated server-side (`is_valid_lan_addr` — a bare IPv4 literal that
    is actually RFC1918) as defense in depth against a malicious or buggy
    agent claiming a public address as its "LAN" address; and folded into
    `clear_endpoint`'s full-clear (`None` family) branch. `list-peers`
    gained a `lan=` column for parity with `endpoint=`/`v4=`/`v6=`.
    `export-config`/static peers are untouched on purpose: a `kind=static`
    node has no agent and can never run the roaming/staleness logic this
    feature depends on, so its exported config stays WAN-only.

89. **`run-nat-test.sh`'s shared-NAT scenario is the direct regression
    test.** `agent2` and `agent3` already sit behind one simulated router
    with real site-local addresses captured as `AGENT2_LAN`/`AGENT3_LAN`;
    its hairpin check was previously `optional` with a note that v1 had
    no fix for it. Now required, plus a direct assertion that each
    agent's configured `wg show ... endpoints` is the *other's LAN
    address*, not the shared router's WAN address — proving the router
    was bypassed entirely, not merely that connectivity happened to work
    because this particular test router supports hairpin.

## M22 — reflexive (NAT-mapped) address discovery, NAT-traversal step 2

90. **A self-hosted, STUN-like UDP responder, learned once per process
    lifetime.** The only WAN endpoint a node ever reported
    (`endpoint_addr_v4`/`_v6`) was the coordinator's TCP/HTTPS-*observed
    source IP* paired with the node's own *self-declared* `listen_port` —
    never an actually NAT-mapped port, so it was only ever correct for a
    real public IP or a manual 1:1 port-forward. Now the coordinator runs
    a minimal, fixed-size, unauthenticated UDP responder
    (`wireserve_types::reflexive`, `wireserve-coordinator::reflexive`)
    that echoes back the observed `ip:port` — deliberately not real RFC
    5389 STUN, since nothing else needs to interoperate with it — and
    each agent asks it once, from a socket it briefly binds to the exact
    `listen_port` it is about to hand to `wg::WgInterface::bring_up`
    (`wireserve-agent::reflexive::learn_reflexive_addr`), then closes,
    relying on the NAT reusing that port's external mapping moments
    later. Kernel WireGuard (`defguard_wireguard_rs::Kernel`) owns the
    real socket once `bring_up` runs, with no way for the agent to
    multiplex a probe through it the way a userspace WireGuard
    implementation could — this is the reason it can only run once per
    process lifetime (`register::join` and each `cmd_daemon` startup),
    not every poll cycle, and why a NAT remapping later (a router
    reboot) is only recovered by a restart, the same class of limitation
    `listen_port` itself already has. IPv4 only, and skipped entirely
    for a node with real working IPv6 (`probe::has_working_ipv6`).

91. **The UDP responder is a public reflector, so its own size is the
    security mechanism.** An unauthenticated address-echo service is a
    classic reflection/amplification target — an attacker spoofs a
    victim's source address so replies go there instead. Rather than
    rely on rate limiting alone, `RESPONSE_LEN` (19 bytes) is smaller
    than the required fixed `REQUEST_LEN` (64 bytes) by construction, so
    the reflection factor is always under 1x regardless of request
    shape — asserted at compile time (`const _: () = assert!(...)`), not
    merely tested. On top of that, anything malformed or over its
    per-source budget (`SlidingWindowLimiter`, extracted from
    `RateLimiter`'s existing per-source half so the HTTP failed-auth
    delay mechanism — which sleeps inside the caller — is never
    accidentally reused for a UDP receive loop) is dropped silently,
    never with an error reply, since an error reply is still a reflected
    packet.

92. **No new port to track.** TCP and UDP are independent port
    namespaces, so the responder reuses `WIRESERVE_LISTEN_ADDR`'s own
    port number, always bound to every interface regardless of what host
    that TCP listener itself uses (which is commonly loopback/private on
    purpose, spec §7's reverse proxy) — this responder's whole job is
    being directly reachable, so it must never inherit a narrower bind.
    The one new operational fact: a reverse proxy only forwards HTTP, so
    this needs its own direct UDP forward at the firewall/router even
    though it's "the same port" — called out in the startup banner, the
    Quadlet file (two `PublishPort` lines, one per protocol, with
    different bind scopes), the Dockerfile (`EXPOSE .../udp` alongside
    the existing TCP one), and both proxy example configs.

93. **The LAN tracker generalized into a multi-tier one, not duplicated.**
    `LanCandidate`/`resolve_lan_candidate`/`LanEndpointTracker` (M21)
    became `EndpointTier::{Lan, Reflexive, Wan}` /
    `resolve_endpoint_candidate` / `EndpointTracker`, `RANKED_TIERS =
    [Lan, Reflexive]` most-preferred first — a future relay tier (step 3,
    not yet designed) is added to that one list and nowhere else in the
    ranking logic. Every peer's per-tier grace-window/backoff state
    (`TierState`) is now independent, and a real behavioral gap surfaced
    while writing the generalized test suite: roam detection originally
    lived on the single *active* tier only, so a NAT remapping on a tier
    that was currently sitting out a backoff window on `Wan` was never
    even noticed — fixed by moving `last_seen_value` into each tier's own
    `TierState` rather than tracking it once per peer, so a value change
    is detected (and that tier's stale backoff history discarded)
    regardless of whether the tier is presently active. When the active
    tier's grace window expires without a confirming handshake, the very
    same cycle tries the next-best tier rather than waiting a cycle to
    fall to `Wan`, proven by a dedicated tier-advancement test with
    independent backoff timers per tier. `choose_peer_endpoint` gained a
    `Reflexive` branch — unlike `Lan`, it carries its own port, so it
    doesn't need `wan_port`'s borrowing trick.

94. **`run-nat-test.sh`'s no-port-forward pair is the direct regression
    test.** Its simple `masquerade` happened to preserve the WireGuard
    socket's source port, so the pre-existing naive WAN guess was
    *already* accidentally correct there — the harness never actually
    exercised the bug this step fixes. Router-b's rule became `masquerade
    random`, set up before any node registers; the new assertions check
    that `list-peers` records a `reflexive=` port different from the
    node's own `listen_port` (proving the guess really would have been
    wrong), and that agent1 — which shares no LAN with node2/agent2, so
    only the WAN tier is in play — actually dials node2 at that reflexive
    address rather than the naive one.

## M23 — opt-in single-hop transit, NAT-traversal step 3

Symmetric NAT (both sides, no shared LAN — the case M21/M22 cannot solve:
a symmetric NAT maps a different external port per *destination*, so the
reflexive port either side learns talking to the coordinator is useless
to the other) is bridged via true multi-hop routing through an
already-connected third mesh member, using WireGuard's own `AllowedIPs`
as both an outbound routing table and an inbound cryptographic source
filter — no new relay server, no new protocol, no port pool.

95. **The coordinator-hosted blind-relay draft was designed in full, then
    rejected.** The first complete design was a coordinator-owned UDP
    relay with its own dynamic port pool and session table. Rejected
    because it would have been the first time the coordinator ever
    touched live mesh traffic — breaking the project's own stated
    principle that the coordinator is a plain HTTP control plane that
    never touches WireGuard, the firewall, or live traffic — and because
    it concentrated relay bandwidth on one process instead of spreading it
    across the mesh the way the adopted design does. Naming is
    deliberately **"transit," never "relay,"** throughout the code and
    this log, specifically so this pivot stays legible to a later reader
    and the rejected shape is never accidentally resurrected.

96. **Transit is a routing overlay, not a fourth `EndpointTier`.** It
    reroutes `AllowedIPs`, never `Endpoint=`, so `EndpointTier::{Lan,
    Reflexive, Wan}` and `choose_peer_endpoint` are untouched.
    `wg::desired_peers` became a two-pass builder: pass 1 is the
    unchanged single-pass logic, run only for peers that are *not* a
    transited key this cycle; pass 2 folds a transited peer's address(es)
    and owned VIPs into its `via` peer's already-built entry instead of
    giving the transited peer a kernel entry of its own. A transited
    peer's own entry is dropped entirely while transit is active — no
    wasted entry, no keepalive noise for a connection deliberately not
    dialed directly. `wg::desired_routes` needed **no change at all**: it
    already flattens every peer's `AllowedIPs` regardless of whose entry
    an address sits under, confirmed by reading the code before writing
    any of this, not assumed.

97. **Discovering "am I the transit carrier" needed its own signal — the
    original plan's own wording was ambiguous about this and got fixed
    while implementing.** A node picked as `via` for a pair always
    already reaches both endpoints directly (that is `TransitState::select`'s
    own requirement), so its own peer-a/peer-c entries never need routing
    help and so never carry a `transit_via` of their own — a bare
    `transit_via` can structurally never fire on the carrier's own poll
    response. Fixed with a dedicated field: `PollResponse::transit_carrying:
    Vec<TransitPair>`, populated only in the *carrier's* own response,
    listing every pair it must forward between this cycle. The requester
    side keeps the original design: `PeerInfo::transit_via: Option<String>`,
    computed fresh per (requester, peer) pair every poll, `None` meaning
    "dial directly," exactly as before.

98. **`TransitState` (`wireserve-coordinator::transit`) is ephemeral,
    in-memory, never the database** — same shape as `RateLimiter`'s own
    `AppState` field, not a `NodeRow` column or a migration, unlike
    `lan_addr`/`reflexive_addr` (M21/M22), which are durable identity
    facts worth surviving a coordinator restart. Every report here is
    refreshed on a ≤20s cycle and meaningless once stale. `select(a, c,
    fresh_secs)` is a pure function of the current snapshot: capable,
    fresh, reaches both, never either endpoint itself, tie-broken
    deterministically by pubkey ascending — the determinism is what lets
    `a`'s poll and `c`'s poll, landing on whatever cycle each happens to,
    independently converge on the same `via` with no coordination between
    them. `either_wants(a, c)` checks both sides' independently-stored
    reports, so the *first* side to give up on a peer drives both
    directions to a `transit_via` on their own very next poll, rather than
    requiring both sides to time out in the same window. Revoke calls
    `TransitState::forget`, so a revoked node's stale report can't linger
    and still get selected for up to one `online_threshold_secs` window.

99. **A real security regression was found and fixed during this review,
    before any of it shipped, by re-reading `nftables.rs`'s own
    `apply_batch` doc comment.** The `wireserve-fwd` FORWARD chain's base
    policy is deliberately `accept` — a past live-deployment bug (see
    M11's own decisions log) taught this project that a stricter base
    policy silently firewalls off traffic on *every* interface, not just
    the ones the chain's own rules `iifname`-match, because a base
    chain's policy is global. The first draft of transit's `ip_forward`
    module wrote the host's *global* forwarding switches
    (`net.ipv4.ip_forward`, `net.ipv6.conf.all.forwarding`). Combined with
    the accept-by-default base policy, that would have let any multi-homed
    transit-enabled host (a second NIC, a LAN, a container bridge) forward
    traffic freely between its *other* interfaces too, the instant transit
    turned the global switch on — an unintended "this node becomes an open
    router" regression with no corresponding opt-in, on any host with more
    than one network interface. **Fixed**: `firewall::ip_forward::set_enabled`
    writes the wg interface's own per-interface forwarding files
    (`/proc/sys/net/{ipv4,ipv6}/conf/<ifname>/forwarding`) and never the
    `all`/global ones — mirroring the same interface-scoping discipline
    the firewall rules already apply. A real kernel test
    (`set_enabled_scopes_forwarding_to_the_named_interface_only`, two real
    dummy interfaces in a fresh network namespace) pins this down as a
    regression guard, not just a doc comment.

100. **The `in` operator against an address set needed nft's `Set`
    literal, not a bare JSON array — caught by a real kernel, not assumed
    from documentation.** `established_or_related()`'s own `ct state { … }`
    match works with a plain `Expression::List` because `ct state` is a
    bitmask/flags-typed field; the transit forward rule's `ip saddr`/`ip
    daddr in { … }` match against a *non*-bitmask (address) type does not
    — a real `nft` refused it with "Basetype of type IPv4 address is not
    bitmask." Fixed by building an anonymous `NamedExpression::Set`
    (`{"set": […]}`) instead, which is what
    `kernel_accepts_a_transit_pairs_ruleset` exists to keep catching if it
    regresses.

101. **Wire fields, all `#[serde(default)]`, no behavior change alone.**
    `PollRequest` gains `transit_capable`/`transit_reachable`/
    `transit_wanted` (both capped at 64, matching `MAX_SERVICES_PER_NODE`'s
    own precedent); `RegisterRequest` gains `transit_capable` (always
    `false` at join time — opt-in is a live, post-join decision, never an
    identity fact); `PeerInfo` gains `transit_via`; `PollResponse` gains
    `transit_carrying`. `GET /admin/peers` leaves `transit_via` always
    `None` on purpose — an admin isn't "a requester" polling on behalf of
    a specific node, so there is no requester to compute it relative to.

102. **Opt-in is a live IPC toggle, not a join-time flag** — `wireserve
    transit on|off`, `IpcRequest::TransitCapable`, `AgentState::transit_capable`
    (`#[serde(default)]`) — same shape as `serve`/`unserve`: mutates the
    running daemon directly, takes effect next poll, no rejoin. Motivated
    directly by the user: a node with a traffic cap is an operational fact
    that should flip without a rejoin, not an addressing fact resolved
    once at bootstrap the way `--endpoint-addr` is.

103. **One question raised and explicitly settled, not left as a gap: A
    and C (the transited pair) get no opt-in or opt-out of their own,
    only B's opt-in gates anything.** This is a private mesh where every
    member already trusts every other member equally; B seeing A/C's
    mesh-layer plaintext is exactly the new trust surface B's own opt-in
    is meant to gate, and a separate per-node "allow being transited"
    flag was deliberately not added.

Explicitly out of scope, same as originally planned: multi-hop
pathfinding beyond one transit hop; automatic/mandatory transit selection
(opt-in only, full stop); bandwidth accounting/metering for transit nodes;
NAT-type classification (still relies on tier grace-window/backoff
discovery instead, consistent with M21/M22).

`deploy/e2e/run-transit-test.sh` (new, sibling to `run-nat-test.sh`)
**passes** as of 2026-09-25, once the harness let the agent write
`/proc/sys/net` (see M27's closing note).

## M24 — refreshable static peers, and gateway routing for them

Spec §9 accepted two consequences for v1 that turned out to be the sharpest
remaining friction in the product, both of them about phones. The config is
a snapshot, so a node added later is unroutable from the device until it is
re-exported and reimported; and re-exporting was `revoke` → `delete-node` →
`export-config`, which minted a new keypair *and* could renumber the device,
because deleting the row frees its addresses back to the allocator.

104. **A `.wg` DNS responder was designed, researched, and ruled out on
    evidence before any of this was written.** The obvious third fix —
    answer `<name>.wg` on a node and point phones at it with `DNS =` — is
    not available with the official clients, and this is worth recording so
    it is not re-proposed. `wireguard-apple` sets `dnsSettings.matchDomains
    = [""]` unconditionally whenever `DNS =` holds any IP
    (`PacketTunnelSettingsGenerator.swift`), which is Apple's sentinel for
    "this resolver answers everything"; its parser has no tilde/split
    handling. `wireguard-android` only calls `addDnsServer()` and
    `addSearchDomain()` — `VpnService.Builder` exposes no match-domain API
    at all, so no version of that app could do it. The tilde split-DNS patch
    lives in a fork and a January 2022 mailing-list thread, unmerged four
    years on. So a `.wg` resolver would capture *all* of the device's DNS,
    and an authoritative-only server returning NXDOMAIN for everything else
    would break the rest of its internet — a negative answer is a
    *successful* transaction, so resolvers do not fall back, and listing a
    second server does not rescue it. This vindicates §6's "resolver in the
    query path" rejection rather than contradicting it: on a Linux host you
    can at least scope a stub resolver to one domain, and on iOS/Android you
    cannot. Names for phones are a reverse proxy plus one public wildcard
    record, later, with no port 53 anywhere.

105. **Spec §9's "WireGuard requires non-overlapping `AllowedIPs`" was
    wrong, and it was the sentence ruling out this whole design shape.**
    Verified on a real kernel in a netns rather than argued: *identical*
    prefixes do collide (assign `10.1.0.5/32` to two peers and the later one
    takes it, the first left with `(none)`), but prefixes of *different*
    lengths coexist — cryptokey routing is a longest-prefix-match trie, so
    `10.1.0.0/24` on one peer and `10.1.0.5/32` on another both survive. A
    gateway peer holding the whole mesh range alongside per-node /32s is
    therefore available. The spec is corrected in place.

    The corollary is what the rest of this milestone turns on: **WireGuard
    has no failover.** The longest match wins whether or not that peer is
    reachable, so a /32 aimed at a dead path black-holes rather than falling
    through to a covering route.

106. **Gateway routing is the existing transit feature, not a second one.**
    No `gateway on|off`, no `approve-gateway`, no new node flag for the
    *carrier* side. A gateway forwards traffic it can read and could forge
    either end of — the same trust surface `approve-transit` exists to gate
    (#99, security review finding #1) — so it is gated on the same approval.
    The forwarding rules ride on `PollResponse::transit_carrying`, which the
    agent already turns into nft rules and already uses to drive
    `ip_forward::set_enabled`, and reachability rides on
    `PeerInfo::transit_via`, which `wg::desired_peers` pass 2 already folds
    into the via peer's entry. **The entire mesh side needed zero agent
    changes** — confirmed by reading `poll_loop.rs`'s
    `TransitAssignments` construction (self-exclusion is its only filter),
    not assumed.

107. **The rule the feature lives or dies on: `transit_via` is set for
    exactly the peers *absent* from the device's config.** `desired_peers`
    pass 1 skips any peer carrying a transit assignment — it *deletes* that
    peer's kernel entry rather than merely hinting a route. Combined with no
    failover (#105), naming a peer that IS in the config makes that peer
    drop the device while the device still dials it directly, since its /32
    outranks the gateway's covering route. Every direct peer would become a
    black hole, and the hybrid config would be strictly worse than routing
    everything through the gateway. The first draft of this plan said "set
    it for every requester except the gateway," which is exactly that bug;
    it was caught in review before implementation.

108. **Config membership is recorded at export time, in
    `static_conf_peers`, not recomputed from live endpoint state.** The
    `.conf` is a snapshot, so which peers it contains is a fact about a
    moment. A live predicate drifts against the file actually on the device,
    and the drift is not symmetric: a node that *loses* its endpoint after
    export merely goes stale, which is what already happened before this
    milestone — but a node that *gains* one would stop being routed through
    the gateway while the device still has no direct entry for it, so the
    forwarded packet is rejected on the crypto source filter at one end and
    there is no path at the other. Broken both ways, silently. Persisting
    the list costs one table and removes the whole class.

109. **A dangling gateway erases the device from the mesh, so the gateway is
    resolved against the live directory on every poll rather than trusted
    from the stored id.** Pass 1 skips a transited peer and pass 2 bails
    when the via peer is missing from the map, so a `transit_via` naming a
    node no longer in the directory leaves the device with *no* entry
    anywhere — not a degraded one. `ON DELETE SET NULL` does not cover this:
    `revoke` keeps the row and drops out of `list_all_peers` instead. One
    live check (present *and* still `transit_approved`) covers revoke,
    `deny-transit` and a gateway that never re-registered, and degrades to
    an ordinary direct entry. `delete-node` additionally 409s while devices
    depend on it, mirroring its existing "revoke it first" guard; `revoke`
    and `deny-transit` only warn, because neither may ever be blockable by a
    routing dependency.

110. **Eligibility is stricter than "has an endpoint," which is the subtle
    half.** `is_valid_endpoint_addr` permits RFC1918 deliberately — an
    endpoint is self-reported and a node on a home LAN legitimately
    advertises `192.168.1.50:51820` to its neighbours there. A naive "has an
    endpoint" gate would mint a /32 for it in a phone's config that
    outranks the gateway's route and black-holes the moment the phone leaves
    that LAN, which is precisely what the hybrid shape exists to avoid. New
    `is_globally_routable_endpoint` rejects private, loopback, link-local,
    unspecified, multicast, CGNAT (`100.64/10` — behind someone else's NAT,
    spelled out because `Ipv4Addr::is_shared` is still unstable) and IPv6
    unique-local; a hostname is taken at its word, since resolving it here
    would only answer for this machine. Documentation ranges are
    deliberately *not* rejected: unlike the rest they say nothing about
    reachability, and they are what this project's tests use throughout to
    mean "a public address."

111. **`rejoin` grew a `kind` check, and it had to go before the mutation,
    not at `/register`.** A rejoin nulls the pubkey and `list_all_peers`
    filters on `pubkey IS NOT NULL`, so `export-config --refresh` aimed at
    an agent node would kick a live node off every other node's directory
    and *then* fail with the mismatch registration would have caught. The
    admin CLI cannot pre-check it: `PeerInfo` carries no `kind`, and a
    separate lookup would race the rejoin. `kind` is optional on
    `RejoinRequest`, so a bare `rejoin` is unchanged. For the same reason
    the whole export flow reads the directory and picks its gateway
    *first* — everything that can fail happens before anything mutates.

112. **No new wire field for the mesh range.** `RegisterResponse` already
    carries `MeshInfo` so an agent can pin it (security review finding #4),
    and the export flow already calls `/register`. `MeshRanges` gained
    `v4_cidr()`/`v6_prefix()`, which rebuild canonical `network/len` strings
    from the parsed value — the mesh range reaches the coordinator from an
    env var or the bootstrap file with no structural validation (the startup
    checks only warn), so it is exactly the kind of value that must come
    back out of a parser before reaching a `.conf`. The same pass fixed
    `render_conf` interpolating `ip4`/`ip6` verbatim, which the module's own
    doc comment already claimed it did not do.

113. **A pre-existing endpoint-selection bug was promoted to critical and
    fixed.** `render_conf` took `endpoint_addr` verbatim while
    `wg::choose_peer_endpoint` guards it with a bracketed-v6-literal check
    plus `prefer_ipv6`. `endpoint_addr` is recorded family-blind, from
    whichever family the node's poll arrived over. As one peer among many
    that mis-picks one entry; as *the gateway* it is the entire config, and
    a phone on v4-only cellular gets a dead file. The renderer now applies
    the same rule.

114. **The QR limit is terminal width, not QR capacity** — found while
    sizing it, and it changes the answer. A code is `4·version + 17` modules
    square plus a 4-module quiet zone, and half-block characters only halve
    the *vertical* extent, so a config comfortably inside byte-mode capacity
    (2953 bytes at version 40) would still need ~185 columns and scan off
    nothing. `--qr` caps at 116 columns (~version 22) and refuses with the
    byte count and a pointer to `--out` rather than printing something
    unscannable. Colours are written explicitly per cell: bare block
    characters inherit the terminal theme, so the same output would scan on
    a light background and be inverted, hence unscannable, on a dark one.
    `qrcodegen` was chosen over `qrcode` (last release 2021, and QR is a
    frozen spec so that means complete rather than rotten) for having zero
    transitive dependencies.

115. **One gap found and left documented rather than fixed.** The agent
    opens the *host* firewall's FORWARD hook from its own local
    `transit_capable`, captured once at daemon start
    (`HostInterop::start`), while the coordinator-driven forwarding path is
    not gated on local opt-in at all. A node approved as a gateway but never
    switched on with `wireserve transit on` would accept the forward
    in its own nftables table while ufw or firewalld still dropped it —
    invisible from every other node. Rather than make `forward_wanted`
    dynamic, `set-gateway` refuses a node that is not *currently* reporting
    `transit_capable` (new `TransitState::is_offering`) and says exactly
    which two commands to run. Nested transit is also not composed: if a
    node reaches the gateway only via dynamic transit, pass 2's lookup misses
    and the device is dropped from that node. It fails closed rather than
    misrouting, and "the gateway must be directly reachable by every node"
    is the documented precondition.

Explicitly out of scope: `.wg` names for static peers (see #104 — a reverse
proxy and one public wildcard record, later); adopt-your-own-pubkey for
static peers; more than one gateway per device; agents routing through a
gateway (only `kind=static` peers do).

`deploy/e2e/run-gateway-test.sh` **passes** as of 2026-09-25, with the same
harness fix as `run-transit-test.sh`.

## M25 — service FQDNs, and publishing them through a reverse proxy

M24 gave a phone *reachability*; it still had no *names*, because `.wg` lives
in `/etc/hosts` and a phone has none. #104 had already ruled out the mesh
resolver on client-implementation evidence and named the alternative — "a
reverse proxy plus one public wildcard record, with no port 53 anywhere".
This is that, and the shape it settled into is narrower and cheaper than the
plan it started from.

116. **Publishing TCP 443 is the opt-in, and it is an existing field.** The
    first design had no opt-in at all and published every service; that gives
    an SSH or Postgres service a public hostname, an ACME order and a vhost
    that answers HTTP at something which is not HTTP. The second had a new
    per-service attribute, which means a wire field, a migration, a `serve`
    flag and an admin surface. Using the *published port* costs none of that:
    `serve plex 443:32400` says "serve this under its name with TLS" and
    `serve prom 80:9090` says "internal". The proxy still speaks plain HTTP
    to the backend — 443 is the published port, which the owning node's
    existing rewrite maps to whatever the service really listens on, so there
    is no second TLS hop and no certificate to verify inside the mesh.

117. **The suffix is replaced, not supplemented, and that is the point.**
    `<name>.wg` becomes `<name>.<domain>` when a domain is set. Keeping both
    was the original plan and it is wrong for a reason that has nothing to do
    with tidiness: an application has *one* configured base URL — Gitea's
    `ROOT_URL`, Grafana's `root_url`, an OIDC `redirect_uri` — so a second
    working name is not a convenience, it is sessions and redirects bouncing
    between two origins. One service, one name.

    Which address that name points at then falls out per service rather than
    globally: a 443 service resolves to the proxy from everywhere, so one base
    URL is correct from a node and from a phone; anything else resolves to its
    own address from everywhere, keeping the direct path, the real client
    address and no hop. Neither ever has two names. The cost, stated plainly:
    a non-443 service is not reachable *by name* from a device with no hosts
    file. It is reachable at `address:port`, and publishing it on 443 is how
    you ask for the name.

118. **The domain is mesh-wide and comes from the coordinator; the proxy
    configuration is written by the agent.** These are different questions and
    got different answers. Nodes that disagreed about the suffix would
    disagree about their own services' names, so `WIRESERVE_SERVICE_DOMAIN`
    and `WIRESERVE_SERVICE_PROXY` ride the poll and register responses exactly
    as `MeshInfo` does (#4's precedent), with no DB, no per-service column and
    no admin verb. But the coordinator cannot write a file on the proxy node —
    it usually is not the proxy node, there is no push channel, and #95
    rejected the coordinator-hosted relay precisely because it would have been
    the first time the coordinator touched anything live. The agent already
    receives the directory every poll and already renders it into a managed
    file; `hosts.rs` is the template.

    `WIRESERVE_SERVICE_PROXY` names the *service*, not the node: the proxy is
    reached at a service address, a node could publish several things on 443,
    and it is the same value that goes in the wildcard DNS record.

119. **Matchers inside one wildcard site block, never a site block per
    service.** `plex.int.example.com { … }` is more specific than the
    operator's `*.int.example.com`, so Caddy would try HTTP-01 for it — which
    cannot work for a name resolving to a mesh address — and one site block
    per service is also one ACME order per service, against Let's Encrypt's
    fifty-certificates-per-registered-domain-per-week limit. One wildcard
    certificate covers every service that will ever exist.

120. **The DNS record points at the proxy's service address, not its node
    address.** `ServiceRule::Mapped` opens `vip:public` and deliberately
    refuses `node:target`, so a wildcard aimed at the node's mesh address is
    dropped by that node's own firewall. Documented in the README and in
    `deploy/proxy/Caddyfile.services.example`, because the failure looks like
    a proxy problem and is not one.

121. **A proxy failure is a warning, never a failed step.** `run_once` returns
    before persisting `last_directory` when any step fails, so folding the
    proxy into `failures` would freeze `wireserve list` on a stale
    directory whenever Caddy was down — a baffling symptom for an unrelated
    cause. The proxy is a convenience layer on a working mesh and must not
    degrade the mesh's own bookkeeping. It is retried every cycle regardless,
    because the backend compares against what is on disk rather than what it
    last wrote. `publish_to_proxy` returns `()` for exactly this reason, and
    is its own function so that is testable.

122. **The generated file is owned outright, and a bad one is rolled back.**
    It is a whole file in `/etc/caddy/conf.d/`, not a managed block in a
    shared one: teardown is an unlink and there is no need for `hosts.rs`'s
    flock dance, which exists only because every instance shares one
    `/etc/hosts`. `fsutil::atomic_write` stages at `.<name>.tmp`, so an
    `import conf.d/*.caddy` glob can never pick up a half-written file —
    pinned by a test, since the alternative is a proxy that occasionally loads
    a truncated config. On a failed `validate` or `reload` the previous bytes
    are restored: Caddy's reload is atomic and keeps the running config, so a
    bad fragment cannot take the proxy down *now*, but left on disk it would
    take it down at the next restart — a reboot or a package upgrade, hours
    later, with nothing connecting it to this agent.

123. **Teardown only on an explicit `leave`.** Every daemon restart runs
    `teardown_everything` too, and removing the vhosts to re-add them seconds
    later means two reloads and needless re-provisioning. Gated on
    `reset_state`, the same distinction that path already draws for state.

124. **Deliberately not filtered on `ServiceInfo::online`.** A flapping node
    would otherwise rewrite the configuration and reload the proxy on every
    transition. A name resolving to a service that is down is a 502, which is
    a better failure than a name that comes and goes.

125. **`ProxyBackend` is agent-local, unlike `FirewallBackend`.** That trait
    lives in `wireserve-types` for two stated reasons — a future Windows
    implementation, and avoiding an orphan rule around `ServiceRule` — and
    neither applies here: one implementation by decision, and `ServiceInfo`
    already lives in types. It stays a trait only so `run_once` has a fake to
    test against, which is the same reason `FirewallBackend` has one. Its
    error is a boxed `dyn Error` rather than an associated type, because the
    poll context holds it as `Option<&mut dyn ProxyBackend>` — the proxy is
    genuinely absent on almost every node — and an associated type is not
    object-safe.

126. **The port-sharing fix that was going to ride along does not work, and
    the investigation is worth keeping.** The idea was to match a reply on
    `ct original ip daddr == vip` rather than `(saddr == node, sport ==
    target)`, freeing several services on one node to share a target port.
    `svc-pre` runs at `PRIO_RAW` (−300) and conntrack registers at −200, so
    the tuple conntrack records is already the rewritten one and `ct original`
    names the node for every mapped service. `ct_original_daddr()` at
    `nftables.rs:477` is the *inverse* case — it matches a container runtime's
    DNAT at −100, after conntrack — so the precedent does not transfer.
    Moving the rewrite later does not help either: conntrack would then expect
    a reply from `vip:public`, the real reply from `node:target` would match
    nothing, and `ct direction reply`, the ct mark and the runtime's own NAT
    would break together.

    The replacement, a per-mapping index in the mark, has three problems that
    together make it its own milestone: nft refuses a binary operation whose
    right operand is another register, so the carry rule must fan out to one
    rule per index; 128 index values do not cover 64 services × 16 ports; and
    the ruleset is full-replaced every poll while conntrack entries outlive
    it, so an index assigned by position renumbers on an unrelated `serve` —
    `ipc/server.rs` does `retain` then `push` — and silently misroutes or
    blackholes open flows on *other* services. Doing it properly means
    persistent index slots in `AgentState` keyed by `(name, public, target,
    proto)`, indexing only where a collision actually exists, and refusing at
    `serve` time on exhaustion. That is the packet-rewrite core, where #99
    records a security regression, and it needs its own kernel tests.

Explicitly out of scope: a mesh DNS resolver (#104, still ruled out); per-node
TLS termination with every service on its own `VIP:443` (needs the port fix
above *and* per-service DNS records, since a wildcard cannot point at
different addresses); more than one proxy per mesh; non-HTTP services by name.

`deploy/e2e/run-proxy-publish-test.sh` is **not yet written** — the unit and
integration tests cover rendering, selection and the warn-only property, but
nothing has yet driven a real Caddy with a real certificate.

## M23 follow-up — the transit opt-in was only half live

Found on a real mesh, not by a test: `lego2` could not reach a service on
`minipc`, which it routes through `hetzner`; the same service was reachable
from `hetzner` itself, and turning ufw off on `hetzner` fixed it.

127. **Two decisions contradicted each other, and the host firewall lost.**
    #102 made `transit on` a *live* IPC toggle — "mutates the running daemon
    directly, takes effect next poll, no rejoin". `HostInterop::start` took
    the opposite view in its own doc comment: `transit_capable` is "set once
    at join time and never changed for the life of a running agent, so it is
    safe to capture once here rather than re-read every reconcile". It never
    was.

    So opting in moved everything the *coordinator* drives — the node is
    selected as a carrier, gets its `transit_carrying` pairs, writes accept
    rules into its own `wireserve-fwd` chain, enables forwarding on the wg
    interface — while the one thing driven by *local* state, opening the host
    firewall's FORWARD hook, stayed shut until the daemon happened to
    restart. ufw's `FORWARD DROP` then ate every forwarded packet. Nothing
    logs, nothing fails, and the symptom appears on a third node: the pair
    being carried simply cannot reach each other, and the carrier looks fine
    because its own table really does accept the traffic.

    Fixed by passing the current opt-in on every tick rather than capturing
    it at startup: `Msg::Tick { forward_wanted }`, `InteropHandle::tick` takes
    it, and the worker reconciles when it changes. Still gated on the opt-in
    rather than on `transit_carrying` being non-empty, so the footprint stays
    stable instead of flapping as pairs come and go, and a node that never
    opts in still has exactly the footprint this module had before transit
    existed.

    `kernel_opting_into_transit_opens_the_forward_hook_without_a_restart`
    pins it against a real kernel, on a ufw-shaped host with `FORWARD DROP`:
    started opted out, nothing in FORWARD; `tick(true)`, the rule appears
    pinned to `-i wg0 -o wg0`; `tick(false)`, it goes again.

    This is the same class of gap as #115, which caught the *other* half at
    plan time — a node approved as a gateway but never switched on locally —
    and answered it with a check at assignment time. Both come from the same
    root: local opt-in and coordinator-driven behaviour are two halves that
    have to agree, and only one of them was live.

## Host-firewall interop — the ruleset reader's memory

Found on a real node, not by a test: `wireserve-agent` sat at 215 MB RSS on
one host while every other node stayed at 10-30 MB. Restarting it and
replacing the binary changed nothing, which is what made it look like a
leak rather than a cost.

128. **The reader parsed the whole ruleset to keep three kinds of object.**
    `ruleset::parse` read `nft -j list ruleset` into `Document { nftables:
    Vec<Value> }` and *then* picked out tables, chains and rules. The node
    in question runs crowdsec and geoip-shell, whose blocklists and country
    sets are hundreds of thousands of elements — 4.4 MB of the JSON — and
    every one of them was parsed into a `serde_json::Value` (a `BTreeMap`
    node per object, ~600 bytes for a one-entry map) and dropped again
    unread.

    Three things turned that into a permanent number. The document is read
    on every reconcile, which is every poll tick plus every debounced `nft
    monitor` event, and geoip-shell rebuilding its tables trips the monitor.
    Freeing it gives nothing back: these are millions of small allocations
    that glibc keeps in its arena free-lists, so RSS is a high-water mark
    (`malloc_trim(0)` on the live process returned 350 MB of a 362 MB
    measurement, which is how the diagnosis was confirmed — the memory was
    dead, not held). And `HostInterop::start` reconciles synchronously
    before the interface comes up, so a fresh process is back at the mark
    within a second — hence a restart that never helped.

    Fixed by never building the parts we discard: `Object`/`Objects`/
    `Document` are hand-written `Deserialize` impls that stream the
    `nftables` array and hand anything that is not a table, chain or rule
    to `IgnoredAny`, which serde_json skips without allocating. The three
    kinds we keep still go through `Value` and `from_value`, because that
    is what makes an unrecognised *shape* skippable rather than fatal —
    a failed `Deserialize` ends the document, a failed `from_value` ends
    one object — and their cost is bounded by the host's rules, not its
    sets.

    Measured on a fixture shaped like that host (4.3 MB, set-heavy): 215 MB
    before, ~6 MB after. What remains scales with rules, not elements —
    about 5 KB per rule, nearly all of it the `expr: Vec<Value>` that
    `planner`'s shape matching needs.

    `set_elements_cost_nothing_to_skip` pins it with a thread-local
    counting allocator: parsing a 2 MB set-heavy document must allocate
    less than a quarter of its size. It allocates 9 KB; before this it
    would have been tens of MB.

129. **The same flaw in the monitor's filter, and there it was bigger.**
    #128 took the agent on that host from 215 MB to 70 MB, with a 169 MB
    peak — against 85 KB of ruleset that the reader actually keeps, so the
    ruleset was no longer what cost anything. The peak was one line.

    **(Corrected by #131: nft does not in fact emit such lines — the
    measurement below was made against a synthetic one. The change stands
    as a CPU and robustness win; the memory claim here does not.)**

    `nft -j monitor` emits one JSON object per netlink message, and a bulk
    element add was believed to be *one* message: geoip-shell loading a
    country set, or crowdsec reloading a blocklist, arriving as a single
    line megabytes long. `is_relevant` parsed each line with `serde_json::from_str::<Value>`
    and then looked at two keys — so the most expensive line the agent ever
    sees was built in full in order to discover, from its second key, that
    it is an element event and ignored. Measured: one 4.2 MB line cost a
    143 MB peak; a 12.6 MB line, 427 MB.

    That it is *ignored* is what hid it. Element churn never reaches the
    debouncer, so nothing reconciles, nothing logs, and the only trace is a
    high-water mark that outlives the burst — which is why this looked like
    a plateau the agent settled at rather than a spike.

    Fixed the same way as #128: `Event`/`Body` read the outer key and the
    object kind and hand everything else to `IgnoredAny`, with the two
    bodies we do read derived (serde's unknown-field path is `IgnoredAny`
    too, so a rule's `expr` and an element event's `elem` cost nothing).
    Ten 4.2 MB events in a row now peak at 6 MB — the line buffer itself —
    and allocate 0 KB beyond two short keys.

    `a_bulk_element_event_costs_nothing_to_ignore` pins it with the same
    counting allocator, now `crate::test_alloc` so both readers share it.

    Both fixes are the same lesson: a reader that discards most of its
    input must skip as it reads. Parsing first and selecting afterwards is
    a cost proportional to the *host's* other tools, not to anything this
    agent does, and glibc turns that cost into a permanent one.

130. **The bill moved to `nft`'s own processes, and `-t` pays most of it.**
    After #128 and #129 the agent itself was 27.7 MB on that host, but the
    operator sees the unit: `Memory: 57.5M (peak: 102.9M)`. A cgroup counts
    the children, and this module runs two — `nft -j list ruleset` on every
    poll tick, and the `nft -j monitor` that stays up.

    Measured in a netns holding a 100k-element set (numbers are the child's
    peak RSS):

    | invocation | peak |
    | --- | --- |
    | `nft -j list ruleset` | 124 MB |
    | `nft -t -j list ruleset` | 11 MB |
    | `nft -j list chains` / `list tables` / `list chain <one>` | 10-11 MB |
    | `nft -j monitor` (idle, any variant) | 118 MB |

    `-t` leaves out set *elements* and nothing else — tables keep their
    flags (checked: a dormant table still reports them), chains their hook
    and type, rules their full expressions — which is exactly the line
    between what `planner` reads and what it never did. So `observe` asks
    for the terse listing, with one fallback: an `nft` that rejects `-t`
    gets the plain listing immediately and from then on, because a host's
    nft version is the host's business and failing to observe means failing
    closed.

    `kernel_a_hosts_set_elements_are_never_listed` pins it against a real
    kernel on a geoip-shell-shaped host, and
    `an_nft_without_terse_falls_back_once_and_stays_fallen_back` pins the
    fallback against a fake `nft` that rejects the flag.

    **Not fixed: `nft -j monitor` costs what it costs.** It builds the full
    ruleset cache — every set element — at startup, and neither `-t` nor
    narrowing it (`monitor rules`, `monitor ruleset`) changes that; all four
    variants sat at 117-118 MB. It is the one child that stays resident, so
    on such a host it is the agent's floor. Replacing it with a netlink
    listener of our own (`NETLINK_NETFILTER`, `NFNLGRP_NFTABLES`, the
    message type and a TLV walk for the table name — no cache, no JSON) is
    the way out, and the crate already has `netlink-sys`; deliberately left
    for a decision of its own rather than folded in here.

131. **Correction to #129: `nft -j monitor` does not emit huge lines.**
    #129 said a bulk element add arrives as one line megabytes long, and
    quoted 143 MB for a 4.2 MB line. The 143 MB is real but the line was
    synthetic — one this author constructed, not one nft was ever observed
    to print. Measured against a real kernel afterwards (nftables 1.1.6):

    | what happened | what the monitor printed |
    | --- | --- |
    | 50k elements added to a plain set in one transaction | 50,000 lines, longest 117 B |
    | 30k elements added to an `interval` set in one transaction | 30,000 lines, longest 140 B |
    | a rule carrying a 30k-element anonymous set | 1 line, 249 B |

    The kernel multicasts one message per element and nft renders one line
    per message, so the volume is in the *count*, not the size. On the same
    50k lines the old `Value`-based filter and the new streaming one both
    peak at 18 MB — identical. The memory saving #129 claimed was not there
    to save, and the drop the operator saw between those two measurements
    (169 MB peak to 102.9 MB) is better explained by the unit's peak
    counter resetting on restart and by what the `nft -j list ruleset`
    child happened to do in each window — which #130 then removed outright.

    What #129 did buy, measured on those same 50k lines: 25 ms of parsing
    becomes 8 ms, and the filter stops caring how long a line is — a
    property worth keeping precisely because the shape of nft's output is
    not ours to guarantee. It stays, with its reasoning corrected rather
    than its code.

    The lesson is about the evidence, not the code: #128's numbers came
    from the host's own `nft -j list ruleset` output and held up; #129's
    came from a fixture built to match a guess about a format, and a
    fixture will always confirm the guess that shaped it. A claim about
    what another tool emits has to be measured against that tool.

## The host firewall's event listener

132. **Listening to the kernel instead of running `nft monitor`.** #130
    left one cost that still grew with the host's other tools: the
    `nft -j monitor` child fetches the whole ruleset cache — every element
    of every set — at startup and holds it. 118 MB on a 100k-element host,
    and neither `-t` nor narrowing it (`monitor rules`, `monitor ruleset`)
    changed that; all four variants measured 117-118 MB. It was also the
    last piece whose size was decided by how long crowdsec's blocklists
    happen to be.

    The kernel multicasts every nftables change on `NFNLGRP_NFTABLES`, so
    `monitor` now binds that group itself. One socket, one 64 KB buffer,
    and a filter that reads three things out of a message: the type (is it
    a table, chain or rule change), one byte of family, and the table's
    name. A blocklist reload is tens of thousands of messages dropped on
    the type alone. Measured on the same host as above: **2 MB, unchanged
    after a 50k-element reload** — against 118 MB, and against the JSON
    rendering of every one of those events that used to be parsed.

    Deliberate choices:
    - **`ENOBUFS` reconciles.** A multicast socket can overflow during a
      burst, and what was dropped is unknowable, so it counts as a change.
      With the child this was invisible — nft's socket overflowed and we
      simply never heard about it. Same for a message larger than the
      buffer: treated as a change rather than parsed halfway.
    - **A read timeout, not a second descriptor.** `Drop` sets a flag and
      returns; the thread notices within 250 ms and closes the socket on
      its way out. Nothing waits for it, because all it can do is send on a
      channel whose receiver is going away.
    - **Every length is checked against what is left** as the attribute
      walk goes, so a truncated or lying message ends the walk instead of
      reading past it. `garbage_is_ignored` feeds it every truncation of a
      well-formed message.
    - **The constants are UAPI** (`NFNLGRP_NFTABLES=7`,
      `NFNL_SUBSYS_NFTABLES=10`, the six new/del message types, family
      `NFPROTO_INET/IPV4/IPV6 = 1/2/10`, and table-name attribute 1 for
      tables, chains and rules alike), read out of this machine's headers
      rather than from memory — and then pinned where it counts:
      `kernel_the_listener_sees_what_the_planner_needs` makes the same
      changes the old test made against a real kernel and counts three
      events, so a wrong group, subsystem, type, family byte or attribute
      id fails the test rather than silently stopping the mesh's firewall
      from healing itself.

    What is unchanged: which events matter (`is_relevant` keeps the same
    rules, including that only *our own* deny table's deletions concern
    us), the 500 ms debounce, the poll tick as the safety net, and the
    restart-on-next-tick when the listener dies. The agent no longer runs
    any long-lived child.

133. **What it came to, as the operator's unit reports it.** One node,
    4.4 MB of `nft -j list ruleset`, crowdsec and geoip-shell:

    | after | `Memory:` | peak | agent's own `VmRSS` |
    | --- | --- | --- | --- |
    | (before) | — | — | 215 MB |
    | #128 streaming ruleset reader | 70 M | 169 M | — |
    | #129 streaming event filter | 57.5 M | 102.9 M | 27.7 MB |
    | #130 terse listing | 57.4 M | 57.9 M | — |
    | #132 own event listener | **4.9 M** | **12.9 M** | — |

    The last step is bigger than removing the `nft monitor` child explains:
    that child was ~30 M of the 57.4 M, so the agent's own footprint fell
    by roughly 23 MB as well. The likeliest reason is the reader thread it
    replaced — a `String` per line and a parse per line, tens of thousands
    of times per blocklist reload, on a thread with its own glibc arena
    that never gave the high-water back. #131's probe measured that churn
    on the main thread of a short-lived process and found no growth; it did
    not measure a dedicated thread's arena in a process that lives for
    weeks. Recorded as the likeliest explanation, not a demonstrated one —
    the same mistake #131 exists to correct would be to state it as fact.

    Either way the shape is what matters: nothing left in this path scales
    with the host's other firewalls. The ruleset reader skips what it does
    not keep, the listing leaves set contents in the kernel, and the event
    listener reads three fields out of a message it usually drops.

## M24 follow-up — nodes a phone cannot dial

Found on the real mesh: `minipc` advertises a globally routable IPv6
endpoint, but the home router drops inbound WireGuard. `export-config
--gateway` wrote it into the phone's `.conf` as a direct `[Peer]`, and since
WireGuard has no failover that /32 black-holed the node and every service on
it. A service declared after the export fared no better: its VIP fell under
the gateway's range, but the gateway refused to forward because the pair was
recorded as direct.

134. **An admin says which nodes cannot be dialled, and only the export
    listens.** `wireserve-admin via-gateway <node> on|off` sets
    `nodes.export_via_gateway`. With a gateway in the config, a flagged node
    gets no direct entry, is absent from the recorded `conf_peers`, and
    `/poll`'s existing M24 derivation does the rest — the node is told to
    reach the device via the gateway, the gateway is told to forward the
    pair, VIPs included. No routing code changed. Nothing detects this
    automatically because nothing can: WireGuard does not report which side
    initiated a handshake, and a phone's config is frozen at export anyway.

135. **Stored on the node, not per export, and not on `PeerInfo`.** A flag on
    the export command would be lost by the next `--refresh` that forgot it,
    which silently restores the black hole. "Nothing outside can dial this
    node" is a fact about the node and true for every device, so it lives on
    the node row and every export re-reads it. It travels to the admin CLI in
    `AdminPeersResponse.via_gateway`, beside `transit_approved`, and never in
    `PeerInfo`: agents route among themselves and must not act on it.
    Admin-set rather than self-reported by the node, because the only thing
    it changes is the next export, which is itself an admin action.

136. **What it deliberately does and does not do.**
    - It changes nothing already on a device. The route answers with the
      devices whose config a refresh would change: turning it on names those
      holding the node as a direct peer (they stay broken until refreshed)
      and those using it as their gateway; turning it off names those
      reaching it through a gateway (they keep working until refreshed).
    - A flagged node is never auto-selected as a gateway and an explicit
      `--gateway` naming one is refused, since a device dials its gateway by
      its one `Endpoint =` line.
    - Without a gateway it does nothing but warn: there is no other path, so
      dropping the direct entry would make the node unreachable, not
      rerouted.
    - It survives revoke and rejoin, like `gateway_node_id`: it describes the
      node's network, not its key.
    - An older coordinator omits the field, which the CLI reads as empty — the
      export then behaves exactly as before.

## M26 — serving an address the node reaches

Every service ran on the node that declared it. A router, a NAS or a printer
cannot run an agent, so nothing on a node's LAN was reachable from the mesh.
`serve myrouter 443:192.168.178.1:80` now makes `myrouter.wg:443` reach the
router's port 80 through the node. It composes with M25 unchanged: the proxy
sends plain HTTP to the service address on 443, so the router gets a TLS name
on phones as well.

137. **`[PUBLIC:][ADDRESS:]TARGET[/proto]`, and `PortMap.addr`.** One
    optional IPv4 address per mapping, absent meaning the node itself. That
    keeps every declaration, state file and wire message from before
    meaning what it meant. `ServiceDecl.ports` is JSON in the database, so
    no migration was needed. A dotted first part of a two-part form is an
    address (`192.168.178.1:80` maps public 80 to it). Refused everywhere,
    by the shared `is_valid_target_addr`: loopback (a rewritten packet
    arriving from the mesh with a loopback destination is a martian),
    multicast, broadcast and unspecified. Refused by the agent and the
    coordinator, each against the mesh ranges it knows: anything inside the
    mesh, since forwarding back into it is transit's job. Otherwise any
    unicast address is allowed, public ones included, at the user's
    request; admin approval is the gate.

138. **IPv4 only, by necessity rather than choice.** A service's own address
    is IPv4 (`vip4`), and the kernel cannot hand an IPv4 connection to an
    IPv6 address (that would be NAT64). IPv6 targets need IPv6 service
    addresses first, which would be M20 over again: allocation, AllowedIPs,
    routes, hosts file, proxy upstreams and every rewrite chain in `ip6`.
    Once that exists, IPv6 targets are cheap. `serve` refuses an IPv6 target
    with that reason. Hostnames are refused too: rules are built from
    literal addresses, and re-resolving on every poll would let DNS change
    what the firewall forwards to.

139. **The same M20 rewrite, a different destination, plus a masquerade.**
    `svc-pre`/`svc-out` rewrite `vip:public` to `addr:target` in place of
    `node:target`, and the kernel routes the rewritten packet out of the
    host. A new `svc-masq` chain (nat, postrouting, srcnat) masquerades it:
    the first packet of a flow still carries the rewrite's mark, and never
    leaves on the mesh interface. The target has no route back into the
    mesh, so it has to see the node's own address, and the client's address
    is lost for this kind of mapping only. Conntrack undoes the SNAT on
    replies, and `svc-rev-*` then match the target address as the source.
    A second NAT mechanism (conntrack DNAT) was considered and rejected:
    the rewrite already exists, is tested, and carries the mark that every
    accept rule keys on. The target key of `validate_node_targets` became
    `(addr, port, proto)`, since two sources are two sources.

140. **Load-bearing: a remote mapping without a service address gets no
    rule at all.** The pre-VIP fallback opens the *target port on the
    node*, which for the router's port 80 would be the node's own port 80.
    `service_rules` skips such a mapping with a warning, and likewise one
    whose address is in the pinned mesh ranges or is the node's own.

141. **Forwarding on the LAN side, owned and guarded.** IPv4 forwards a
    packet only if the interface it *arrived on* forwards, and the replies
    arrive on the LAN interface. So beyond the mesh interface's own flag
    (now also on while any remote mapping exists), the agent turns on the
    egress interface's flag (`routes::egress_ifname`, `ip route get` over
    netlink). It does this only where the flag is off and
    `conf/all/forwarding` is off. While it owns the flag, `wireserve-fwd`
    drops everything forwarded from that interface that isn't one of our
    marked flows (`Forwarding::guarded`, IPv4 only). The guard goes in
    before the flag goes on, and the flag goes off before the guard goes.
    If `all` turns on later (Docker or Podman starting, which rewrites
    every interface's flag), ownership is dropped without a write, since a
    guard would then break the runtime. Ownership lives in the state file
    (`forwarding_owned`), so a crashed agent's successor still guards and
    releases it, and stop turns it off. `FirewallBackend::apply` now takes
    a `Forwarding` (transit pairs plus guarded interfaces), so the guard
    and the rules are one transaction.

142. **Host-firewall interop: two new FORWARD shapes, mark-scoped.**
    `ForwardWanted { transit, services }` replaces the transit bool, and an
    `Opening` enum replaces "one accept per hook". A node with a remote
    mapping gets `iifname <wg> ct mark & M == M` (the request) and
    `oifname <wg> ct mark & M == M` (the reply) in every foreign FORWARD
    chain, including iptables `-m connmark --mark 0x1000000/0x1000000` for
    Docker's FORWARD policy DROP. firewalld's guard gets the request shape
    as an exception ahead of its drop. Neither opens routing from the mesh
    as such: only flows our own table rewrote to a declared target carry
    the mark. Kernel round trips pin that nft and `iptables -S` list both
    back exactly as the planner expects, so they settle.

143. **The target address reaches admins, not the mesh.** The coordinator
    stores it and `wireserve-admin list-services` shows it (an approver should
    see that a node exposes its LAN). The directory every node receives
    leaves it out: peers need only the public face, and the owner acts on
    its own declaration. The owner's `list` shows its declaration for that
    reason. Approval stays per name, as in M18: a later change of target
    address, like a change of target port, needs no re-approval.

144. **Old daemons and downgrades.** A declaration with an address goes
    over IPC as `serve_forwarding`, which a daemon from before M26 refuses
    as an unknown op instead of dropping the address and mapping onto its
    own port. The CLI then says to restart the daemon. What cannot be
    caught is a *downgrade*: an older agent reading a state file ignores
    `addr` and would serve the target port on the node itself. Known and
    accepted. `unserve` such services before downgrading.

`deploy/e2e/run-lan-target-test.sh` **passes** as of 2026-09-25, after two
harness fixes: the device's route now goes in from a helper, and the guard
check is a one-way UDP probe, since a TCP connect failed with or without the
guard. Several routers (FRITZ!Box among them) refuse requests whose Host
header is not their own name, a DNS-rebinding defence. The generated vhost
cannot carry a per-service `header_up`, so the README suggests a hand-written
`handle` ahead of the generated `import`; untried against a real router.

## M27 — an exit node for phones, and a home resolver for it

145. **IPv6 transit never forwarded, found while planning this milestone.**
    `ip_forward::set_enabled` wrote `ipv6/conf/<wg>/forwarding`, but IPv6's
    per-interface `forwarding` only picks host or router behaviour (router
    advertisements, IsRouter). Whether a packet is forwarded is decided by
    `all.forwarding`, or since Linux 6.17 by `force_forwarding` on the
    interface the packet *arrives* on. Verified in netns before changing
    anything: per-interface `forwarding=1` on both sides forwards nothing,
    `force_forwarding` on the ingress side alone forwards one direction only,
    and writing `all.forwarding` 1→0 resets `force_forwarding` everywhere. So
    M23 transit and M24 gateway routing carried IPv6 only on hosts that
    forward globally (Docker, Podman). Small in practice, since service
    addresses are IPv4 and the firewall drops ICMP to nodes, but wrong. Now
    `force_forwarding` on the mesh interface, which is both ingress and egress
    for transit, re-asserted every cycle against that reset. On an older
    kernel nothing is written and the daemon warns once. `all.forwarding` is
    still never touched: it would make every interface a router and stop the
    host accepting router advertisements, which can cost it its IPv6 route.
    `transit on` says so on such a kernel. The kernel test forwards a real
    packet between two namespaces rather than checking which files were
    written, which is how the old test passed while the feature did nothing.

146. **Two consents, and no new admin verb.** The gateway opts in locally
    with `wireserve exit on`, reported every poll as `exit_capable`
    and tracked in memory beside the transit report
    (`TransitState::report_exit`), like `transit on`. The device side is
    the admin's `export-config --exit`, which already is a per-device admin
    action, so an `approve-exit` would only repeat it. Exit is not implied
    by transit approval: forwarding between mesh members is one decision,
    sending a device's internet traffic out under the node's own public IP
    (abuse complaints, a VPS provider's terms) is another. An exit is a
    gateway first, so transit approval and `transit on` are still needed.

147. **Recorded per export, and derived through the gateway.**
    `nodes.exit_enabled` is written by the same `set_gateway` call as
    `gateway_node_id` and `static_conf_peers`, because it describes the same
    files (#108): a `--refresh` without `--exit` clears it. The export
    records what it actually rendered, so a gateway dropped for want of a
    mesh range records no exit. `/poll` sends a gateway its
    `exit_clients` (pubkeys) through `gateway_id_of`, so revoke, delete and
    `deny-transit` end the exit on the same poll that ends the gateway, with
    no code of their own. The agent acts on the list only while `exit on`;
    the coordinator's list is never the whole consent.

148. **Its own mark bit, `EXIT_MARK = 0x0200_0000`.** M26 allows public
    target addresses, and `svc-rev-*` rewrites replies matching a target
    address and port under `SERVICE_MARK`. An exit flow to the same address
    and port sharing that bit would have its replies rewritten to look like
    they came from the service. The adjacent bit is free of every user
    listed at `SERVICE_MARK`.

149. **Marked in prerouting, for the internet only.** `exit-mark` (filter,
    prerouting, -150) marks a *new* flow from an exit client whose
    destination is outside `NOT_THE_INTERNET_V4` and the mesh range. The
    mark has to exist before any FORWARD chain runs, because it is what the
    host's other firewalls are opened for (`Opening::ExitRequest`,
    `ExitReply`, iptables `connmark 0x2000000`, a firewalld guard
    exception), and their chains run at the same priority as ours in no
    promised order. Private destinations are refused on purpose: reaching
    the gateway's LAN through an exit would bypass the per-service approval
    a LAN target needs. The range list lives in `wireserve-types` and the
    export's resolver check uses the same list, so the two cannot disagree.
    A flow a service address already rewrote carries the service bit and is
    left to that path. `exit-masq` masquerades marked flows leaving by any
    interface but the mesh's.

150. **The egress is the default route, through the M26 machinery.** The
    replies arrive on the interface the host reaches the internet by, found
    with the same netlink route lookup as a LAN target's
    (`routes::egress_ifname` on a global address), and it goes through the
    same owned, guarded forwarding switch: guard before switch, Docker's
    `all=1` hand-off, ownership in the state file. The guard now drops
    what carries neither bit.

151. **IPv4 only, with IPv6 captured.** The full-tunnel profile routes
    `::/0` into the tunnel so none of the device's IPv6 leaves around it,
    and the gateway drops it (the final `iifname <wg> drop`, or the kernel
    before that on a host that does not forward IPv6). Forwarding it would
    need NAT66, an IPv6 guard, and `force_forwarding`, which only Linux 6.17
    has (#145). Phones rarely notice: the tunnel's only IPv6 address is a
    ULA, which RFC 6724 ranks below IPv4 for a global destination. Adding it
    later changes only the gateway; the profile already captures IPv6.

152. **One keypair, two profiles.** A second export would rotate the key, so
    the full-tunnel profile is rendered in the same run from the same
    `[Interface]` and the same direct peers, differing only in the `DNS =`
    line and the gateway's `AllowedIPs = 0.0.0.0/0, ::/0`. The direct peers'
    /32s outrank the default route, so the mesh stays exactly as direct.
    `--exit` needs `--out` (the second file goes beside it as
    `<file>-exit.conf`) or `--qr` (two labelled codes, both rendered before
    anything is written).

153. **`--dns` is required, and resolving it happens before any mutation.**
    Without a resolver, a phone in a full tunnel keeps asking the café's, at
    a private address the gateway refuses. A name is an approved service,
    written as its address (with a warning if nothing is published on
    53/udp); a literal must be a mesh address the directory knows or a
    public one. A private address outside the mesh is refused with the
    `serve` line that would reach it. The resolver learning the mesh's names
    is documentation, not code, at the user's choice: a resolver on a node
    reads its `/etc/hosts`. Found while writing that up: AdGuard Home
    follows changes to the file, dnsmasq and so Pi-hole re-read it only on
    `SIGHUP`, so the README gives a systemd path unit that reloads them. A
    resolver in a container sees no names, since the agent replaces the file
    atomically and a single bind-mounted file keeps the old one.

`deploy/e2e/run-exit-test.sh` **passes** (2026-09-25), all nine checks. Getting
there found three harness gaps, none in the exit: the debug image lacked
`sysctl` for wg-quick; podman mounts `/proc/sys` read-only, so the agent's
forwarding writes failed and nothing forwarded (fixed with `--security-opt
unmask=/proc/sys` in the four harnesses that forward, and documented as "run
forwarding nodes on the host", not changed in the quadlets); and a
hand-rolled phone route sent a direct peer's handshakes out through the exit,
which made the mesh check pass by a detour. Not yet tried with a real phone.

## M28 — names on a phone without the full tunnel

154. **The mesh profile can name a resolver too, opt-in (`--mesh-dns`).** #104
    ruled out a `DNS =` line in the mesh profile because the phone apps
    cannot scope it: it captures every query while the tunnel is up. That
    rules out a resolver answering only the mesh's names, whose negative
    answers break the rest of the phone's DNS. It does not rule out a full
    resolver on the mesh — a served Pi-hole or AdGuard Home, the same one M27
    names for the exit — which answers everything and names every service,
    non-HTTP ones included. That is MagicDNS's own shape. The cost is
    availability: while the tunnel is on, the phone's DNS depends on that
    resolver. So it is never a default, and the export says so on stderr.

155. **The resolver must be on the mesh.** The mesh profile's `AllowedIPs`
    carry the mesh and nothing else, so a public resolver would be asked
    outside the tunnel, name nothing on the mesh, and still take over the
    phone's DNS. `resolve_dns` now also reports whether the address is the
    mesh's (a node's address or an approved service's), and `--mesh-dns`
    refuses anything else. No gateway is needed: without one, the resolver's
    owner is a direct peer like every other.

156. **No coordinator or agent change.** The resolver is an ordinary service
    address: reached directly when its owner is in the config, and through
    the gateway's existing M24 forwarding otherwise. `--dns` no longer
    implies `--exit`; it names a resolver for whichever profile asks, with
    `--exit` and `--mesh-dns` saying which, and refuses to stand alone. The
    exit's `--exit --dns` means what it did. `ExportOptions` replaces the
    growing argument list of `export_config::run`.

`run-exit-test.sh` step 10 (a device on the plain mesh profile resolving a
service through the served resolver, and a public resolver refused for that
profile) **passes** as of 2026-09-25, with the rest of the suite.

## M29 — a sign-in in front of chosen services

157. **The proxy is where identity belongs, and the mesh is what makes it
    hold.** M25 already fronts every 443 service with one Caddy holding one
    wildcard certificate, so `forward_auth` there gives per-person access —
    a passkey at Pocket ID through authward, say — to exactly the services
    that are web apps. Per-device service ACLs were considered and declined
    by the user; this answers the case they were for ("my partner's phone
    reaches Jellyfin, nothing else") at the level people reason about.
    Headscale cannot do the equivalent: it issues no HTTPS for `serve`.

158. **Proxy-only is not optional, and it is the whole feature.** forward_auth
    providers (authward's deployment guide says so outright) trust that every
    backend is reachable only through the proxy; otherwise a client skips
    the sign-in and sends its own `X-Auth-User`. Before M29 every mesh member
    reached `service:443` directly. So for a marked service the owning node's
    `svc-pre` rewrite gains `ip saddr <proxy node>` on **every** mapping, not
    just 443: another mapping to the same backend is another door. A request
    from anyone else is never rewritten, so it is addressed to the service
    address, which nothing answers. The node's own clients (`svc-out`) are
    not limited, which is also how a proxy on the same node reaches it. The
    one source-restricted rule in the design, deliberately not a general
    access list. A marked service whose proxy is not in the directory, or
    which has no service address (whose fallback opens the node's port to
    everyone), is not opened at all: fail closed.

159. **The operator's snippets, not an identity provider in WireServe.** A
    marked service's generated `handle` imports `wireserve_auth` ahead of
    `reverse_proxy`; once anything is marked, every service's upstream
    imports `wireserve_upstream`. Both are defined in the operator's
    Caddyfile — for authward, its `forward_auth` block and the two
    `header_up Cookie` lines stripping its session cookie. The upstream one
    goes on every vhost because the sign-in cookie is scoped to the whole
    domain and reaches unmarked services too. Neither is emitted while
    nothing is marked, so a Caddyfile from before M29 keeps validating.
    Verified with `caddy validate` on 2.11.4 against the shipped example.

160. **Marks belong to names, in their own table.** A `services` row is
    deleted on withdraw and re-created on re-declare — instantly, with
    approval off — so a mark on the row would silently drop across that
    round trip and reopen the service. `service_auth(name)` is removed only
    by an admin, and marking a name nothing declares is allowed and inert
    (the next declarer is protected: the safe direction to be early in).
    `approve-service --auth` sets the mark before approving, so the service
    never appears unprotected in between.

161. **Refused until both agents understand it.** Each half fails open on an
    agent that ignores the mark: an old owning node leaves the direct path
    open, an old proxy publishes the service with no sign-in while the owner
    admits only that proxy. So agents now send `capabilities` on every poll
    (`service-auth`, tracked in memory beside the transit report), and
    `PUT /admin/services/{name}/auth` refuses to mark until the owning node
    and the proxy's node have reported it within the online threshold. It
    also refuses without a service domain and proxy, for a service not on
    TCP 443 with an address of its own, and for the proxy itself. Turning a
    mark off is never refused. What it cannot catch is a later downgrade;
    the README says not to.

## M30 — the command is `wireserve`, and a group can use it without sudo

162. **Only the binary is renamed.** The CLI is typed constantly and the spec
    (§4.6) already called it `wireserve`; the crate stays `wireserve-agent`
    (`[[bin]] name = "wireserve"`, so `wireserve_agent::` paths are
    untouched) and so do the systemd unit, its template and the quadlet.
    The unit names the daemon, and renaming it would break
    `systemctl restart wireserve-agent` on every running deployment for
    nothing. `wireserve-coordinator` and `wireserve-admin` are unchanged.
    `install` writes `/usr/local/bin/wireserve` and a unit whose
    `ExecStart` points at it. An already-joined node upgrades by copying the
    binary and the two unit files and restarting (`install` would join
    again); README has the commands. **`install` does not remove an existing
    `/usr/local/bin/wireserve-agent`** (the user's call: never delete a
    file silently); it says the file is now unused and leaves it. A daemon
    already running keeps its old binary until restarted.

163. **A group, decided by file permissions alone.** Nothing in the IPC
    protocol depends on the caller being root; the socket was `0600` in a
    `0700` directory only because nobody had needed otherwise. Now, if a
    group named `wireserve` (`WIRESERVE_SOCKET_GROUP` renames it, empty
    disables) exists when the daemon binds, the socket is `0660` and its
    directory `0750`, both `root:wireserve`; otherwise exactly as before, so
    existing deployments and containers change nothing. The directory is
    opened to the group only after the socket is final, so the group never
    reaches a socket with default permissions. The group is looked up once,
    at bind: `install` creates it before starting the unit, and a daemon
    started before the group existed needs a restart.

164. **Why not a per-request check, or a world-writable socket.**
    `SO_PEERCRED` reports only a peer's *primary* gid, and `usermod -aG`
    grants supplementary groups, so a gid check in the daemon would refuse
    the very users it is for. The kernel's own permission check on the
    socket handles supplementary groups correctly. A world-writable socket
    would let any local account `leave` the mesh or publish a service. A
    second, read-only socket for `list` was declined: it costs client
    fallback logic and buys little on a single-user node.

165. **What membership grants.** Everything the socket does: `serve`,
    `unserve`, `transit`, `exit`, `list`, `leave`. Approval still lives at
    the coordinator, and keys and the bearer token stay in the root-only
    state file, so a member is a node operator, comparable to the `docker`
    group, not a way around the coordinator. `daemon`, `install` and `join`
    stay root: they write the 0700 state directory and bring up the
    interface.

166. **`CAP_CHOWN` joins the unit's bounding set.** Changing a file's group
    to one the caller is not a member of needs it; root inside the unit has
    only what the bounding set allows. The set is documented as informational
    already (`CAP_DAC_OVERRIDE` makes it no real reduction), so this costs
    nothing further. If the chown fails anyway (a unit from before this,
    without the capability) the daemon warns and keeps a root-only socket
    instead of losing its IPC. `PermissionDenied` on connect is now reported as such
    ("run with sudo, or join the `wireserve` group") instead of "is it
    running?". A container sees no host groups, so it stays root-only.
    `run-multi-instance-test.sh` gained a step that restarts one instance
    with a group and checks a supplementary-group member succeeds and an
    outsider gets the message (needs root; not run when this was written).

167. **`install` on a joined node is the upgrade.** The update used to be
    scp, `install -m 0755`, hand-copied unit files and a restart, and
    `install` could not do it because it re-joins. Now, when the instance
    already has a bearer token and the caller passed no URL or token,
    `install` skips the join, refreshes the binary and both unit kinds (the
    binary is shared, so a stale template would break instances this run
    was not asked about), and restarts every active `wireserve-agent*` unit;
    a URL or token still means a re-join. A corrupt state file is an error,
    not "unregistered" (which would go on to replace the identity). Left
    for later, on the user's word: the same for the coordinator (it has no
    CLI to carry it), a `deploy/push.sh` wrapper, and nodes pulling the
    binary from the coordinator (declined for now: it would let the
    coordinator make every node run code as root).

## M31 — `wireserve-coordinator install`, and a user of its own

168. **The coordinator installs itself, like a node does.** Setting one up
    was six README commands and a `grep | cut >` to hand the admin key to
    `wireserve-admin`, and every non-default setting meant reading
    `coordinator.env.example`. `wireserve-coordinator install` (clap added;
    no subcommand still runs the server, so `ExecStart=` and the images are
    unchanged) creates the user, installs itself and the `wireserve-admin`
    lying next to it, writes the env file, generates the admin key and mesh
    ranges, starts the unit and saves the admin key for one user. Like the
    agent's, the unit is `include_str!`'d. With the unit already present it
    upgrades instead: binaries and unit replaced, restarted if running, no
    questions, env file untouched — and a setting flag there is refused with
    a pointer to `--reconfigure` rather than silently ignored.

169. **Six questions, in plain words.** Web address; whether the web
    server (reverse proxy) runs here; the internal port (TCP closed to the
    internet, UDP optionally forwarded for M22); service approval; a
    service domain and the proxy service's name; who gets the admin key.
    Each says what it is for first and offers a default (the current
    setting on `--reconfigure`); a bad answer re-asks. Mesh ranges, token
    lifetime, rate limits and log level are not asked: their defaults are
    right for a first install. Every question has a flag, and without a
    terminal nothing is asked (`--public-url` is the only required one), so
    it scripts and tests. The admin port is always the node port + 1 on
    loopback. The public URL is stored as `WIRESERVE_PUBLIC_URL`, printed at
    startup and offered back on `--reconfigure`.

170. **Only asked-about keys change.** A fresh env file starts from the
    documented example. An edit replaces a key's line in place or appends it
    under one heading; a key being cleared (no domain any more) is commented
    out, not removed; every other line comes back byte for byte.

171. **Its own user, `wireserve-coordinator`.** The unit ran as
    `wireserve`, whose group has been, since M30, the one allowed to drive
    the root agent daemon — so on a host running both, the coordinator
    could. The unit now names `wireserve-coordinator`; `--user` picks
    another through a drop-in, keeping the shipped unit byte-identical. On
    upgrade, systemd's `StateDirectory=` chowns the directory to the new
    user by itself; the `ExecStartPre=` migration now chowns with
    `--reference` to that directory instead of naming a user. The old
    `wireserve` user is left, with a note, and no `userdel` is suggested:
    it would take the agent's socket group with it.

172. **The admin key is written by the admin user's own process.** Their
    home is theirs to arrange, links included, and root following a link
    planted there writes where it points. `install` re-executes itself as
    that user (`save-admin-config`, hidden; std drops supplementary groups
    with `setgroups(0)` before `setuid`) with the values in the environment
    under `wireserve-admin`'s own variable names. A different key already
    saved there is replaced only on a yes at a terminal; without one it is
    left and the replacing command printed. The key is generated before the
    first start (`bootstrap::resolve_with`, reading the env file rather than
    sudo's environment) so there is no waiting on the service — except when
    an old `/var/lib/wireserve` database is about to be moved in with its
    own secrets, when `install` waits for them instead.

173. **`WIRESERVE_TRUSTED_PROXY`.** A proxy on another machine means a
    listener on a LAN address, and `WIRESERVE_TRUST_PROXY_HEADERS` believed
    `X-Forwarded-For` from any peer — anyone on that LAN could name their
    own source. Leaving it off is worse: every node looks like the proxy,
    so the endpoint fallback yields nothing and all nodes share a
    rate-limit bucket. The new setting believes the header only when the TCP
    peer is that address (v4-mapped peers normalised); everyone else is
    taken at their own address. `install` sets it for a remote web server,
    and `TRUST_PROXY_HEADERS=true` for a local one, where only local
    processes reach the loopback listener.

174. **Tested in systemd containers.** `run-coordinator-install-test.sh`
    boots an Arch container (it must run binaries built on this host) under
    rootless podman, with `SYS_ADMIN` inside the user namespace for the
    unit's sandbox. It checks: a fresh flags-only install, `wireserve-admin`
    working with no flags for the admin user, `--reconfigure` keeping a
    hand-added line and commenting out a dropped domain, an upgrade leaving
    the env file byte-identical, and a pre-M31 install (unit from 9a43d33,
    running as `wireserve`) moving to the new user with its database and
    admin key. Passes (2026-09-26).

## M32 — the coordinator writes the service names into public DNS

First of three milestones moving TLS to each service's own node, the way
`tailscale serve` does but on the operator's own domain and with stock
WireGuard phones (plan: M32 records, M33 per-node termination, M34 sign-in
built in and the central proxy removed). M32 stands on its own: every
approved service gets a public name, so a phone resolves services that are
not on 443 — the gap #117 stated plainly — and the hand-made wildcard
record is no longer needed.

175. **One rule for where a name points, shared by both ends.** `Naming`
    moved out of the agent's `hosts.rs` into `wireserve-types` as
    `ServiceNames` (with `publishes_tls` and `own_address`, which the proxy
    had its own copy of). The hosts file and the coordinator's records call
    the same function, so a name cannot resolve one way on a node and
    another on a phone. It is pure; the agent wraps it to keep the warning
    about a configured proxy missing from the directory.

176. **`dns-update`, with a curated five.** Stalwart's crate covers ~70
    providers but has no generic configuration — each takes different
    credentials through its own constructor — so every provider is a
    hand-written mapping. RFC 2136 with TSIG (BIND, Knot, PowerDNS: the one
    the e2e test exercises), Cloudflare, deSEC, Hetzner and Porkbun; adding
    one is an enum variant, its `Field`s and a match arm. Its default
    aws-lc-rs feature is the provider reqwest already brings in; `ring`
    would have dragged in native-tls. Credentials are `WIRESERVE_DNS_*` in
    `coordinator.env` — the database still holds only hashed secrets — and
    `Debug` never prints them. HMAC-MD5 is not accepted.

177. **The coordinator owns the service names under the domain, and only
    those it wrote.** A-record writes replace the whole RRset
    (`set_rrset`), so a clashing record at a service's name is overwritten;
    configuring a provider is the statement that the coordinator manages
    those names, and the wizard and README say so. Deletes are bounded by
    the new `dns_records` table: a name leaves DNS only while a row says
    this coordinator put it there, so a fresh or restored database deletes
    nothing, and a wildcard or any other record in the zone is never
    touched. The table has no record type column yet; ACME challenges
    (M33) get their own.

178. **A reconcile loop, never a request.** The coordinator's first
    background task, spawned beside the reflexive responder. Each pass
    builds the directory exactly as `/poll` does (`services_directory`,
    now shared), computes the wanted records, drops the database lock, and
    writes the difference. It runs every minute and when poked — every
    poll, approve, deny, revoke, delete, rejoin and auth mark pokes it —
    with at least five seconds between passes. Provider failures back off
    60s, 120s, … to 15 minutes, are logged, and show in `list-services` as
    `dns=error: …`; a failed write is not recorded, so it is retried. The
    poll path never waits on a provider.

179. **A changed address waits 20 seconds; new and withdrawn names do
    not.** A proxy briefly missing from the directory swings every 443 name
    to its own address (`ServiceNames::new`), and a written swing lives
    in caches for a TTL (default 300s). So an address change is written
    only once it has held for `DEBOUNCE`; a swing back inside that window
    cancels it, and a different new target restarts the wait. A new name
    has nothing cached to protect and is written at once.

180. **The wizard checks the credential before installing.** After the
    service domain it asks whether the coordinator should write the
    records, which provider, and that provider's fields — secrets read
    without echo, and Enter keeping the current one. Not at a terminal,
    `--dns-provider` takes credentials from the environment variables of
    the same names, never from flags, which would put them in `ps`. Then
    it writes and removes a `_wireserve-check.<domain>` TXT record through
    the provider; a refusal stops the install with nothing changed
    (`--skip-dns-check` skips it). Switching provider or `--no-dns` clears
    every credential key the new setting does not read.

181. **Tested against a real BIND.** `run-dns-test.sh` runs the coordinator
    beside BIND 9.20 taking RFC 2136 updates under a TSIG key (rootless
    podman; no WireGuard involved), with nodes as plain `/register` and
    `/poll` calls. It checks: nothing for a pending service; approved ones
    at their own address, a 443 one at the proxy's; a stale hand-made record
    at a service's name replaced; `dns=published`; a withdrawn service and a
    revoked node's services removed; the operator's own record untouched;
    and a restart with everything written leaving the zone serial alone.
    Passes (2026-09-26).

## M33 — each node serves its own 443 services with TLS

The second of the three per-node TLS milestones. A service published on TCP
443 is served with HTTPS by its own node, on its own address, with a
certificate that node obtains — `tailscale serve`, on the operator's domain,
for stock WireGuard phones. No hop through another node, no single proxy
every HTTPS service depends on, no wildcard key on one box.

182. **A terminator of its own, not a thread of the agent.** `wireserve
    tls-serve` (crate `wireserve-tls`, in the same binary) runs under
    `wireserve-tls.service` as the `wireserve-tls` user with only
    `CAP_NET_BIND_SERVICE` (none since M35) and a strict sandbox, `PartOf=`
    the agent. It
    parses TLS and HTTP from the whole mesh, which does not belong in the
    root process holding the WireGuard key. The old objection to terminating
    beside the agent — an agent restart takes HTTPS down — no longer holds:
    a clean agent stop already tears down the interface (`teardown_everything`
    on SIGTERM), so nothing survives a restart that HTTPS alone would lose.

183. **Reused, not written: `instant-acme`, `rustls`, `axum-reverse-proxy`.**
    ACME (DNS-01, ARI renewal windows, `replaces`) is djc's crate; SNI
    selection is one `ResolvesServerCert`; proxying — hop-by-hop headers,
    WebSocket upgrades, HTTP/2 — is `axum-reverse-proxy` over hyper with
    `Host` preserved and `X-Forwarded-*` set from the connection. What is
    ours is the edge: every forwarding header and `X-Wireserve-Node` a client
    sent is removed before the proxy sets them afresh, and `X-Wireserve-Node`
    names the node the mesh source address belongs to. (WebSocket upgrades
    are ours since M42, #256.)

184. **The key stays on the node, the DNS credential on the coordinator.**
    The terminator generates key and CSR; the coordinator publishes the
    `_acme-challenge` TXT record through `POST /tls/challenge` (bearer
    auth), written by the handler itself so the node knows when it exists,
    and removed on `DELETE` or after 10 minutes by the DNS loop. It is
    refused unless the name is `<label>.<domain>`, the label is a service the
    caller owns, approved, on TCP 443 with an address, not behind the
    sign-in and not the proxy; the value must be a 43-character digest; at
    most two per name. Not `terminated`: readiness needs a certificate first.

185. **`terminated` follows readiness, per service.** The agent sends
    `tls_ready` — services whose certificate is held and whose address is
    bound, as the terminator last said — and the coordinator stores it
    (`tls_ready` table, so a coordinator restart does not flap every name),
    replaced on every poll and cleared on revoke, rejoin and re-register. A
    service is `terminated` only while that holds, it is on 443 with an
    address, DNS records are written, and it is neither marked for sign-in
    nor the proxy. `ServiceNames` then points its name at its own address,
    in hosts files and DNS alike. The agent latches its report for 3 minutes
    so a terminator restart does not move public DNS.

186. **Unrewritten, marked, local.** The owner's firewall turns a
    terminated service's 443 mapping into `ServiceRule::Terminated`: a
    mark-only rule in `svc-pre`, no rewrite, no reply rule, the target still
    reserved against other mappings and never forwarded. The mark is what the
    existing input accept and every host-firewall opening already admit, so
    ufw and firewalld hosts need nothing new. The agent routes the address to
    the host (`local` route in table local, protocol 247, `prefsrc` the node,
    so a caller on the node itself is named as the node), and an input rule
    drops the address from any interface but the mesh and `lo`. It emits the
    rule only while the directory says terminated **and** the terminator
    checked in within 30 seconds; otherwise the plain mapping is back.
    (M35, #208: now rewritten to the terminator's own port.)

187. **Local routes survive nothing by accident.** Kept in
    `AgentState.local_routes`; added before the ruleset that sends traffic
    to them, removed after the one that stopped; removed on every stop; and
    after a crash, swept at start by protocol number within this instance's
    mesh range.

188. **A socket that can do nothing else.** The terminator talks to the
    agent over `/run/wireserve-tls[-<inst>]/tls.sock` (0660 to the
    `wireserve-tls` group, in a directory the agent unit creates), decoding
    only `TlsRequest`: a check-in returning `TlsConfig` (built from the
    node's own declarations — the directory drops target addresses — plus
    the ACME settings and a caller map), and a challenge request, which the
    agent forwards only for names it configured. A compromised terminator
    cannot `serve`, `unserve` or `leave`, and names it claims to serve beyond
    its configuration are ignored.

189. **Certificates are kept and not asked for twice.** One issuance at a
    time; stored per name, 0600, and loaded at start, so restarts and
    upgrades cost no issuance (Let's Encrypt allows five duplicates a week);
    renewal inside the CA's ARI window, else two thirds through the
    lifetime; exponential backoff from 2 minutes to 6 hours after a failure
    (five failed validations per name per hour). An `EADDRINUSE` on the
    address — something else on `0.0.0.0:443` — leaves the service on its
    old path (M35 removed the conflict: #208). `WIRESERVE_ACME_DIRECTORY`/`_EMAIL`/`_PROPAGATION_SECS` on the
    coordinator choose the CA for every node; Let's Encrypt production by
    default.

190. **The central proxy keeps working meanwhile.** Nodes that predate this
    still resolve 443 names to the proxy; its generated vhost for a
    terminated service now uses `transport http { tls; tls_server_name
    <name> }` to the service's address. Services marked for sign-in stay on
    the proxy until M34 builds the sign-in in.

191. **Tested against a real CA and DNS.** `run-tls-terminate-test.sh`
    (rootful podman) runs a coordinator, BIND 9.20 taking TSIG-signed
    updates, Pebble validating against it, and two agents. It checks: one
    issuance and the service terminated; verified HTTPS from another node
    with the right `X-Wireserve-Node`, `X-Forwarded-For` and `Host`, forged
    copies gone; the owner named as itself; the service's other port still a
    mapping and its target closed; no challenge record left; a restarted
    terminator serving the stored certificate; a stopped one handing the
    address back to the plain mapping and TLS returning with it; the local
    route removed on stop and swept after `kill -9`. Passes (2026-09-27). The
    harnesses' `socat SYSTEM:` test backend, which socat's own escape parsing
    mangled into answering nothing, is now `deploy/e2e/echo-backend.sh`.

## M34 — the sign-in built in, and the central proxy gone

The last of the three per-node TLS milestones. The sign-in that M29 put in
the central Caddy moves into every node's terminator, and the central proxy
— `WIRESERVE_SERVICE_PROXY`, `wireserve daemon --proxy caddy`, the generated
vhost file, the proxy-only firewall rule — is removed. Treated as a fresh
design, not a migration: nothing from M25–M33's proxy is accepted or warned
about any more.

192. **Caddy's `forward_auth`, built into the terminator.** Before a request
    to a marked service goes to its backend, a headers-only copy goes to
    `https://<provider>.<domain><verify_path>` with the original `Host`,
    `X-Forwarded-Method`, `X-Forwarded-Uri` and every other header (API-token
    headers included). 2xx: through, with `copy_headers` copied on. 401 with
    `X-Login-Url` on a GET or HEAD: 302 to it. Anything else: the provider's
    answer as is. That is exactly the contract authward documents, so it
    needs nothing changed. Configured once on the coordinator —
    `WIRESERVE_AUTH_SERVICE` plus `_VERIFY_PATH`, `_COPY_HEADERS`,
    `_SESSION_COOKIE`, defaulting to authward's — and shipped to every node
    in `ServiceNaming.sign_in`. It needs DNS records, since only terminated
    services exist to be signed in to.

193. **The check reaches the provider through the provider's own
    terminator, unmodified.** authward has one listener and trusts
    `X-Forwarded-Host/-Uri/-Method` as its protocol. The calling terminator
    connects to the provider service's own address over verified TLS
    (Mozilla's roots via `webpki-roots`; `hyper-rustls`, pooled) with the
    protected service's name as `Host`; the provider's terminator strips the
    forwarding headers as it does for everyone, and `axum-reverse-proxy`
    derives `X-Forwarded-Host` from that `Host` — which is what authward
    reads. `X-Forwarded-Uri` and `-Method` pass through. No special case on
    either side. A client calling `/verify` itself only learns about its own
    session. The provider's target is resolved by the agent from the
    directory, and only once the provider is `terminated`; until then a
    marked service answers 503 rather than serve unchecked.

194. **Identity and cookie hygiene on every request, marked or not.** Every
    terminator removes every `copy_headers` header a client sent, from every
    request, and the provider's session cookie from every request but the
    provider's own (it is scoped to the whole domain, so the browser sends it
    everywhere). M29 needed the operator's `wireserve_upstream` snippet for
    this; it is now unconditional once a sign-in is configured.

195. **A marked service opens nothing but its terminated 443.** The owner's
    `service_rules` skip every other mapping of a marked service — each
    would be a way round the check — and open nothing at all while its
    terminator does not serve it; the direct-open fallback is refused too.
    `ServiceRule::Mapped.only_from` and the proxy-source lookup are gone:
    the one source-restricted rule in the design is no longer needed.

196. **`terminated` no longer excludes anything but readiness.** Marked
    services and the provider itself terminate like any other; the
    challenge endpoint no longer refuses them. Marking needs a configured
    sign-in, a service on 443 with an address that is not the provider, and
    an owner reporting `sign-in` (`CAP_SIGN_IN`, sent with `tls-terminate`
    by an agent whose terminator has checked in). `CAP_SERVICE_AUTH` is
    gone.

197. **The proxy removed outright.** `crates/wireserve-agent/src/proxy/`,
    the `--proxy`, `--proxy-conf` and `--proxy-main-config` flags,
    `PollContext.proxy`, the proxy step of the poll, `-/etc/caddy` in both
    agent units, `ServiceNaming.proxy_service` on the wire, `Config.service_proxy`,
    the installer's proxy question and `--proxy-service`, and
    `deploy/proxy/Caddyfile.services.example`. `ServiceNames` has no proxy
    branch: every name points at its service's own address. The installer's
    question is now which service runs the sign-in (`--auth-service`,
    `--no-auth-service`), asked only with a DNS provider.

`deploy/e2e/run-service-auth-test.sh` **passes** (2026-09-27), all six
steps: every service terminated; a marked service sends a caller without a
session to sign in and serves one with it, the backend seeing who and not
the cookie; an unmarked one needs no sign-in and loses the cookie too; the
way round the sign-in leads nowhere; `service-auth off` gives it back.

## Cleanup — no earlier installation is assumed

Everything that existed only to accept what an earlier version wrote or
sent is removed. There are no previous installations to carry forward.

198. **No migrations of old names.** The agent no longer removes `wg0` or the
    old `wireserve` nftables table and host-firewall guards
    (`remove_legacy`, `plan_legacy_removal`, `ifname::LEGACY`). The
    coordinator installer no longer moves the pre-M31 state database or
    notes the old service user, and its unit no longer has the migrating
    `ExecStartPre`. The agent installer no longer looks for the
    `wireserve-agent` binary.

199. **Services are declared as port mappings only.** `ServiceDecl`,
    `ServiceInfo`, `AdminServiceInfo`, `PendingService` and the `Serve`
    request carry `ports: Vec<PortMap>` and nothing else; the single
    `port`/`proto` pair and `ServeForwarding` are gone. `wireserve serve
    <name> <port>` still works because a bare port is a mapping
    (`443` = `443:443`); `<port> tcp|udp` is no longer accepted. The
    coordinator's `port`/`proto` columns hold the first mapping, as they
    are `NOT NULL`.

200. **Every service has its own address.** `ServiceRule::Open` — opening
    the service on the node's own address when it had no VIP — is removed,
    with its nftables rule. A service without a VIP is skipped with a
    warning, and no service rules exist before the node has an address.

201. **Joins and daemons require what the coordinator always sends.** A
    join needs a mesh range it can pin (`JoinError::MeshUnverifiable`),
    a daemon refuses to start without one, and plaintext HTTP is a stored
    per-node setting only (`WIRESERVE_ALLOW_PLAINTEXT_HTTP` gone).
    `ProbeResponse.reflexive_port` is required, and `TlsResponse::Unsupported`
    — "an old coordinator" — is gone. `WIRESERVE_STATE_PATH` and
    `WIRESERVE_SOCKET_PATH` are gone too: paths come from the instance.

202. **The install wizard asks for the DNS zone.** It defaulted silently to
    the service domain, so `home.example.com` inside the zone `example.com`
    failed the wizard's test record on Hetzner, Porkbun and RFC 2136 (which
    take the zone name as given; Cloudflare and deSEC walk up to it). Only
    `--skip-dns-check` and a hand edit got past it, and `--reconfigure`
    failed again. The zone is now a question (from `WIRESERVE_DNS_ZONE`,
    then asked, then kept), part of the check, and written only when it
    differs from the domain. The DNS explanation's "add one wildcard
    record yourself" went too: with every service on its own address, no
    wildcard can be right.

203. **`run-nat-test.sh` tests the reflexive tier on a NAT it can work on.**
    #94 made router-b `masquerade random`, but Linux gives every
    destination of such a masquerade its own random port: a symmetric NAT,
    where the reflexive port is useless to anyone but the coordinator
    (M23's case). Agent1 reached node2 only because node2 dialled agent1's
    port-forward and WireGuard roamed agent1's endpoint, so the check that
    agent1 dials the reflexive address failed. Node2 now sits behind an
    endpoint-independent mapping to a different port (a fixed SNAT to
    40404 plus a DNAT back), what most home routers do; agent3 stays
    behind the symmetric one.

204. **Certificates are kept per CA.** The store was keyed by name alone and
    a held, valid certificate is never re-issued, so moving the coordinator
    from Let's Encrypt staging to production would have kept serving the
    untrusted staging certificates until renewal, some 60 days. They now
    live under `certs/<ca>/<name>`; on a change of CA the terminator loads
    or issues the new CA's certificate (without ARI's `replaces`, which
    names a certificate of the same CA only) and serves the old one
    meanwhile, so the service stays ready. `<ca>` is an FNV-1a hash of the
    directory URL, as is the account file's name, which used
    `DefaultHasher` — not stable across Rust releases, so a toolchain
    upgrade could have created a new account. README documents trying a
    first setup on the staging CA.

205. **The wizard finds the DNS zone instead of asking for it, and speaks
    plainly.** Few people know what their provider calls a zone, so #202's
    question is gone: the install's test record tries a zone already set
    (`WIRESERVE_DNS_ZONE`, or the env file's), then the domain, then each
    domain above it down to two labels, keeping the first the provider
    accepts. The domain, DNS and login questions are reworded for someone
    who has bought a domain and nothing more, and each provider's
    credential question is preceded by where that token is created
    (Hetzner's must come from the Hetzner Console; the old DNS Console's do
    not work with the Cloud API `dns-update` uses).

206. **A pair leaves transit once a direct path works.** On the real mesh,
    lego2 and minipc (both `192.168.178.0/24`, at two homes) stayed
    transited via strato for good, although minipc's port-forward made it
    directly reachable. Each tried the other's private address, fell to
    `Wan` and asked for transit in that same cycle, before the WAN address
    was ever dialled. The transit then removed the peer's own kernel entry,
    so no direct handshake could ever clear "wanted". Four changes, all in
    the agent:
    - A transited peer keeps a **probe entry**: its endpoint and keepalive,
      no `AllowedIPs`. It routes and accepts nothing, but a direct
      handshake over it ends the transit. Pass 2 no longer folds into a
      via that is itself transited, so a cycle still routes nothing.
    - A peer that is transited **stays wanted until its direct path
      handshakes**, so a tier retry can't drop the transit for a grace
      window, and **`Wan` gets its own `ENDPOINT_GRACE_WINDOW`** before it
      asks (`switched_at` is kept across `Wan` cycles).
    - `peers_to_configure` sends an unchanged endpoint as none, so moving
      `AllowedIPs` back keeps the address the kernel roamed to. For a node
      without a port-forward, that's the only one that works.
    - The `Lan` tier is skipped when both nodes' public IPv4 addresses are
      known and none match. Unknown on either side stays optimistic.

207. **Hole-punching for a transited pair, and tiers that stay confirmed.**
    #206 wasn't enough for lego2 ↔ minipc: minipc is reachable directly
    only over IPv6, and lego2 has none. That leaves IPv4 hole-punching,
    which three things prevented:
    - **A node with working IPv6 never learned its reflexive IPv4
      address** (#90 skipped the probe), so its IPv4-only peers had
      nothing to punch towards. The probe now always runs.
    - **Backoff kept the two sides of a punch apart.** Each side's retries
      back off independently, up to 30 minutes, so both sending at once
      was luck. A transited peer's entry is only a probe, so failing costs
      nothing: it is never backed off or put on `Wan`, and keeps dialling
      its ranked candidates, taking turns each grace window, until one
      handshakes.
    - **A confirmed tier fell back at the next poll without a newer
      handshake**, which on a live session (one handshake per ~2 minutes)
      is nearly every poll. It now stays while handshakes keep coming
      within `ENDPOINT_CONFIRMED_MAX` (180s, WireGuard's session limit,
      plus a grace window). This also covers the hand-over: a tier
      confirmed while transited keeps its endpoint when the transit ends.

    `ENDPOINT_GRACE_WINDOW` is 30s instead of 60s. A working path
    handshakes within a second or two; the window only has to span the
    poll interval (20s by default), since tiers are judged once per poll.

## M35 — the terminator leaves port 443 to others

The terminator bound `<service address>:443` for each service, and on Linux
that bind and a listener on every address — nginx's `0.0.0.0:443`, Caddy's
and Go's dual-stack `[::]:443` — refuse each other whichever starts second,
`SO_REUSEADDR` or not. A node could not run Caddy, Stalwart or nginx on 443
beside a terminated service.

208. **An unprivileged port on every address, 443 rewritten to it.** The
    terminator listens on `0.0.0.0:11443` (`TLS_LISTEN_PORT`), and a
    terminated service's 443 becomes an ordinary mapping onto it: `svc-pre`
    for the mesh and `svc-out` for the node's own clients rewrite only the
    port — the address stays, the caller's too — and `svc-rev-*` rewrite the
    reply back. The terminator tells its services apart by the local address
    a connection arrived on; any other address (the host's own, a service no
    longer served) is closed unanswered, and an input rule drops the port
    from anything but the mesh and `lo`. One listener instead of one per
    service also ends the rebind race of `d3e58be` and `IP_FREEBIND`.

209. **systemd holds the port, so nobody else can.** An unprivileged port
    on a local address can be bound by any local user whenever its owner
    lets go — a restart, a crash — and the agent would keep sending the
    mesh there. `wireserve-tls.socket` binds it from boot, as root, and
    keeps it across every restart of the terminator, which takes the
    descriptor (`LISTEN_FDS`) and needs no capability at all any more
    (`CapabilityBoundingSet=` empty). Without systemd — the e2e containers —
    it binds `--port` (`WIRESERVE_TLS_PORT`) itself.

210. **The port is the socket's, and the agent learns it.** The check-in
    carries the port the terminator's socket really has; the agent writes
    its rewrite from that, under the same 30-second liveness as `serving`.
    There is no second setting to keep in step. 11443: unprivileged, below
    Kubernetes' NodePort range and the kernel's ephemeral ports, and clear
    of the alternative HTTPS ports other software takes (4443 Jitsi, 6443
    Kubernetes, 7443/8443 UniFi, 8443/9443 common Caddy and Stalwart setups).

211. **Instances get ports of their own.** Every instance's socket listens
    on every address, so no two may share a port. `wireserve install`
    gives a named instance the first port above 11443 that no other
    instance has and nothing on the host listens on, in a drop-in
    (`wireserve-tls@<i>.socket.d/port.conf`), and says which. `--tls-port`
    chooses one for any instance; a drop-in already there is kept as it is.


## M36 — who can reach what: service groups, grants and tags

Today every approved service is reachable by every node, and the only way
to restrict one is M34's mark, which asks the sign-in about every request —
the owner's own laptop included — and covers HTTP on 443 alone. M36 moves
access into grants the coordinator computes and every node enforces
itself: nft by source node for any protocol, the terminator by device and
then by sign-in for HTTP. One earlier installation exists: its services all
land in the built-in `default` group, which everyone is granted, so it
upgrades without a change in behaviour.

Two findings of the 2026-09-27 security review come first, because M36
builds on the sign-in they concern.

212. **The provider is told the service's own name, and a request naming
    another is misdirected.** The terminator picks the service by the
    address a connection arrived on, but passed the client's `Host` to
    `/verify` — and authward chooses its per-host rules (`bypass_paths`,
    `required_group`) by that name, so a mesh peer could have another
    host's rules applied to a marked service. `SignIn::check` now sends the
    route's fqdn as `X-Forwarded-Host` — which authward, like any
    forward_auth provider behind a proxy, reads first — and the provider's
    own name as `Host`, since the provider is itself a terminated service
    that answers for its own name only (sending the service's name there
    was 421'd by the provider's terminator: found by
    `run-service-auth-test.sh`, fixed 2026-09-29). The provider's own
    terminator keeps a client's `X-Forwarded-Host` on its verify path
    alone, where the other terminators send it — asking `/verify` directly
    only ever answers the asker. Every terminated
    service answers a request whose `Host` or authority names anything else
    with **421 Misdirected Request** before the sign-in or the backend sees
    it. `run-service-auth-test.sh` step 6.

213. **The provider is trusted on one node only.** It was known by service
    name alone: whichever node declared `auth` after the real one withdrew
    it would have received every `/verify` request, session cookies
    included, and decided who gets in. `WIRESERVE_AUTH_NODE` names the node
    (installer: `--auth-node` and a question), `SignIn` carries it, and the
    agent builds a `SignInTarget` only from a directory entry owned by that
    node; otherwise there is none, and marked services refuse with 503.
    Without `WIRESERVE_AUTH_NODE` the sign-in is off, with a warning at
    startup — a coordinator configured before the setting still starts.
    `run-service-auth-test.sh` step 7.

214. **Groups, grants and tags, keyed like the marks were.** Migration 0017:
    `service_groups` (seeded `default`), `service_group_members` by service
    **name** — a row stored on `services` would vanish with a withdraw and
    come back in `default` — `grants` (`everyone` / `oidc` / `tag` → group,
    seeded `everyone → default`) and `node_tags`. A name with no membership
    is in `default`, so the existing installation upgrades into exactly
    what it reached before. `service_auth` is dropped; `db::refuse_live_marks`
    stops the upgrade, naming them, while any mark exists, since a marked
    service would otherwise come out public. `default` can never be deleted,
    and no group while it holds services, has grants or a declaration waits
    to join it.

215. **A declaration names a group once, on approval, and never an unknown
    one.** `ServiceDecl.group` (`wireserve serve … --group g`) is stored as
    `services.declared_group` on a **new** row only, and becomes membership
    when that row is approved — auto-approved or by `approve` — if the name
    has no groups yet; it is cleared either way, so an admin who later
    empties the groups is not overruled. A pending or denied declaration
    seeds nothing. A new name naming a group that does not exist is left out
    of the upsert entirely, never published into `default`; that and a
    re-declaration naming another group become `PollResponse.service_notices`
    (shown by `wireserve list`) instead of failing the poll.

216. **One function decides access, and each owner is told its own.**
    `access::service_access` gives a service `open` (`everyone` granted) or
    the ip4s of the nodes whose principals — `everyone`, their tags, their
    owner's groups (M38) — match a grant, always with the owner's own
    address; `sign_in` when it is terminated, a provider is configured, its
    owner reports `CAP_SIGN_IN` and a grant names an `oidc:` group, with
    those groups. The provider's own service on its own node is always open,
    and cannot be put in a group. `/poll` sends `access` for the polling
    node's own non-denied services only, pending ones included so the rules
    are ready at approval; `GET /admin/access/{services,nodes}/…` explains
    with the same function. `ServiceInfo.auth`, the marks' routes and
    `service-auth` / `approve-service --auth` are gone.

217. **The firewall admits the granted sources, per packet.** `ServiceRule`
    carries `sources` (`None`: everyone); `forward_rewrite` in `svc-pre` gets
    `ip saddr { … }` first, so a source left out is never rewritten nor
    marked and meets the refusal of an unpublished port — including on its
    open connections, since the rewrite runs before conntrack. An empty list
    emits no rewrite (nft has no empty set literal) but keeps the address in
    the refusal. `svc-out`, the node's own clients, is never filtered. The
    agent saves `own_access` before the rest of the cycle, since
    `last_directory` is saved only after all of it succeeds and the
    terminator must never enforce older grants than the firewall; sources
    outside the pinned mesh range are dropped. A declared service with no
    access entry opens nothing; a `sign_in` service's terminated 443 is open
    to every node while its terminator serves it, and every other mapping —
    and that one otherwise — admits the sources alone.

218. **The terminator checks every request: device, then sign-in.**
    `TlsService.access` feeds a `Policy` kept in its own map and replaced in
    place on every check-in, and `service_fn` looks the policy and the caller
    up per request — so a grant taken away, or a node revoked, reaches an
    open keep-alive or HTTP/2 connection at its next request (review finding
    3; an upgraded WebSocket is asked about again every 30s since M42,
    #261). An open service or a
    granted caller goes on; anyone else, with `sign_in`, is asked about, and
    one of `sign_in_groups` in the provider's groups header lets them in,
    anything else is 403; without `sign_in`, 403. The identity headers are
    named once (`WIRESERVE_AUTH_{USER,EMAIL,GROUPS}_HEADER`, replacing
    `WIRESERVE_AUTH_COPY_HEADERS`), carried in `ServiceNaming` and
    `TlsConfig`, and removed from every request on every service, provider
    or not.

219. **The admin's commands.** `group create|delete|list`,
    `group add|remove <group> <service>`, `grant add|remove <source> <group>`,
    `grant list`, `tag add|remove <node> <tag>`, `access <service>` and
    `access --node <node>`; `list-services` shows `groups=`.

## M37 — the sign-in's answers, reused as the provider allows

Every request from a device the grants do not name asked the provider
again, a round trip over the mesh each. authward now says how long its
answer holds (`Cache-Control: max-age`, `Vary: cookie, host,
x-forwarded-host[, …]`), in plain HTTP any forward_auth provider can speak;
a provider that says nothing is asked every time, as before.

220. **Kept only per person, and only when asked to.** A 2xx is reused when
    it names a user (a path the provider lets anyone through says nothing
    about who is asking), carries `max-age` above zero and neither
    `no-store` nor `no-cache`, and a `Vary` that is not `*` and names the
    cookie or `Authorization` — otherwise one person's answer could reach
    another. The key is the service's name and the value of every `Vary`
    header exactly as sent, hashed (SHA-256): no cookie is stored. At most
    10 000 answers, an hour at most, per provider; replaced with it.

221. **A stale answer only while the provider is down.** `stale-if-error`
    lets a kept answer stand in when the provider times out, cannot be
    reached or answers 5xx, for that long past its `max-age`. The grants are
    checked on every request, cached or not — only who someone is is
    reused, never whether they may in.

## M38 — devices that belong to someone

A grant to an identity provider's group could only be proven by a browser
sign-in, service by service. With the provider configured, a device can now
belong to a person, and its grants count their groups for every protocol —
the shared laptop keeps the sign-in, the personal one no longer needs it.

222. **The coordinator is an OpenID Connect client.** `WIRESERVE_OIDC_ISSUER`,
    `_CLIENT_ID`, `_CLIENT_SECRET` (and `_SCOPES`, `_GROUPS_CLAIM`,
    `_REFRESH_SECS`); `WIRESERVE_PUBLIC_URL` is now a setting, not only a
    banner line, since the provider sends browsers back to
    `<public url>/claim/callback`. `openidconnect` 4 without its own HTTP
    client: requests go through the workspace's reqwest 0.13, never
    following redirects. Discovery runs for each sign-in and each refresh
    pass, so a provider rotating its keys is picked up. Groups come from the
    ID token (read after its signature checks out) or else userinfo for the
    same `sub`; names a grant could not name are dropped.

223. **Only an admin makes claim links.** `POST /admin/nodes/{name}/claim`
    (`claim-url`, and `create-node` / `export-config` when the provider is
    set): `clm_` + 32 random bytes, stored hashed, ten minutes, single use.
    A node that could make its own could send it to anyone and collect their
    groups.

224. **Claiming is three requests, and ends with a confirmation.**
    `GET /claim/{code}` checks the link without using it up (link previewers
    open links) and starts the code flow with PKCE — its state in memory,
    capped, ten minutes, tied to the browser by a `__Host-` cookie (plain name
    on an http coordinator). A bad link counts as a failed authentication.
    `GET /claim/callback` needs that cookie and its state, exchanges the
    code, checks the ID token and nonce, requires a refresh token, and asks
    "make <node> yours?" with the node's tags and current owner.
    `POST /claim/confirm` needs the cookie and the page's token, uses the
    link up atomically (`UPDATE … WHERE used = 0`), and stores the owner.
    Pages escape everything and forbid framing, scripts, referrers and
    caching.

225. **Owners are kept current, and end cleanly.** Migration 0018:
    `node_owners` (one per node, the refresh token sealed with
    XChaCha20-Poly1305 under `WIRESERVE_OIDC_TOKEN_KEY` — generated silently
    into `coordinator-secrets.env` — with the node id as associated data) and
    `claims`. Every refresh interval each token is exchanged: new groups and
    the rotated token are kept; `invalid_grant` ends the ownership; any other
    failure marks the owner stale, and after an hour its groups count for
    nothing until a refresh succeeds. Revoke and rejoin clear the owner and
    its links; `owner clear` does it by hand.

226. **The owner's groups are principals, and backends learn who it is.**
    `access::read_rules` counts each owner's groups (`oidc:<group>`), so a
    claimed device is in the firewall's sources like a tagged one. A node
    with terminated services gets `PollResponse.identities` for the devices
    allowed in, saved with `own_access`, sanitised (mesh addresses, no
    control characters, usable group names), and passed to the terminator on
    each `Caller`, which fills the identity headers for a request its device
    got in by — the user is the provider's `sub`, as authward sends it.
    `access --node` shows the owner.

In-process, `tests/oidc_flow.rs` claims a device against an identity
provider running in the test (discovery, JWKS, PKCE, signed ID tokens, a
refused refresh); `deploy/e2e/run-owner-test.sh` does it against
mock-oauth2-server, and passes (2026-09-29). The installer does not ask for the provider;
the settings go into `coordinator.env` by hand, where `--reconfigure` leaves
them.

227. **The provider is told which device is asking** (security audit
    2026-09-29, finding 1). The provider's session cookie is scoped to the
    whole domain, so any node owner with an approved :443 service can read a
    visitor's cookie and replay it at another service's terminator; the
    provider could not tell, because it never learnt the caller's address
    (both terminators removed `X-Forwarded-For`, and the verify request came
    from the calling node). `SignIn::check_request` now sets one
    `X-Forwarded-For` — the TCP peer, so never something the client wrote —
    and the provider's own terminator keeps it on its verify path (as it does
    `X-Forwarded-Host`) and proxies it on without appending its own peer
    (`Route::verify_router`, `XForwardedFor::Preserve`); anywhere else a
    client's is still removed. Standard forward_auth semantics, so nothing is
    provider-specific: a provider that binds sessions to the client address
    (authward's `bind_session_to_client_ip`) then rejects a replay; one that
    ignores it behaves as before. Login reaches the provider through the same
    terminator, so the address is the same single value there. A forged value
    on a direct `/verify` only ever answers the forger. Not exercised by a
    harness yet.

228. **The terminator does not wait on a client without end** (security audit
    2026-09-29, finding 2). It parses TLS and HTTP from the whole mesh, and a
    test showed an idle connection, a 3-byte TLS record and a finished
    handshake with half a request all still open after 70 seconds — any node,
    a phone included, could exhaust a node's sockets, and doing it to the
    sign-in provider's terminator fails every restricted service at once.
    `serve::Limits`: the TLS handshake in 10s; a first request begun within
    30s of it; hyper's header-read timer (20s, HTTP/1) and HTTP/2 keep-alive
    pings; a connection with no request being served and nothing read or
    written for 300s closed (`Watched`) — a slow backend or a streaming
    answer is not idle by that (a WebSocket was meant not to be either, and
    was: #258); 128 open connections per source
    address and 4096 in all, the rest closed unanswered before any TLS work
    (one warning a minute). The unit gets `LimitNOFILE=16384`, above
    systemd's 1024, which the cap would otherwise never reach. Not covered:
    a client dripping a request *body* or HTTP/2 header frames slowly holds
    one of its own 128 — the caps, not a timer, bound it, and one address
    cannot take the shared 4096 alone.

229. **A node is told an owner's identity only once the device has called**
    (security audit 2026-09-29, finding 3). `PollResponse.identities` named
    every owner of a device the node's terminated services let in — on a
    default mesh, where a service without a group is open, every owner's
    subject, e-mail address and groups, to any node with one such service,
    and (through the agent's state file and the terminator's `callers`) to
    whatever ran there. Now the terminator notes which known devices connect
    (`Shared::seen`), reports them on each check-in (`TlsRequest::CheckIn
    { seen }`), the agent keeps them for a day (`TlsLink::callers_seen`) and
    sends them as `PollRequest.callers_seen` (capped at 256), and the
    coordinator names an owner only for a device in that list *and* let in.
    A device seen for the first time wakes the poll loop (`TlsLink::wake`,
    a second's grace to coalesce), so its owner is known in a second or two
    and only its first requests reach the backend unnamed. The first time a
    node is told an owner is logged (`owner_identity_released`, subject
    only). What this does not do: the list is the node's own word, so a node
    that lies is told as many owners as it names — one device at a time,
    each logged, where before it was told all of them unasked. That would
    need proof of a connection, which a machine the owner controls cannot
    give.

230. **One authenticated node cannot exhaust the coordinator** (security audit
    2026-09-29, finding 4). Three ways were shown by test. (a) Unapproved
    services took addresses of the mesh's range: four nodes declaring 64 each
    used up a /24, and `/register` then failed with a bare 500 — no new node
    could join. Where approval is required a node now has at most
    `MAX_UNAPPROVED_SERVICES_PER_NODE` (16) services waiting or denied; a new
    name past that is a notice, not a failed poll, and is taken once an admin
    has decided some. A denied service keeps its name (it still must be
    withdrawn or its node revoked) but no longer an address: `deny` frees it,
    `assign_vip` skips it, `approve` assigns one at once. A full range is a
    503 that says so. (b) `/poll` had no per-node throttle, and a poll costs
    a read of every node and service under the one database lock: with 8
    connections flooding, a legitimate poll took about 14 times as long. A
    token bucket per node (`TokenBuckets`, `WIRESERVE_POLL_RATE_BURST` 20 and
    `_PER_MIN` 30, ten times a node's need; 0 turns it off) answers 429, and
    logs once a minute per node. (c) Adding and withdrawing `/tls/challenge`
    values in a loop reached the DNS provider without bound — 60 cycles, 60
    writes and 60 removals — enough to spend its API allowance and stop every
    record and certificate. A bucket per node (burst 10, 3 a minute; a real
    order is one value and the terminator issues one name at a time, each
    waiting a minute or more) is checked after the name is authorised and
    before the provider is called. Not done: the database is still one
    connection behind one lock, so what a node does inside its allowance still
    queues everyone; and the denied and pending rows of a revoked node's
    names stay until the node is deleted.

231. **A declared name cannot take over what the zone already holds, nor
    another node's name** (security audit 2026-09-29, finding 5). Writing a
    service's record replaced every A record at the name (`set_rrset`), and
    withdrawing it later deleted what had been written — so an approved
    `mail`, in a zone that already had a `mail`, took it and later removed it.
    The sync loop now asks the provider (`DnsWriter::existing`, the library's
    `list_rrset` for A, AAAA and CNAME — the provider's own answer, not a
    resolver's cached one) before it *first* writes a name; anything but an A
    record inside the mesh's range (what an earlier run wrote and did not get
    to record) leaves the name alone. That is shown as the record's state
    (`dns_name_taken` logged once per change) but is *not* a provider failure,
    which would put every other name's writes on the loop's backoff; a zone
    that cannot be read is one, and holds the name back. A name already
    written is not asked about again. Names: `Config::reserved_reason` refuses
    a new declaration of a name in `WIRESERVE_RESERVED_SERVICE_NAMES` or
    of the coordinator's own host label under the service domain, and `/poll`
    refuses another node's name (a node may have a service called after
    itself, which the real mesh does: `hetzner` on `hetzner`) — each a notice
    to the node, never a failed poll, and never for a name the node already
    holds. Names held by pending and denied rows are still first come first
    served: the cap of 16 per node (#230) bounds how many, and revoking the
    node frees them. No admin command reserves a name in the database yet;
    the environment list does.

232. **Three small audit findings** (security audit 2026-09-29, findings 6–8).
    (6) The coordinator read the *first* `X-Forwarded-For` line, so behind a
    proxy that adds a line of its own instead of appending to the client's
    (HAProxy's `option forwardfor`) the client chose the address it was rate
    limited, logged and fail2ban-banned under — including someone else's. It
    now reads the last line, then that line's right-most entry; `nginx`'s and
    Caddy's single line gives the same answer as before. (7) The shipped
    fail2ban filter required `client_ip="<HOST>"` and the coordinator logs
    `client_ip=203.0.113.9` — no quotes, tracing's `%` — so the jail matched
    nothing and banned nobody, silently. Filter and README corrected, and
    `tests/fail2ban_filter.rs` runs the *shipped* `failregex` (through the
    `regex` crate, a dev-dependency) against the lines `/poll`, `/register`
    and the admin listener really log, IPv6 included; the old filter fails it.
    (8) Only the configured identity headers were removed from a client's
    request; `Remote-User`, `X-Forwarded-User`, `X-Original-URL` and their
    kin reached the backend, and a backend that trusts one could be spoofed.
    `serve::prepare` now removes a built-in list — `X-Forwarded-*`,
    `X-Original-*`, `X-Remote-*`, `X-Auth-Request-*`, `X-WebAuth-*`,
    `X-Authentik-*`, `X-Authelia-*` by prefix, and `Forwarded`, `X-Real-IP`,
    `True-Client-IP`, `CF-Connecting-IP`, `X-Client-IP`, `Remote-User/-Email/
    -Groups/-Name` and a few more by name — plus `WIRESERVE_STRIP_HEADERS`
    (`ServiceNaming::strip_headers`, `TlsConfig::strip_headers`); the
    provider's verify path keeps `X-Forwarded-Host/-For/-Uri/-Method`, which
    the calling terminator sets. Headers the terminator sets itself (the
    identity headers, the node's name) come after and are unaffected. A
    proxy in front of the terminator that legitimately forwards one of these
    to a backend behind it would now lose it; none is known.

233. **The trust model is written down** (security audit 2026-09-29, finding
    9 and the provider note). The README gains *What you trust a node with*
    — what a joined node sees, reports unchecked, declares, and gains by an
    approved 443 service, what it cannot do, the reach of the `wireserve`
    group, that identity is the device's, and the coordinator's one lock — and
    a paragraph under *Signing in* on binding sessions to the device: which
    providers do (authward, authentik) and which describe no such thing
    (Authelia and oauth2-proxy, from their documentation, not their code).
    No code changed: none of these has a fix short of a different design.

## M39 — relaying end to end: the carrier forwards what it can't read

Transit (M23) was hop by hop: the carrier decrypted the pair's traffic from
one tunnel and encrypted it into the other, so it read everything and could
send packets as either end — which is why it needed an admin's approval at
all. Now the two ends run their own WireGuard session and the carrier only
forwards its UDP. A spike on 2026-09-29 (three network namespaces, plain
`wg` and `nft`) showed it works with two NAT rules and nothing else, and
`firewall::nftables::tests::kernel_a_carrier_relays_a_session_it_cannot_read`
now keeps that true against the rules the agent actually writes: pings in
both directions, and not one ICMP packet through the carrier's forward hook.

234. **A second interface per node, the carry interface** (`<main>-t`,
    `wg::carry_ifname`, cut to fit 15 characters). Same private key, no
    address, MTU 1340 (`CARRY_MTU`: the mesh interface's 1420 less an outer
    header, so a full packet isn't fragmented by the carrier's tunnel), and a
    listen port the kernel picks once and `AgentState::carry_port` keeps.
    One interface was the alternative: a relayed peer's single entry would
    then hold the carrier as its endpoint, and probing its direct candidates
    would mean leaving the relay each time. A second interface only for
    *probing* was rejected too: a probe from another UDP port tests another
    NAT mapping, so its success proves nothing for the mesh interface's
    port. So the mesh interface keeps all NAT traversal unchanged (M21–M23,
    #206/#207) — a relayed peer keeps its probe entry there exactly as a
    transited one did — and the carry interface only carries. Its routes
    name the node's mesh address as their source (`routes::RouteSet::
    prefsrc`); both interfaces' routes move in one `routes::sync_all`,
    removals first, so an address changing interface never meets its old
    route (an existing route counts as added).
235. **The carrier's rules** (`nftables::relay_rules`): for each direction
    of a pair, `iifname <mesh> ip saddr A ip daddr <self> udp dport P_C
    dnat to C:carry_C` and `oifname <mesh> ip saddr A ip daddr C udp dport
    carry_C snat to <self>:P_A`, plus a forward accept for exactly that UDP.
    The SNAT is to a fixed port — the sender's own relay port — and that is
    what makes it work whoever dials first: C's packets to `<self>:P_A` are
    then the *reply* of A's tracked flow, and the other way round. With
    plain masquerade each side learned the carrier's own WireGuard port as
    the other's endpoint and the handshake answers were lost (seen in the
    spike). Each node's relay port is `WIRESERVE_RELAY_PORT_BASE` (41000)
    plus its **relay slot** (migration 0019), the smallest free one on
    creation, freed on delete, 1000 of them; `wireserve_types::relay_port`.
    Inside the tunnel only: for agent pairs nothing is opened anywhere.
236. **Tracked flows decide what a relay port means, so nothing may move
    under them.** A packet that reaches a carrier before its relay rules
    must not be tracked, or its untranslated flow would outlive the rules —
    keepalives every 25 s keep a UDP flow alive for ever. The mesh
    interface's default-deny drops it in the input hook, before conntrack
    confirms it, so it isn't. The same reasoning makes the carry port
    persistent: a port that moved on a restart would leave the carrier's
    flow pointing at the old one, and the other side's keepalives would keep
    it there. What this leaves: a carry port that has to change because
    something else took it, which a carrier only recovers from when the
    pair stops sending for the flow's timeout. Rare enough to accept; no
    conntrack flushing (that needs `conntrack` or netlink conntrack, neither
    a dependency today).
237. **The carry interface has a table of its own**, `inet
    wireserve.<carry>` (`nftables::carry_table`), written in the same
    transaction as the mesh interface's: default-deny, the same grants on
    the service addresses, no forwarding at all. Its own table, not an
    interface set in the mesh table, because the host-firewall interop
    checks a table's input and forward chains end in `iifname <if> drop`
    (`planner::own_table_intact`) — with a table per interface a second
    `HostInterop` for the carry interface works unchanged
    (`firewall::Interops`). The mesh table's drops for terminated addresses
    and the terminator's port exempt the carry interface, and it accepts the
    carry port from the mesh (`Forwarding::relay_ends`); WireGuard drops
    anything there no carry peer signed. The rewrites' marking, reply and
    masquerade chains aren't tied to an interface and serve relayed flows as
    they are. The carry name is checked before any firewall state names it:
    one that belongs to something else is left alone and the node runs
    without relaying.
238. **The coordinator arranges it** (`routes/poll.rs`). An agent reports
    `CAP_RELAY` and its `carry_port` each poll (`TransitState::
    report_carry_port`, in memory like the rest of transit); every
    `PeerInfo` carries a `relay` (`PeerRelay`: `port`, `carry_port`, and the
    requester-relative `via`). A pair is relayed when either end wants help,
    both ends are relayable and a carrier that can relay is chosen by the
    same deterministic `select` (now `select_where`); the carrier learns it
    from `relay_carrying`. There is **no fallback** to hop-by-hop transit
    for agent pairs — a pair with an older node among the three stays
    unreachable rather than readable — so every node upgrades together.
    `transit on` / `approve-transit` keep their names and remain the
    consent: a carrier still sees who talks to whom, and can drop it.
239. **What remains hop by hop** until M41: a phone's gateway (#106), whose
    `transit_via` and `transit_carrying` pairs are untouched here, and the
    exit (M27), which stays so by design. `wireserve list` says which is
    which: `relayed by <carrier>` for a peer, and on a carrier "relaying (end
    to end, unreadable here)" apart from "forwarding (readable here)".
240. **Verification.** Unit tests for the assignments, both peer maps, the
    carrier's forwards, the rules' JSON and the carry table; kernel tests for
    the carry interface's routes moving and back
    (`wg::tests::kernel_a_relayed_peer_moves_to_the_carry_interface_and_back`)
    and for the relay itself (above); coordinator tests for selection, no
    fallback, and stable relay ports. `run-transit-test.sh` now checks the
    relay by name, the carry interface's routes, and that the carrier
    forwarded UDP and not one TCP packet while the services were reached —
    not run yet (rootful podman).

## M40 — phones reach every node end to end, through a carrier's public port

A phone can't nest a tunnel: the WireGuard apps' own sockets bypass their
tunnel (Android `VpnService.protect()`, iOS's tunnel extension), so a phone
can only dial a carrier at its public address. Kernel WireGuard gives nft no
way to tell which node a packet from the internet is for — the handshake
names its responder only through a MAC keyed on its public key — so the
destination has to be in the port: each NAT-ed node a phone reaches through
a carrier gets that carrier's public relay port for it. IPv4 only (per-node
IPv6 addresses were considered and left out: phones on IPv4-only Wi-Fi, NDP
proxying, `force_forwarding`).

241. **The same relay port.** A phone's relay for node C is C's relay port
    (#235) on the carrier's public address. `nftables::public_relay_rules`:
    `iifname <public> udp dport P_C limit 200/s ct mark |= RELAY_MARK dnat
    to C:<C's own listen port>`; srcnat of marked flows to the carrier's mesh
    address on a port of the range after the relay ports
    (`base + 1000 … base + 1999`), because a phone that roams starts a new
    flow while its old one is still tracked and a fixed port would clash;
    forward accepts per destination, and a drop for marked flows whose relay
    has gone. The session ends on C's mesh interface, whose entry for the
    phone exists anyway and learns the carrier as its endpoint. Only new
    flows are rate-limited — a nat chain sees nothing else.
242. **A packet before its rule must not be tracked** (found in the spike: a
    phone whose first packets beat the carrier's rules stayed broken, its
    keepalives keeping an untranslated flow alive, until it roamed). The
    carrier drops the whole relay port range on every interface but the
    mesh's in its input chain (`Forwarding::relay_ranges`), before conntrack
    confirms anything. `RELAY_MARK` (`0x0400_0000`) is its own bit: the
    guard on the public interface (M26's, which the carrier's egress joins)
    lets it through, and the host-firewall interop opens exactly marked
    flows (`Opening::RelayRequest`/`RelayReply`; the firewalld guard's
    exception is the reply — a test caught it missing).
243. **Dialable, measured.** The coordinator's reflexive responder answers
    each probe a second time from its own second socket (`AppState::
    probe_udp`, advertised as `ProbeResponse::answers_twice`); two answers
    stay under the request's size (a compile-time check). Only a NAT or
    firewall that admits unsolicited traffic delivers the second, so the
    agent reports `dialable_v4` each poll; `list-peers` shows it. Known
    misclassification, documented: an address-restricted (not
    port-restricted) cone passes. A node that never said (an older agent) is
    treated as before: direct if it has a public endpoint.
244. **The export plans, checks and records** (`POST /admin/relays/plan`,
    `PUT /admin/nodes/{name}/export`). Direct for a dialable node; else a
    carrier that is approved, offering, relays, is itself dialable, has a
    public IPv4 and reaches the node now — preferring one whose port for it
    was already seen open, then one already serving phones, so as few ports
    as possible ever need opening. Every port not seen open in the last 30
    days is **checked from outside** first: the carrier's next poll carries
    `port_checks`, its agent listens on the port (`port_check.rs`, the port
    left open for it and its relay stood down meanwhile, so a re-check of a
    port in use isn't eaten by its own DNAT), the coordinator sends the
    nonce from its second socket, and the carrier's next poll — brought
    forward by the nonce — reports it. A closed port stops the export before
    anything is created, naming the port, carrier and address to open;
    `--allow-unverified` writes the config anyway. Results are kept in
    `relay_ports` (migration 0020); `wireserve-admin relay-ports` lists
    every port, its devices, whether it was open, and which may be closed.
    The rendered config gets `MTU = 1340` when anything in it is relayed.
245. **Settled with the user:** IPv4 only; one port per NAT-ed node, never a
    range to open; wireserve never touches a firewall outside the machine,
    and says exactly when one has to be changed.

## M41 — the gateway is retired

With every node reachable end to end, the gateway's hop-by-hop mesh
forwarding (M24) and `via-gateway` (#134) have nothing left to do, and they
were the only places a node still read traffic it merely forwarded.

246. **Removed:** `via-gateway`, `--gateway`, `export_via_gateway`,
    `static_conf_peers` and the gateway's `transit_carrying` pairs, the
    agent's pass-2 fold of `AllowedIPs`, `PeerInfo::transit_via`,
    `TransitForward`, and M23's hop-by-hop forward rules
    (`transit_forward_rules`). #106/#107 and #134 are superseded.
    `run-gateway-test.sh` became `run-phone-relay-test.sh`.
247. **The exit stays, and still reads what it sends on** (settled with the
    user). `--exit [node]` names it (`gateway_node_id` became
    `exit_node_id`); it must be approved, `exit on` and dialable directly.
    The full-tunnel profile holds the same end-to-end entries as the mesh
    profile, with the exit's `AllowedIPs` widened to `0.0.0.0/0, ::/0`:
    longest-prefix match keeps the mesh end to end and sends only the rest
    to the exit. A relayed node is never an exit.
248. **What this costs** (the user's trade): a phone's config is a snapshot
    again — a node that joins later needs `--refresh`, and `list-peers`
    marks such devices `stale=yes` (also: never exported since the upgrade,
    or a carrier or exit that no longer qualifies) — and two phones don't
    reach each other. Upgrading: every node together (no fallback, #238),
    then re-export every phone; the migration clears a gateway that was not
    also an exit.
249. **Verification.** Unit and API tests for the plan, the port check round
    trip (a carrier picking up a check and reporting its nonce), the record,
    exits, relays, stale devices and refusals; the carrier's rules against a
    real kernel (`kernel_accepts_a_carriers_relay_rules`), the interop
    openings round trip. The spike behind #241/#242 ran in network
    namespaces with plain `wg` (roaming included). Not run yet (rootful
    podman): `run-phone-relay-test.sh` (dialability, a port blocked upstream
    stopping the export, the relay, 0 TCP through the carrier, a roam,
    default-deny, `relay-ports`, refresh), `run-exit-test.sh` (`--exit
    node-gw`, no covering route), and `run-nat-test.sh`'s new dialability
    check. **2026-09-30: `run-phone-relay-test.sh` passes**, after three
    harness fixes: heredocs need `podman run -i`; the interop's accepts sit
    ahead of any counter in a forward chain, so the test counts in
    postrouting; `getent hosts` can repeat a name. `run-transit-test.sh`
    (carrier forwarded UDP only), `run-exit-test.sh` and `run-nat-test.sh`
    (dialability) pass too.

250. **The QR code is as wide as the terminal allows** (2026-09-30, found on
    the real mesh). A config now lists every node, so the fixed 116-column
    limit from the gateway days refused a 1.3 kB one — after a `--refresh`
    had already retired the old key, and without printing the new config
    anywhere, which left the phone cut off. `qr::render` now checks the
    width of the terminal it draws on (`TIOCGWINSZ` on stderr; no terminal,
    no limit), and a code that can't be drawn never loses the export: the
    config is printed as without `--qr`, with the reason.

251. **No guessing for a node that never said** (2026-09-30, found on the
    real mesh). An offline node (or an older agent) has no dialability
    report, and the plan fell back to its last recorded endpoint — a home
    NAT's address, shared with the node behind it, so the phone got a dead
    entry for fedora-workstation carrying minipc's address. Only a node that
    reported itself dialable is dialled now; every other one is relayed,
    preferring a carrier that reaches it right now but not requiring one,
    since an offline node's relay works once it is back.
252. **A port check on the coordinator's own host proves nothing.** With the
    coordinator on the carrier, its datagram to the carrier's public address
    never leaves the machine and read "open" past a provider's firewall;
    the export then never said which port to open. Such a port is not
    checked (`is_own_address`: binding to it works) and is marked
    `unverifiable_here`, and the export now lists every port the config
    relies on, each with what is known about it — `NOT CHECKED` with
    where to make sure, for these. (A coordinator in a container on the
    carrier's host isn't recognised; its check still can't see a firewall
    in front of the host.)

253. **Confirmed on the real mesh** (2026-09-30): the S25 on mobile data
    reaches lego2 and minipc through strato's public relay ports, with
    strato as coordinator and carrier. Nothing had to be opened by hand:
    ufw rules added for 41001/41003 counted 0 packets and were removed
    again — the relay's DNAT takes the packets before ufw's input chain, and
    the interop opens its forward chain — and Strato's own firewall does not
    block them.

254. **The mesh interface's MTU is 1400** (2026-10-01, found on the real
    mesh: lego2 and the S25 lost minipc for minutes at a time, while TCP
    connections still opened and SSH's greeting came through; TLS and SSH's
    key exchange stalled). WireGuard pads what it encrypts to a multiple of
    16, up to the interface's MTU, which #234's 1340 didn't count: a full
    relayed packet of 1400 went out of a 1420 mesh interface padded to
    1408, as 1468 on the wire. minipc sits behind Vodafone's DS-Lite, whose
    IPv4 carries 1460 (measured: "Frag needed, mtu = 1460" from
    `192.0.0.2`), so every full-size relayed packet to or from it was
    fragmented, and the fragments crossed the provider's NAT only some of
    the time. `wg::MESH_MTU` = 1400 caps the padding at 1400, i.e. 1460 on
    the wire (1480 over IPv6); `CARRY_MTU` stays 1340, now derived from it,
    and so does a phone's relayed config. Set on every start, so an
    interface kept from an older build changes too. Every node should get
    it: the carrier pads on its own mesh interface.

255. **A dead direct path is relayed within about a minute** (2026-10-01,
    asked for on the real mesh: lego2 waited about four minutes for strato
    to take over when its punched path to minipc died). The handshake was
    the only liveness signal, and WireGuard renews it only every two
    minutes: a confirmed tier held for `ENDPOINT_CONFIRMED_MAX` (210s) after
    the last poll that saw one, then `Wan` got its own 30s grace window,
    then the request waited for a poll. Now:
    - **Silence is death.** `EndpointTracker::observe_rx` keeps each
      peer's kernel `rx_bytes` (now in `TunnelPeer`) and when it last
      moved; nothing for `PEER_SILENT_MAX` (30s) makes a peer silent. A
      silent peer's confirmed tier is given up at once, it is wanted for a
      relay at once (no `Wan` grace: the probe entry goes on dialling, and
      the first direct handshake ends the relay as before), and a carrier
      stops offering it (`reachable_peers`). A peer never observed is not
      silent, so a restart gives everyone a full window.
    - **Checked every 5s** (`LIVENESS_CHECK_INTERVAL`), between polls, in
      the daemon's select; the first tracked peer to go silent triggers a
      poll at once. Only tracked peers (another agent) count: a phone's
      quiet is normal.
    - **Agents keep each other alive every 10s** (`AGENT_KEEPALIVE_SECS`,
      both interfaces); phones stay at 25s (`STATIC_KEEPALIVE_SECS`), since
      every packet can wake their radio. An agent is a peer with a carry
      port, LAN or reflexive address. 30s is three keepalives, so two lost
      in a row don't count, and covers a peer still on 25s.
    From a dead path to a relay request: 30-35s; the other end and the
    carrier follow at their next poll. A flapping direct path now switches
    more often, each time for about a minute instead of four; if that
    bothers, hold a direct path for a while before ending the relay.

## M42 — WebSockets through the terminator, as the backend answers them

M33 left WebSockets to `axum-reverse-proxy`, and nothing ever tested one.
Reading the code (2026-10-02) found them working only in part: a WebSocket
quiet for five minutes was closed as idle, the backend got no forwarding
headers, and a backend's refusal reached the client as a 502.

256. **An upgrade is ours, proxied as bytes** (`wireserve_tls::upgrade`).
    An HTTP/1.1 request with `Upgrade` and `Connection: upgrade`, past
    `prepare` and `guard` like any other, goes to the backend on its own
    hyper client connection; the backend's answer comes back as it is — a
    101 with every header it set (subprotocol, extensions, `Set-Cookie`), or
    a 401/403/redirect with its body. The backend has 30s to answer. Once
    both sides switch, `copy_bidirectional` carries the bytes: nothing is
    re-framed, so `permessage-deflate` (which the library had to strip)
    works, and any other upgrade token does too. The provider's verify path
    stays on the library's router.
257. **The forwarding headers as on any request:** `X-Forwarded-For` (the
    peer), `X-Forwarded-Proto: https` and `X-Forwarded-Host`, set from the
    connection — the library's WebSocket path set none, and `prepare` had
    removed the client's. Hop-by-hop headers go both ways, `Upgrade` and
    `Connection: upgrade` excepted on the way in.
258. **An upgraded connection is never idle.** The request ended with its
    101, so `Watched` saw a connection with nothing in flight and closed it
    after `idle` (300s) without traffic — an app that doesn't ping lost its
    socket. `ConnStats::upgraded`, set on a 101, takes it off the idle
    timer. In its place every accepted socket gets TCP keepalives (60s, then
    every 15s, 4 tries), which find a client that went away without a word.
259. **An open WebSocket keeps its place in the limits.** hyper's
    connection future ends at the upgrade, and with it went the connection's
    permit — upgraded sockets were not counted at all. The permit now lives
    in `Watched`, which hyper hands on to the upgraded connection.
260. **HTTP/2:** no RFC 8441 extended CONNECT. A browser that negotiated h2
    opens an HTTP/1.1 connection of its own for a WebSocket (ALPN still
    offers `http/1.1`).
261. **Asked again while open.** Every `Limits::recheck` (30s) the request
    as the client sent it goes through `guard` again: the service no
    longer served here, its name no longer the one asked for, a grant
    taken away, a node revoked or a sign-in no longer valid closes the
    connection. A provider that cannot answer (a 5xx from `guard`) closes
    nothing; its trouble is not the caller's. This closes the gap #218
    left open.
262. **Verification.** Unit tests against a real TLS listener and a
    tungstenite backend: subprotocol and `Set-Cookie` from the backend's
    101, forwarding headers from the connection (a forged
    `X-Forwarded-For` gone), text and binary echo; the backend's own 403;
    a WebSocket quiet for three idle periods kept; one open WebSocket
    counted against `max_per_source`; a device without access refused
    before the backend; a grant taken away and an unrouted service closing
    an open socket. The idle, forwarding and refusal tests fail against
    the M33 path. `run-tls-terminate-test.sh` step 10 (**passes**, 2026-10-02,
    with steps 1–9): a WebSocket from the client node over verified TLS, with
    `chat` chosen, `X-Wireserve-Node: node-client`, the client's mesh
    address in `X-Forwarded-For`, and an echo; `ws-backend.py` and
    `ws-client.py` were checked against bookworm's websockets 10.4.

## M43 — a proxy of the operator's own may name its client

A Caddy on a public host proxying into the mesh (`reverse_proxy
https://files.home.tia.sh`) reached the backend as itself: the terminator
removes every `X-Forwarded-*` a caller sends and sets them from the
connection, so Seafile saw the Caddy node's mesh address for every visitor,
and could not tell which public name was asked for.

263. **`WIRESERVE_FORWARDING_NODES`** (coordinator; node names,
    comma-separated, validated as labels) travels in `ServiceNaming` and
    `TlsConfig` like `WIRESERVE_STRIP_HEADERS`. A request whose caller (by
    mesh address, the `callers` map) is one of them keeps its
    `X-Forwarded-For` and `X-Forwarded-Host`; the proxy appends the peer to
    the first (`client, node`) and keeps the second. On upgrades
    (`upgrade::set_forwarded`) the same. Node names are one namespace with
    phones (`nodes.name UNIQUE`), so a name means one device.
264. **Only where, never who.** `X-Forwarded-Proto` is still always set
    afresh (`https`), every identity header still goes, and the operator's
    `WIRESERVE_STRIP_HEADERS` still removes the two if listed. The `Host`
    check (421 for another name) is unchanged: the proxy must send the
    service's own name as `Host` and the public one in `X-Forwarded-Host`.
265. **Verification.** Unit tests: `prepare` keeps exactly the two for a
    forwarding node and the operator's list wins; through a real TLS
    listener, a caller becoming a forwarding node changes what the backend
    sees from `127.0.0.1`/`svc.test` to `203.0.113.9, 127.0.0.1`/
    `files.example.com`; `set_forwarded` appends; the coordinator parses
    the setting. No e2e.

Reviewed with the user before deploying (2026-10-02); three tightenings:

266. **A forwarding node's owner is never named.** By device, its requests
    would carry its owner's identity headers (M38) — every internet visitor
    named as whoever owns the proxy's host. It speaks for someone else, so
    `guard` gets no owner for it. A sign-in still names whoever signed in;
    `X-Wireserve-Node` still names the node, which is true.
267. **Only the client the proxy saw** (`vouched_for`). Of its
    `X-Forwarded-For`, only the last entry is kept: a proxy that appends
    (nginx's `$proxy_add_x_forwarded_for`) passes on whatever its client
    claimed before it, and backends believe the first entry (Seafile:
    `split(',')[0]`). Not an IP address: dropped, and the backend sees the
    node alone, as before M43. The verify path is untouched.
268. **`X-Forwarded-Host` is one host name**, with an optional port as
    `Host` may carry (RFC 9110 §7.2): labels of letters, digits and
    hyphens. Several values, a list, a path, an empty port, an IPv6
    literal or a trailing dot: dropped, and the proxy names the request's
    own `Host`. Apps build absolute URLs — reset links — from it.
    Still open: the trust follows a node *name* (a deleted node's name can
    be registered again) and covers every service; to be talked about next.

269. **A forwarding node's share of the connections is 1024**
    (`Limits::max_per_forwarder`), not 128: its one address is everyone
    its proxy serves, and each WebSocket through it holds a connection of
    its own — a hundred Seafile tabs filled 128. A quarter of `max_total`,
    so whatever comes through it, every other caller keeps the rest.
    Decided at accept, by the same address-to-node lookup
    (`Shared::forwarding_node`); the refusal log names the node.
270. **32 WebSockets per client of a forwarding node**
    (`max_upgrades_per_forwarded_client`), by the address it vouched for
    (#267) — or, without one, the node's own — so one internet client
    cannot take the node's whole share; over it, 429. Counted from the
    upgrade request until the bytes stop (the slot rides in the bridge
    task). Ordinary requests end on their own and are not counted. Both
    fixed, not settings, until a deployment needs one.

## Security audit 2026-10-02 — three fixes

An audit of M39–M43 found nothing high; three medium findings, fixed here
as agreed with the user. Nothing deployed; no e2e suite covers these paths.

271. **Only a WebSocket is upgraded** (`wireserve_tls::upgrade`). M42
    tunnelled any `Upgrade` the backend answered with a 101, and past it
    nothing the client sent was looked at: a test with a backend that
    switches to `h2c` got `remote-user: admin`, a forged
    `X-Wireserve-Node` and any path through, the sign-in never asked. Now
    `wanted` takes exactly `Upgrade: websocket`, version 13 and a key of 16
    bytes; any other upgrade is ignored (RFC 9110 §7.8) — `Upgrade` and the
    `upgrade` token go, and the request is served as a plain one (settled
    with the user, over refusing it: a client offering `h2c` on every
    request still works). A backend's 101 counts only with `Upgrade:
    websocket`, `upgrade` in `Connection` and the `Sec-WebSocket-Accept`
    the key calls for; anything else is a 502 and the backend connection
    is dropped. `sha1` and `base64` are direct dependencies now (both were
    in the lock already).
272. **No certificate for a name the zone holds for somebody else**
    (`routes::tls::not_held_elsewhere`). #231 made the DNS sync leave such
    a name alone, but the challenge path still published its TXT record,
    so a node with an approved service called `mail` could get a trusted
    certificate for a real `mail.<domain>` elsewhere. The provider is asked
    before a new challenge value is published, by the sync's own rule
    (`is_ours_to_replace`): live, since a challenge can come before the
    sync's first look at a name, and its findings don't outlive a restart.
    Taken: 403. The provider can't be read: 409, nothing published. A value
    already held is only refreshed, without asking.
273. **A released service address is held for the phones that may still
    route it** (migration 0021, `db::services::holds`). Configs are
    snapshots (#248) and addresses were handed out lowest-free, so a
    withdrawn address could go to another node's service at once while
    older phones still sent it to the node that had it — which could answer
    for the new service. Triggers on `services` record every release of an
    approved service's address (withdrawn, denied after approval, revoked,
    node deleted — the cascade fires them too), so no code path can forget
    one. Such an address goes to nobody else while a live device (not
    revoked, registered) was exported before the release, or never; its
    own node takes it back first, and a node deleted afterwards loses that
    claim (ids are reused). A range left with only held addresses gives the
    service none, and the log names the devices to refresh — never a
    silent reuse. `list-peers` shows `holds=` per device, and such a
    device is `stale=yes`. Node addresses are left out (the user's call):
    nothing is served on a node's own address, so a stale phone sending one
    to the wrong node reaches nothing. Releases from before the migration
    aren't known; every phone needs a `--refresh` after M41 anyway.

## Security audit 2026-10-02, second pass — two fixes

274. **The relay ports' drop spares this host's own UDP**
    (`nftables::apply_batch_with`). The input-chain drop for the relay
    ports (#242) had no conntrack state, and 41000–41999 lies inside
    Linux's ephemeral range (32768–60999): on every node with `transit
    on`, a reply to its own UDP sent from one of those ports — a DNS
    lookup, NTP — was dropped on every interface but the mesh's, about one
    in thirty. Now `ct state new` only: an untranslated relay packet is
    never anything but new, and dropped it leaves no flow to establish.
    `kernel_a_reply_to_this_hosts_own_udp_on_a_relay_port_arrives` sends a
    lookup from relay port 41010 through a namespace and gets its answer,
    while a datagram nobody asked for on 41011 is still dropped; it fails
    without the fix.
275. **A device owner's e-mail only when verified** (`oidc::verified_email`,
    migration 0022). The claim took the ID token's `email` unchecked, and it
    went to backends as the owner's e-mail header on every request from the
    device: someone handed a claim link could type an admin's address into
    their profile and be taken for the admin by any backend that knows
    people by e-mail (Seafile). authward refuses the same. Now only
    `email_verified: true` counts, at the claim and on every refresh that
    brings an ID token — a later change or lost verification follows; a
    refresh without one leaves the stored value. The emails stored so far
    are cleared (nothing says they were verified); the next refresh brings
    a verified one back. The user header stays the subject, as authward's.
    Settled with the user: verified emails only, rather than none.

## Requests another site starts

276. **A page on another site may not act as the device it runs on**
    (`wireserve_tls::serve::started_elsewhere`). Found in the second audit
    pass, explained to the user with an example: ttyd on
    `shell.<domain>`, granted to a laptop, and a blog open on that laptop
    whose script opens `wss://shell.<domain>/ws` — the browser sends it
    through the laptop's tunnel, the terminator admits the laptop (and
    names its owner, M38), and ttyd, which checks no `Origin` by default,
    hands the page a shell. Admission by device is ambient: no cookie, so
    no SameSite rule; the names are public (DNS, CT logs). A test opening a
    WebSocket with `Origin: https://evil.example` reached the backend
    before this. Now, decided with the user:
    - Refused (403) when `Sec-Fetch-Site` is `cross-site` or `same-site`
      — every service shares the parent domain, a node's own among them —
      or, without it (older browsers), `Origin` isn't
      `https://<service>`: any method but GET, HEAD and OPTIONS, and any
      WebSocket. A WebSocket's `Origin` must be the service's own whatever
      else the browser says.
    - Allowed: following a link, reads — the browser keeps the answer from
      the other page, and dashboards that embed images keep working (the
      user's choice over refusing them) — the service's own pages, typed
      URLs, and clients that send neither header.
    - Exempt: the sign-in provider's own service (its provider may answer
      by form POST), and `WIRESERVE_CROSS_SITE_SERVICES` (coordinator,
      service names), carried as `ServiceNaming::cross_site_services` and
      `TlsService::cross_site` — both, as the user chose.
    Applies to every request, signed-in ones too: a same-site page gets the
    authward cookie sent along.

277. **Through a forwarding node, the public name is the service's own
    origin** (found right after #276, before any deploy). A Caddy serving
    `files.tia.sh` into `files.home.tia.sh` (M43) has browsers whose
    `Origin` is `https://files.tia.sh`: #276 refused every WebSocket
    through it — Seafile's among them — and every POST from a browser too
    old to send `Sec-Fetch-Site`. For a forwarding node, the
    `X-Forwarded-Host` it vouched for (#268: one plain host name, kept only
    for such a node) counts as the service's own name as well.

278. **A relayed peer reaches a service that is forwarded, too**
    (`nftables::carry_table`). The carry interface's table (#237) dropped
    everything forwarded from it, so a relayed agent never reached a
    mapping onto a container's published port or a LAN address (M26) —
    only services answered on the host itself, and 443 services, whose
    terminator connects to the backend on its own. On the real mesh that is
    lego2 and minipc whenever their direct path is down. The carry table
    now accepts a service's own flows (`ct mark & SERVICE_MARK`) ahead of
    its drop, exactly as the mesh table does, whenever there is a mapped
    service. `kernel_a_mapped_service_is_reached_through_the_carry_interface_too`
    sends a connection through each interface to a LAN target; it needs
    real root for the payload rewrites, and skips without. **Run as root
    2026-10-02 (user):** fails without the fix on exactly the relayed
    peer, passes with it. Getting there took two harness fixes: as root the
    kernel tests now use `unshare -n` (a user namespace refuses the payload
    writes), and the test's clients route via the host's address, since the
    veths standing in for WireGuard interfaces do ARP.

279. **The carry interface forwards, too, when a service needs it**
    (`ip_forward::set_enabled`, `poll_loop`). #278 opened the carry table
    for a service's flows, but IPv4 forwards only what arrives on an
    interface whose own `forwarding` is on, and the agent only ever turned
    on the mesh interface's: on a host that doesn't forward globally (no
    Docker or Podman), a relayed peer still never reached a LAN target.
    #278's kernel test hid it by switching all three interfaces on by hand.
    Now the carry interface's switch follows the same condition as the
    mesh interface's forwarding to a service's target, and whether this
    process turned an interface on is kept per interface (one flag for the
    process had been enough while there was one interface). The kernel test
    leaves the carry interface off, sees nothing get through, then switches
    it on with `set_enabled` as the agent does.
