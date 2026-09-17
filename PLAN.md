# WireServe — Implementation Status

Living status document. Update the checkboxes and the "Currently working on"
line as part of the commit that makes progress, so work can pause and
resume across sessions without re-deriving context. Full design is in
`wireserve-design-spec.md`; the detailed step-by-step plan that produced
this checklist lives in the session that created it — this file is the
source of truth for *current status*, the spec is the source of truth for
*requirements*.

**Currently working on:** nothing open — all milestones complete through
M15. 204 tests passing across `cargo test --workspace`, plus three
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
