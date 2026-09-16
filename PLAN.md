# WireServe — Implementation Status

Living status document. Update the checkboxes and the "Currently working on"
line as part of the commit that makes progress, so work can pause and
resume across sessions without re-deriving context. Full design is in
`wireserve-design-spec.md`; the detailed step-by-step plan that produced
this checklist lives in the session that created it — this file is the
source of truth for *current status*, the spec is the source of truth for
*requirements*.

**Currently working on:** Milestone 2 — `wireserve-coordinator`

## Milestones

- [x] **M0 — Workspace scaffolding**: Cargo workspace, per-crate stub
      crates, `.gitignore`, `rust-toolchain.toml`, empty `deploy/` tree,
      this file.
- [x] **M1 — `wireserve-types`**: shared wire structs (§4), the single
      `is_valid_dns_label` validator (§3), `FirewallBackend`/`ServiceRule`
      (§5), token hashing helper. 24 unit tests, `cargo clippy` clean.
- [ ] **M2 — `wireserve-coordinator`**: SQLite schema + migrations, IP
      allocation, `/register`, `/poll`, `/admin/*` routes, two separate
      listeners (node-facing vs admin), rate limiting, audit logging.
- [ ] **M3 — `wireserve-agent`**: poll loop, WireGuard reconciliation
      (`defguard_wireguard_rs`), nftables firewall backend (`rustables`),
      `/etc/hosts` managed block, Unix-socket IPC for
      `serve`/`unserve`/`list`/`leave`, join/bootstrap command.
- [ ] **M4 — `wireserve-admin`**: `create-node`, `revoke`, `rejoin`,
      `list-peers`, `export-config` (§9).
- [ ] **M5 — Security hardening review pass**: checklist pass over M2–M4
      against §7, once they're functionally complete.
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
