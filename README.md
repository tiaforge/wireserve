# WireServe

Minimal, self-hosted WireGuard mesh with a declared-service directory. See
`wireserve-design-spec.md` for the full design and `PLAN.md` for current
implementation status.

## Workspace layout

- `crates/wireserve-types` — shared wire structs, validation, token hashing.
- `crates/wireserve-coordinator` — axum + SQLite coordinator binary.
- `crates/wireserve-agent` — WireGuard/firewall/hosts-file daemon + CLI.
- `crates/wireserve-admin` — separate admin CLI (distinct trust surface).
- `deploy/` — systemd units, Dockerfiles, Quadlet files.

## Build prerequisites

`wireserve-agent` depends on the `rustables` crate, which generates nftables
netlink bindings at build time via `bindgen`. Building it requires:

- `clang`/`libclang` (e.g. `apt install clang libclang-dev` on Debian/Ubuntu)
- Linux kernel headers providing `linux/netfilter/nf_tables.h` (present by
  default on most distros; `linux-libc-dev` on Debian/Ubuntu if missing)

No `libnftnl`/`libmnl` runtime linking is required — `rustables` talks to
netlink directly.

```sh
cargo build --workspace
```

`wireserve-coordinator` and `wireserve-admin` have no special system
dependencies beyond a C toolchain (for `rusqlite`'s bundled SQLite).
