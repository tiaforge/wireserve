# Building from source

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

## Running the end-to-end tests

The suites in `deploy/e2e/` stand up real meshes in Podman containers.
Most need rootful Podman and the WireGuard kernel module; each says so at
the top. Run them from anywhere:

```sh
sudo ./deploy/e2e/run-e2e-test.sh
sudo E2E_RELEASE=1 ./deploy/e2e/run-e2e-test.sh   # test the release build instead
```

Each suite starts with `deploy/e2e/build.sh`, which compiles every binary
once, as a debug build unless `E2E_RELEASE=1` is set. It compiles in a
`rust:1-slim-bookworm` container, for the glibc reason above, and keeps
cargo's target directory in the Podman volume `wireserve-e2e-target`, so
later builds are incremental. The binaries land in `target/e2e/bin`, and
the shipped Dockerfiles take them from there with
`--build-arg BINARIES=prebuilt`. That way the suites test the same
runtime images that ship. When nothing has changed, the build takes a few
seconds, so running several suites in a row costs almost nothing.
