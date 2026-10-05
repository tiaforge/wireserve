# Build context must be the repository root (the Cargo workspace root),
# not this deploy/docker/ directory, since building any one workspace
# member requires the whole workspace to be present:
#
#   docker build -f deploy/docker/coordinator.Dockerfile -t wireserve-coordinator .
#
# No special --cap-add/--device flags are needed at `docker run` time —
# the coordinator never touches WireGuard or the host firewall (spec §8).
#
# The admin listener defaults to 127.0.0.1 *inside the container's own
# network namespace* — the coordinator refuses to start on 0.0.0.0 for
# that listener regardless of environment (spec §4.0: "never 0.0.0.0,
# regardless of the token check"), which rules out the usual Docker
# pattern of "bind 0.0.0.0 inside, restrict with `-p host_ip:port:port`"
# for this one port specifically. `wireserve-admin` is therefore bundled
# into this same image so admin operations run via:
#
#   docker exec -it <container> wireserve-admin node create homeserver
#
# which reaches the loopback-bound admin port from inside the same
# network namespace. The node-facing port (47820) has no such restriction
# and can be published normally, e.g. `-p 127.0.0.1:47820:47820` with a
# reverse proxy terminating TLS in front of that, per spec §7.

# The e2e suites build with `--build-arg BINARIES=prebuilt`: the runtime
# stage below then takes binaries deploy/e2e/build.sh has already compiled
# into target/e2e/bin, and the build stage is skipped entirely. The
# release workflow builds with `--build-arg BINARIES=release`, taking the
# tested binaries for each platform from dist/<amd64|arm64>.
ARG BINARIES=builder

# ---- build stage ----
FROM rust:1-slim-bookworm AS builder
WORKDIR /build
COPY . .
# rusqlite's `bundled` feature compiles SQLite from source — no system
# libsqlite3 needed, just a C toolchain, which the rust:slim image ships.
#
# The two cache mounts below are what keep a rebuild from recompiling the
# whole dependency graph every time. `COPY . .` is invalidated by any
# source change, so without them each build starts cargo from nothing —
# several minutes of rustls, tokio and rusqlite's bundled SQLite, every
# single time, for a one-line edit. The caches persist across builds AND are shared between
# the two images, which otherwise compile the common dependencies twice.
#
# A cache mount is not part of the image layer, so /build/target does not
# survive into the next stage — hence copying the binaries to /out inside
# the same RUN, which is where the runtime stage picks them up.
#
# Clear them with `podman builder prune --all` if a build ever looks like
# it is reusing something it should not.
#
# RUSTUP_TOOLCHAIN: the image names its toolchain by version (1.xx.y), so
# rust-toolchain.toml's `stable`, copied in with the rest of the repo,
# would otherwise make rustup download a whole second toolchain on every
# build. Pinning to the one the image ships is the same stable release.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/build/target,sharing=locked \
    RUSTUP_TOOLCHAIN="$(rustup default | cut -d' ' -f1)" \
    cargo build --release -p wireserve-coordinator -p wireserve-admin \
    && mkdir -p /out \
    && cp target/release/wireserve-coordinator target/release/wireserve-admin /out/

# ---- or: binaries built beforehand (e2e) ----
FROM scratch AS prebuilt
COPY target/e2e/bin/wireserve-coordinator /out/
COPY target/e2e/bin/wireserve-admin /out/

# ---- or: the release workflow's binaries, one set per platform ----
FROM scratch AS release
ARG TARGETARCH
COPY dist/${TARGETARCH}/wireserve-coordinator /out/
COPY dist/${TARGETARCH}/wireserve-admin /out/

FROM ${BINARIES} AS binaries

# ---- runtime stage ----
FROM debian:bookworm-slim
# ca-certificates: wireserve-admin (bundled below) builds its HTTP client
# with reqwest's rustls-native-certs backend, which loads the system trust
# store at client-construction time even for a plain-HTTP localhost call —
# without this package the client fails to construct at all (caught by
# actually running this image, not just reading the Dockerfile).
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --shell /usr/sbin/nologin wireserve \
    && mkdir -p /var/lib/wireserve \
    && chown wireserve:wireserve /var/lib/wireserve
COPY --from=binaries /out/wireserve-coordinator /usr/local/bin/wireserve-coordinator
COPY --from=binaries /out/wireserve-admin /usr/local/bin/wireserve-admin

USER wireserve
ENV WIRESERVE_DB_PATH=/var/lib/wireserve/coordinator.db
ENV WIRESERVE_LISTEN_ADDR=0.0.0.0:47820
ENV WIRESERVE_ADMIN_LISTEN_ADDR=127.0.0.1:47821
# Mesh addressing and the admin token are NOT set here on purpose: leaving
# them unset lets the coordinator generate and persist all three itself
# on first start, into the /var/lib/wireserve volume declared below, so
# they survive container recreation. Set any of
# WIRESERVE_ADMIN_TOKEN/WIRESERVE_NET_V4_CIDR/WIRESERVE_NET_V6_PREFIX at
# run time with --env-file or -e if you'd rather manage one yourself —
# see deploy/env/coordinator.env.example.
# Convenience defaults so a bare `wireserve-admin <subcommand>` works from
# a `docker exec` shell without extra flags. Two different URLs, matching
# the two separately-bound listeners: WIRESERVE_COORDINATOR_URL for
# /admin/*, WIRESERVE_REGISTER_URL for device create's /register call.
ENV WIRESERVE_COORDINATOR_URL=http://127.0.0.1:47821
ENV WIRESERVE_REGISTER_URL=http://127.0.0.1:47820
VOLUME ["/var/lib/wireserve"]
EXPOSE 47820
# Same port number as the line above, over UDP: the reflexive-address
# responder (NAT-traversal step 2, PLAN.md decisions log #90+). See
# deploy/quadlet/wireserve-coordinator.container's comment on why this
# one needs its own direct publish even when the TCP port isn't public.
EXPOSE 47820/udp
ENTRYPOINT ["/usr/local/bin/wireserve-coordinator"]
