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
#   docker exec -it <container> wireserve-admin create-node homeserver
#
# which reaches the loopback-bound admin port from inside the same
# network namespace. The node-facing port (8080) has no such restriction
# and can be published normally, e.g. `-p 127.0.0.1:8080:8080` with a
# reverse proxy terminating TLS in front of that, per spec §7.

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
# several minutes of rustls, tokio, rusqlite's bundled SQLite and (for the
# agent) bindgen against the kernel headers, every single time, for a
# one-line edit. The caches persist across builds AND are shared between
# the two images, which otherwise compile the common dependencies twice.
#
# A cache mount is not part of the image layer, so /build/target does not
# survive into the next stage — hence copying the binaries to /out inside
# the same RUN, which is where the runtime stage picks them up.
#
# Clear them with `podman builder prune --all` if a build ever looks like
# it is reusing something it should not.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/build/target,sharing=locked \
    cargo build --release -p wireserve-coordinator -p wireserve-admin \
    && mkdir -p /out \
    && cp target/release/wireserve-coordinator target/release/wireserve-admin /out/

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
COPY --from=builder /out/wireserve-coordinator /usr/local/bin/wireserve-coordinator
COPY --from=builder /out/wireserve-admin /usr/local/bin/wireserve-admin

USER wireserve
ENV WIRESERVE_DB_PATH=/var/lib/wireserve/coordinator.db
ENV WIRESERVE_LISTEN_ADDR=0.0.0.0:8080
ENV WIRESERVE_ADMIN_LISTEN_ADDR=127.0.0.1:8081
# Mesh addressing. Both differ from the binary's own compiled-in defaults
# (100.90.0.0/24 and fd00:90::/64), deliberately — see the commentary in
# deploy/env/coordinator.env.example for why each one was moved. Set
# these before the first node registers: addresses are allocated once and
# kept, so a later change leaves the mesh addressed out of two ranges.
# Override at run time with --env-file or -e as usual.
ENV WIRESERVE_NET_V4_CIDR=10.90.0.0/24
ENV WIRESERVE_NET_V6_PREFIX=fdb4:d481:7c21::/64
# Convenience defaults so a bare `wireserve-admin <subcommand>` works from
# a `docker exec` shell without extra flags — WIRESERVE_ADMIN_TOKEN itself
# must still come from the coordinator's own env (see coordinator.env),
# never baked into the image. Two different URLs, matching the two
# separately-bound listeners: WIRESERVE_COORDINATOR_URL for /admin/*,
# WIRESERVE_REGISTER_URL for export-config's /register call.
ENV WIRESERVE_COORDINATOR_URL=http://127.0.0.1:8081
ENV WIRESERVE_REGISTER_URL=http://127.0.0.1:8080
VOLUME ["/var/lib/wireserve"]
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/wireserve-coordinator"]
