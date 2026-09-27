# Build context must be the repository root, same reason as
# coordinator.Dockerfile:
#
#   docker build -f deploy/docker/agent.Dockerfile -t wireserve-agent .
#
# Run with:
#
#   docker run -d --name wireserve-agent \
#     --network host \
#     --cap-add=NET_ADMIN --device /dev/net/tun \
#     -v /etc/hosts:/etc/hosts \
#     -v wireserve-agent-state:/var/lib/wireserve \
#     -v wireserve-agent-run:/run/wireserve \
#     --env-file agent.env \
#     wireserve daemon
#
# Never --privileged (spec §8) — CAP_NET_ADMIN + /dev/net/tun is the
# whole capability set this needs for WireGuard and nftables
# operations.
#
# --network host is REQUIRED for a real node (security review F5): the
# agent creates its WireGuard interface (wireserve0, or the next free
# name) and installs its nftables table in whatever network
# namespace it runs in. In a private container namespace nothing on the
# host can reach the mesh, and no service running on the host is
# reachable through it — the container would be a node all by itself.
# Host networking puts the interface and the firewall rules on the host, which is
# the point. (deploy/e2e deliberately runs agents in isolated namespaces
# because there each container IS the node under test.)
#
# Host firewalls: the agent also makes ufw/iptables and other nftables
# tables on the host let the mesh interface through (see README, "Other
# firewalls on the host"), which with --network host happens on the host
# itself — hence `nftables` and `iptables` in the image. firewalld is the
# exception: it is driven over the host's D-Bus, which the container can't
# reach, so on a firewalld host the agent logs the one command to run on
# the host instead.
#
# IMPORTANT caveat, not a Dockerfile-solvable problem: the managed
# /etc/hosts block (spec §6) is only useful to processes that share the
# same hosts file the agent is writing. Inside a container, "/etc/hosts"
# is the CONTAINER's own hosts file by default, isolated from the host's
# — bind-mounting the host's /etc/hosts in, as shown above, is what makes
# `<name>.wg` resolve for processes running on the host itself rather
# than just inside this container. If nothing outside the container
# needs that resolution, the bind mount can be omitted.
#
# The `serve`/`unserve`/`list`/`leave` subcommands talk to the daemon over
# a Unix socket in /run/wireserve, which only exists inside this
# container's own namespace — run them via
# `docker exec wireserve-agent wireserve list`, not from the host,
# unless /run/wireserve is separately bind-mounted out.

# ---- build stage ----
FROM rust:1-slim-bookworm AS builder
WORKDIR /build
COPY . .
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
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/build/target,sharing=locked \
    cargo build --release -p wireserve-agent \
    && mkdir -p /out \
    && cp target/release/wireserve /out/

# ---- runtime stage ----
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates nftables iptables \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/wireserve /usr/local/bin/wireserve

# Runs as the image's default root user, deliberately — same reasoning as
# deploy/systemd/wireserve-agent.service: writing the bind-mounted host
# /etc/hosts needs DAC access this container's root has for free and a
# non-root user would need CAP_DAC_OVERRIDE (nearly as broad as root) to
# get another way.
# The default instance keeps its state in /var/lib/wireserve and its
# socket in /run/wireserve; a named instance (`--instance <n>`) keeps its
# state under /var/lib/wireserve/instances/<n>, inside the same volume.
VOLUME ["/var/lib/wireserve", "/run/wireserve"]
ENTRYPOINT ["/usr/local/bin/wireserve"]
CMD ["daemon"]
