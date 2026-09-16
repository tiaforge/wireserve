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
#     wireserve-agent daemon
#
# Never --privileged (spec §8) — CAP_NET_ADMIN + /dev/net/tun is the
# whole capability set this needs for WireGuard and nftables netlink
# operations.
#
# --network host is REQUIRED for a real node (security review F5): the
# agent creates wg0 and installs its nftables table in whatever network
# namespace it runs in. In a private container namespace nothing on the
# host can reach the mesh, and no service running on the host is
# reachable through it — the container would be a node all by itself.
# Host networking puts wg0 and the firewall rules on the host, which is
# the point. (deploy/e2e deliberately runs agents in isolated namespaces
# because there each container IS the node under test.)
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
# `docker exec wireserve-agent wireserve-agent list`, not from the host,
# unless /run/wireserve is separately bind-mounted out.

# ---- build stage ----
FROM rust:1-slim-bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang libclang-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY . .
RUN cargo build --release -p wireserve-agent

# ---- runtime stage ----
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/wireserve-agent /usr/local/bin/wireserve-agent

# Runs as the image's default root user, deliberately — same reasoning as
# deploy/systemd/wireserve-agent.service: writing the bind-mounted host
# /etc/hosts needs DAC access this container's root has for free and a
# non-root user would need CAP_DAC_OVERRIDE (nearly as broad as root) to
# get another way.
ENV WIRESERVE_STATE_PATH=/var/lib/wireserve/agent-state.json
ENV WIRESERVE_SOCKET_PATH=/run/wireserve/agent.sock
VOLUME ["/var/lib/wireserve", "/run/wireserve"]
ENTRYPOINT ["/usr/local/bin/wireserve-agent"]
CMD ["daemon"]
