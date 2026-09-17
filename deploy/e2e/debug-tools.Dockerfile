# Throwaway image used only by run-e2e-test.sh to inspect a running
# agent's real WireGuard/network state (`wg show`, etc.) from inside its
# network namespace via `--network container:<name>`. Never part of any
# shipped deployment artifact — deploy/docker/agent.Dockerfile does not
# and should not include these tools.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 wireguard-tools nftables iputils-ping netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*
CMD ["sleep", "infinity"]
