# Throwaway image used by the e2e harnesses to inspect a running
# agent's real WireGuard/network state (`wg show`, etc.) from inside its
# network namespace via `--network container:<name>`. Never part of any
# shipped deployment artifact — deploy/docker/agent.Dockerfile does not
# and should not include these tools.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 wireguard-tools nftables iptables iputils-ping netcat-openbsd \
    socat tcpdump util-linux dnsutils dnsmasq-base procps curl ca-certificates openssl \
    python3-websockets \
    && rm -rf /var/lib/apt/lists/*
CMD ["sleep", "infinity"]
