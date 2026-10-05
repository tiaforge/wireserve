# shellcheck shell=bash
# Sourced by the e2e suites, from the repo root: `. deploy/e2e/lib.sh`.

# The agents' poll interval in every suite. Short, so the suites wait for a
# change to arrive rather than for a cycle to come round; the default of 20
# is for real nodes, where it is a load on the coordinator.
POLL=1

# wait_for SECS CMD [ARGS...]: runs CMD every half second until it
# succeeds, for at most SECS seconds, and returns 1 if it never did — so
# it reads as the check it waits for:
#
#   wait_for 20 podman exec "$AGENT2" grep -q testsvc.wg /etc/hosts \
#       || fail "agent2's /etc/hosts never picked up testsvc.wg"
#
# Instead of a fixed sleep, which has to cover the slowest run every run.
# CMD's output is discarded; it must not call `fail`, which would end the
# suite on the first try.
wait_for() {
    local deadline=$((SECONDS + $1))
    shift
    until "$@" >/dev/null 2>&1; do
        [ "$SECONDS" -lt "$deadline" ] || return 1
        sleep 0.5
    done
}

# What a check that something does NOT happen waits instead: long enough
# for every agent to have polled a few times since the change.
settle() { sleep $((3 * POLL + 1)); }

# if_on CONTAINER NETWORK: the name of CONTAINER's interface on NETWORK.
# Not eth0/eth1 by the order of the --network flags: podman 5 keeps that
# order, podman 4 (Ubuntu 24.04, so the GitHub runners) does not.
if_on() {
    local ip
    ip=$(podman inspect "$1" --format "{{(index .NetworkSettings.Networks \"$2\").IPAddress}}")
    podman exec "$1" ip -o -4 addr show | awk -v ip="$ip" '{ split($4, a, "/") } a[1] == ip { print $2 }'
}
