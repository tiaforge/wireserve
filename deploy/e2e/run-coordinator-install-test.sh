#!/usr/bin/env bash
# `wireserve-coordinator install` end to end (PLAN.md M31), in throwaway
# systemd-booted containers, so nothing touches this machine's own users,
# units or /etc.
#
# Checks that a fresh install (no terminal, flags only) creates the
# wireserve-coordinator user, installs both binaries, writes exactly the
# asked-for settings, starts the service as that user and leaves
# wireserve-admin working for the admin user with no flags; that
# --reconfigure changes only its own keys; that a plain re-run upgrades
# without touching the settings; and that `setup domain|login`
# (PLAN.md M47) change only theirs, and restart the service to take them.
#
# The image has to be able to run binaries built on this machine (same or
# newer glibc) and boot systemd; Arch's does both for an Arch-based host.
# No root needed: rootless podman runs systemd containers fine. Usage:
#   cargo build --release --workspace && ./deploy/e2e/run-coordinator-install-test.sh
# Exit code 0 = every check passed.

set -euo pipefail
cd "$(dirname "$0")/../.."   # repo root
BIN=${BIN:-$PWD/target/release}
IMAGE=${IMAGE:-docker.io/library/archlinux:latest}
PODMAN=${PODMAN:-podman}

for b in wireserve-coordinator wireserve-admin; do
    [ -x "$BIN/$b" ] || { echo "FAIL: $BIN/$b missing — run cargo build --release --workspace" >&2; exit 1; }
done

WORK=$(mktemp -d)
CONTAINERS=()
log() { echo; echo "=== $* ==="; }
pass() { echo "PASS: $*"; }
fail() {
    echo "FAIL: $*" >&2
    for c in "${CONTAINERS[@]}"; do
        echo "--- journal of $c" >&2
        $PODMAN exec "$c" journalctl -u wireserve-coordinator --no-pager -n 30 >&2 || true
    done
    exit 1
}
cleanup() {
    for c in "${CONTAINERS[@]}"; do $PODMAN rm -f "$c" >/dev/null 2>&1 || true; done
    rm -rf "$WORK"
}
trap cleanup EXIT

# Just the two binaries, side by side, as an operator would copy them over.
mkdir -p "$WORK/bin"
cp "$BIN/wireserve-coordinator" "$BIN/wireserve-admin" "$WORK/bin/"

boot() {
    local name=$1
    # SYS_ADMIN (inside the user namespace only): systemd needs it to set
    # up the unit's sandbox (ProtectSystem=, PrivateTmp=, ...).
    $PODMAN run -d --name "$name" --systemd=always --cap-add SYS_ADMIN \
        -v "$WORK/bin:/opt/ws:ro" \
        "$IMAGE" /usr/lib/systemd/systemd >/dev/null
    CONTAINERS+=("$name")
    for _ in $(seq 1 60); do
        state=$($PODMAN exec "$name" systemctl is-system-running 2>/dev/null || true)
        case "$state" in running|degraded) return 0 ;; esac
        sleep 0.5
    done
    # A container that already exited has no journal to read; its own
    # output is what says why.
    $PODMAN logs "$name" 2>&1 | tail -30 >&2 || true
    fail "$name: systemd did not come up (state: $state)"
}
in_c() { local c=$1; shift; $PODMAN exec "$c" "$@"; }
main_pid() { in_c "$1" systemctl show -p MainPID --value wireserve-coordinator; }

# ---------------------------------------------------------------------
log "fresh install, no terminal, flags only"
C=wireserve-coord-install-$$
boot "$C"
in_c "$C" useradd -m tester
in_c "$C" env SUDO_USER=tester /opt/ws/wireserve-coordinator install \
    --public-url https://mesh.test --port 48000 --yes >"$WORK/fresh.out" 2>&1 \
    || { cat "$WORK/fresh.out"; fail "install exited non-zero"; }
cat "$WORK/fresh.out"

in_c "$C" systemctl is-active --quiet wireserve-coordinator || fail "service is not active"
pass "service active"
owner=$(in_c "$C" stat -c %U "/proc/$(main_pid "$C")")
[ "$owner" = wireserve-coordinator ] || fail "service runs as $owner"
pass "runs as wireserve-coordinator"
in_c "$C" getent group wireserve-coordinator >/dev/null || fail "no wireserve-coordinator group"
if in_c "$C" getent passwd wireserve >/dev/null; then fail "created the old wireserve user"; fi
pass "own user and group, no wireserve user"
for b in wireserve-coordinator wireserve-admin; do
    in_c "$C" test -x "/usr/local/bin/$b" || fail "/usr/local/bin/$b not installed"
done
pass "both binaries installed"

in_c "$C" cat /etc/wireserve/coordinator.env > "$WORK/env1"
expect_key() {
    local file=$1 line=$2
    grep -qxF "$line" "$file" || { grep '^WIRESERVE' "$file" >&2; fail "env file lacks '$line'"; }
}
expect_key "$WORK/env1" WIRESERVE_PUBLIC_URL=https://mesh.test
expect_key "$WORK/env1" WIRESERVE_LISTEN_ADDR=127.0.0.1:48000
expect_key "$WORK/env1" WIRESERVE_ADMIN_LISTEN_ADDR=127.0.0.1:48001
expect_key "$WORK/env1" WIRESERVE_TRUST_PROXY_HEADERS=true
expect_key "$WORK/env1" WIRESERVE_REQUIRE_SERVICE_APPROVAL=true
if grep -q '^WIRESERVE_SERVICE_DOMAIN=' "$WORK/env1"; then fail "install set a domain"; fi
if grep -q '^WIRESERVE_TRUSTED_PROXY=' "$WORK/env1"; then fail "trusted proxy set for a local web server"; fi
[ "$(in_c "$C" stat -c '%U %a' /etc/wireserve/coordinator.env)" = "root 600" ] || fail "env file not root 600"
pass "env file holds exactly the answers, root 600"
for verb in "setup domain" "setup login"; do
    grep -q "wireserve-coordinator $verb" "$WORK/fresh.out" || fail "install does not point at $verb"
done
pass "install points at the setup commands"

in_c "$C" runuser -l tester -c 'wireserve-admin node list' >/dev/null || fail "wireserve-admin does not work for tester"
pass "wireserve-admin works for the admin user with no flags"
[ "$(in_c "$C" stat -c '%U %a' /home/tester/.config/wireserve-admin/admin_token)" = "tester 600" ] \
    || fail "admin_token not tester 600"
in_c "$C" runuser -l tester -c 'wireserve-admin node create box1' > "$WORK/create.out" 2>&1 || fail "node create failed"
grep -q 'https://mesh.test' "$WORK/create.out" || { cat "$WORK/create.out"; fail "node create does not print the public address"; }
pass "node create prints the public address"

# ---------------------------------------------------------------------
log "setup domain sets the domain, and restarts the service"
before=$(main_pid "$C")
in_c "$C" /opt/ws/wireserve-coordinator setup domain --domain int.test --no-dns --yes >"$WORK/domain.out" 2>&1 \
    || { cat "$WORK/domain.out"; fail "setup domain exited non-zero"; }
in_c "$C" cat /etc/wireserve/coordinator.env > "$WORK/env1b"
expect_key "$WORK/env1b" WIRESERVE_SERVICE_DOMAIN=int.test
[ "$(main_pid "$C")" != "$before" ] || fail "setup domain did not restart the service"
in_c "$C" systemctl is-active --quiet wireserve-coordinator || fail "service not active after setup domain"
pass "domain set, service restarted"

# ---------------------------------------------------------------------
log "--reconfigure changes only its own keys"
in_c "$C" sh -c 'echo "RUST_LOG=debug" >> /etc/wireserve/coordinator.env'
in_c "$C" /opt/ws/wireserve-coordinator install --reconfigure --no-approval --yes >"$WORK/reconf.out" 2>&1 \
    || { cat "$WORK/reconf.out"; fail "reconfigure exited non-zero"; }
in_c "$C" cat /etc/wireserve/coordinator.env > "$WORK/env2"
expect_key "$WORK/env2" RUST_LOG=debug
expect_key "$WORK/env2" WIRESERVE_REQUIRE_SERVICE_APPROVAL=false
expect_key "$WORK/env2" WIRESERVE_SERVICE_DOMAIN=int.test
expect_key "$WORK/env2" WIRESERVE_PUBLIC_URL=https://mesh.test
in_c "$C" systemctl is-active --quiet wireserve-coordinator || fail "service not active after reconfigure"
in_c "$C" runuser -l tester -c 'wireserve-admin node list' >/dev/null || fail "admin key changed on reconfigure"
pass "hand-added line kept, approval off, the domain and the rest unchanged, same admin key"

# ---------------------------------------------------------------------
log "setup login writes and clears its keys, and the old sign-in's"
# A key the forward_auth sign-in read before M48: nothing reads it now, and
# setup login takes it out, saying so.
in_c "$C" sh -c 'echo "WIRESERVE_AUTH_SERVICE=auth" >> /etc/wireserve/coordinator.env'
in_c "$C" env WIRESERVE_OIDC_CLIENT_SECRET=s3cret /opt/ws/wireserve-coordinator setup login \
    --issuer https://id.test/application/o/wireserve/ --client-id wireserve --skip-check --yes >"$WORK/login.out" 2>&1 \
    || { cat "$WORK/login.out"; fail "setup login exited non-zero"; }
in_c "$C" cat /etc/wireserve/coordinator.env > "$WORK/env2b"
expect_key "$WORK/env2b" WIRESERVE_OIDC_ISSUER=https://id.test/application/o/wireserve/
expect_key "$WORK/env2b" WIRESERVE_OIDC_CLIENT_ID=wireserve
expect_key "$WORK/env2b" WIRESERVE_OIDC_CLIENT_SECRET=s3cret
if grep -q '^WIRESERVE_AUTH_SERVICE=' "$WORK/env2b"; then fail "the old sign-in's key is still active"; fi
if grep -q 's3cret' "$WORK/login.out"; then fail "the client secret was printed"; fi
in_c "$C" systemctl is-active --quiet wireserve-coordinator || fail "service not active with a login server set up"
grep -q 'owner link' "$WORK/login.out" || { cat "$WORK/login.out"; fail "setup login does not say what's next"; }
grep -q 'setup domain' "$WORK/login.out" || { cat "$WORK/login.out"; fail "setup login does not say the sign-in needs DNS records"; }
pass "login server set up (issuer as typed, secret from the environment, never printed); the old key gone"

in_c "$C" /opt/ws/wireserve-coordinator setup login --off --yes >"$WORK/login-off.out" 2>&1 \
    || { cat "$WORK/login-off.out"; fail "setup login --off failed"; }
in_c "$C" cat /etc/wireserve/coordinator.env > "$WORK/env2c"
if grep -q '^WIRESERVE_OIDC_' "$WORK/env2c"; then fail "an OIDC key is still active"; fi
expect_key "$WORK/env2c" "# WIRESERVE_OIDC_CLIENT_SECRET=s3cret"
pass "--off comments the login server's keys out"

in_c "$C" /opt/ws/wireserve-coordinator setup domain --off --yes >"$WORK/domain-off.out" 2>&1 \
    || { cat "$WORK/domain-off.out"; fail "setup domain --off failed"; }
in_c "$C" cat /etc/wireserve/coordinator.env > "$WORK/env3"
if grep -q '^WIRESERVE_SERVICE_DOMAIN=' "$WORK/env3"; then fail "domain still active"; fi
expect_key "$WORK/env3" "# WIRESERVE_SERVICE_DOMAIN=int.test"
pass "a dropped domain is commented out, not deleted"

# ---------------------------------------------------------------------
log "a plain re-run upgrades, and leaves the settings alone"
before=$(main_pid "$C")
in_c "$C" /opt/ws/wireserve-coordinator install </dev/null >"$WORK/upgrade.out" 2>&1 \
    || { cat "$WORK/upgrade.out"; fail "upgrade exited non-zero"; }
grep -q 'upgraded; restarted wireserve-coordinator' "$WORK/upgrade.out" || { cat "$WORK/upgrade.out"; fail "no upgrade message"; }
in_c "$C" cat /etc/wireserve/coordinator.env > "$WORK/env4"
cmp -s "$WORK/env3" "$WORK/env4" || fail "upgrade changed the env file"
[ "$(main_pid "$C")" != "$before" ] || fail "service was not restarted"
pass "upgraded, restarted, env file byte-identical"

if in_c "$C" /opt/ws/wireserve-coordinator install --no-approval >"$WORK/refuse.out" 2>&1; then
    fail "a settings flag without --reconfigure was accepted"
fi
grep -q -- '--reconfigure' "$WORK/refuse.out" || { cat "$WORK/refuse.out"; fail "refusal does not point at --reconfigure"; }
pass "settings flags on an installed host point at --reconfigure"

echo
echo "ALL COORDINATOR INSTALL CHECKS PASSED"
