#!/usr/bin/env bash
# Builds what the podman e2e suites run, once for all of them: every
# wireserve binary in a single cargo invocation, then the coordinator,
# agent and debug-tools images tagged `:e2e`. Each suite calls this first;
# when nothing changed it takes seconds, so running suites one after
# another does not rebuild anything.
#
# Why not just `podman build` the shipped Dockerfiles, as the suites used
# to: those build each image from scratch with `--release`, one cargo run
# per image (with different packages selected, so shared dependencies can
# be compiled twice over with different features). Here cargo runs in a
# throwaway rust:1-slim-bookworm container whose target directory is a
# named volume that outlives it, so a change recompiles incrementally.
# The binaries go to target/e2e/bin, and the shipped Dockerfiles take them
# from there with `--build-arg BINARIES=prebuilt` — the e2e images are
# the shipped runtime stage, only the compiling is done differently.
#
# Not the host's own cargo: the host's glibc is usually newer than the
# images' Debian bookworm, and a binary linked against it won't start
# there. Building on bookworm makes binaries that run in the images (and
# on any newer host).
#
# Debug builds by default — much faster to compile, and the suites check
# behaviour, not speed. E2E_RELEASE=1 builds what ships instead:
#
#   sudo E2E_RELEASE=1 ./deploy/e2e/run-e2e-test.sh
#
# E2E_PREBUILT=1 compiles nothing and builds the images from whatever is
# already in target/e2e/bin. The release workflow uses it to run the
# suites against the very binaries it then publishes:
#
#   sudo E2E_PREBUILT=1 ./deploy/e2e/run-e2e-test.sh
#
# The cargo caches are the volumes wireserve-e2e-target and
# wireserve-e2e-registry; `podman volume rm` them if a build ever looks
# like it is reusing something it should not.

set -euo pipefail
cd "$(dirname "$0")/../.."   # repo root

if [ "${E2E_PREBUILT:-0}" = 1 ]; then
    profile=prebuilt
elif [ "${E2E_RELEASE:-0}" = 1 ]; then
    profile=release
else
    profile=debug
fi
out=target/e2e/bin

if [ "${E2E_PREBUILT:-0}" = 1 ]; then
    for b in wireserve wireserve-coordinator wireserve-admin; do
        [ -x "$out/$b" ] || { echo "E2E_PREBUILT=1 but $out/$b is missing or not executable" >&2; exit 1; }
    done
    echo "=== using the prebuilt binaries in $out ==="
else
echo "=== building wireserve ($profile) ==="
mkdir -p "$out"
# The source is mounted read-only (--locked keeps cargo from wanting to
# rewrite Cargo.lock), the build happens in the target volume, and only
# binaries that actually changed are copied out — an unchanged binary
# keeps the image layers below cached.
# RUSTUP_TOOLCHAIN: see the comment on it in deploy/docker/agent.Dockerfile.
podman run --rm \
    -v "$PWD:/src:ro" \
    -v "$PWD/$out:/out" \
    -v wireserve-e2e-target:/target \
    -v wireserve-e2e-registry:/usr/local/cargo/registry \
    -e CARGO_TARGET_DIR=/target \
    -e CARGO_PROFILE_DEV_DEBUG=line-tables-only \
    -e PROFILE="$profile" \
    -w /src \
    docker.io/library/rust:1-slim-bookworm \
    sh -c '
        set -e
        export RUSTUP_TOOLCHAIN="$(rustup default | cut -d" " -f1)"
        if [ "$PROFILE" = release ]; then flag=--release; else flag=; fi
        cargo build --locked --workspace --bins $flag
        for b in wireserve wireserve-coordinator wireserve-admin; do
            cmp -s "/target/$PROFILE/$b" "/out/$b" || cp "/target/$PROFILE/$b" "/out/$b"
        done
    '
# Under sudo, hand the copies back to whoever ran it, so a later plain
# `cargo clean` can remove them.
if [ -n "${SUDO_UID:-}" ]; then
    chown -R "$SUDO_UID:${SUDO_GID:-$SUDO_UID}" target/e2e
fi
fi

echo "=== building e2e images ==="
podman build -q --build-arg BINARIES=prebuilt \
    -f deploy/docker/coordinator.Dockerfile -t wireserve-coordinator:e2e . >/dev/null
podman build -q --build-arg BINARIES=prebuilt \
    -f deploy/docker/agent.Dockerfile -t wireserve-agent:e2e . >/dev/null
podman build -q -f deploy/e2e/debug-tools.Dockerfile -t wireserve-e2e-debug-tools deploy/e2e >/dev/null
echo "images ready: wireserve-coordinator:e2e, wireserve-agent:e2e ($profile)"
