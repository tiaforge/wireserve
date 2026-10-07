# Releasing

Development happens on Forgejo. GitHub is a public push mirror, and the
GitHub Actions there run the checks and publish releases.

## What runs where

- **Every branch push and pull request**
  (`.github/workflows/ci.yml`): unit tests on x86_64 and aarch64, in
  strict mode, so a firewall test that would quietly skip fails instead;
  then `cargo clippy -D warnings`.
- **The Release workflow** (`.github/workflows/release.yml`):
  1. Builds the release binaries on Debian bookworm for both
     architectures.
  2. Runs every `deploy/e2e/run-*-test.sh` suite against exactly those
     binaries, on both architectures.
  3. Started by a tag, it then publishes; started by hand or by the
     nightly schedule, it stops here.

  The nightly run (03:17 UTC, on `main`) catches a broken suite the day
  it breaks instead of on release day. It skips itself when `main` has
  not moved since the last green nightly. GitHub emails a failed
  scheduled run to whoever last changed the `cron:` line.

  A release publishes:
  - `wireserve-<version>-<arch>-linux.tar.gz`: the agent, for bare metal.
  - `wireserve-coordinator-<version>-<arch>-linux.tar.gz`: the
    coordinator and `wireserve-admin`.
  - `SHA256SUMS`.
  - `ghcr.io/<owner>/wireserve-coordinator:<version>` for amd64 and
    arm64, with `wireserve-admin` inside. A pre-release does not move
    `latest`.

## Cutting a release

1. **Dry run.** Push to Forgejo, wait for the mirror to sync, then on
   GitHub go to Actions → Release → Run workflow, on `main`. It builds
   and runs all the e2e suites, and publishes nothing.
2. **Tag.** Once the dry run is green:

   ```sh
   deploy/release.sh 1.0.0-beta.1
   ```

   It checks that you are on a clean `main` that matches `origin/main`,
   sets the version in `Cargo.toml`, commits "Release 1.0.0-beta.1", tags
   `v1.0.0-beta.1`, and asks before pushing both to Forgejo. The mirror
   carries the tag to GitHub, and the Release workflow builds, tests and
   publishes it. The workflow refuses a tag that doesn't match the
   version in `Cargo.toml`.

Versions are semver, as Cargo requires: `1.0.0-beta.1`, not `1.0-beta1`.
Anything with a hyphen becomes a GitHub pre-release.

**If a tag's run fails**, nothing has been published. Delete the tag on
Forgejo (`git push origin :refs/tags/v1.0.0-beta.1` and
`git tag -d v1.0.0-beta.1`). The next mirror sync removes it from GitHub
too. Fix the problem, then release again.

## Why the workflow never makes the tag

A Forgejo push mirror runs `git push --mirror`, which deletes every ref on
GitHub that Forgejo does not have. A tag made on GitHub would disappear at
the next sync, and its release would turn back into a draft. Tags
therefore always start on Forgejo.

## One-time setup

- **Forgejo push mirror:** enable "sync when commits are pushed", so
  the tag reaches GitHub straight away instead of at the next interval.
  The mirror's token needs the `workflow` scope, or GitHub refuses
  pushes that change `.github/workflows/`.
- **Forgejo Actions:** if Actions is enabled on this repository, Forgejo
  runs `.github/workflows` itself whenever there is no
  `.forgejo/workflows`. Disable Actions for the repository there.
- **ghcr package:** after the first release, open the
  `wireserve-coordinator` package on GitHub and check that it is
  public. If it isn't, change its visibility once in the package
  settings.
