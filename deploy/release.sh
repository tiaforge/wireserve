#!/usr/bin/env bash
# Cuts a release: sets the workspace version, commits, tags v<version>,
# and (after asking) pushes main and the tag to origin. On GitHub the
# tag arriving through the push mirror starts .github/workflows/release.yml,
# which builds, runs every e2e suite and only then publishes.
#
#   deploy/release.sh 1.0.0-beta.1
#
# Run a dry run first — Actions → Release → Run workflow on GitHub — on
# the commit you mean to release. See docs/releasing.md.
#
# The tag is made here and not by the workflow: the Forgejo push mirror
# runs `git push --mirror`, which deletes every ref GitHub has that
# Forgejo does not, a tag made on GitHub included.

set -euo pipefail
cd "$(dirname "$0")/.."   # repo root

version=${1:-}
semver='^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'
if ! [[ $version =~ $semver ]]; then
    echo "usage: $0 <version>   e.g. $0 1.0.0-beta.1 (semver, no leading v)" >&2
    exit 2
fi
tag=v$version

[ "$(git branch --show-current)" = main ] || { echo "not on main" >&2; exit 1; }
[ -z "$(git status --porcelain)" ] || { echo "the working tree has changes; commit or stash them first" >&2; exit 1; }
git fetch --quiet origin
[ "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" ] \
    || { echo "main is not the same commit as origin/main; push or pull first" >&2; exit 1; }
if git rev-parse -q --verify "refs/tags/$tag" >/dev/null || git ls-remote --exit-code --tags origin "refs/tags/$tag" >/dev/null; then
    echo "tag $tag already exists" >&2
    exit 1
fi

current=$(sed -n '/^\[workspace.package\]/,/^\[/ s/^version = "\(.*\)"$/\1/p' Cargo.toml)
if [ "$current" != "$version" ]; then
    sed -i '/^\[workspace.package\]/,/^\[/ s/^version = ".*"$/version = "'"$version"'"/' Cargo.toml
    # Brings Cargo.lock's entries for the workspace's own crates along.
    cargo update --workspace --offline --quiet
    git commit --quiet -m "Release $version" Cargo.toml Cargo.lock
    echo "committed: Release $version ($current -> $version)"
fi
git tag -a "$tag" -m "wireserve $version"
echo "tagged $tag at $(git rev-parse --short HEAD)"

read -r -p "Push main and $tag to origin? [y/N] " answer
if [ "$answer" = y ] || [ "$answer" = Y ]; then
    git push --atomic origin main "$tag"
    echo "pushed. The mirror carries $tag to GitHub, where the Release workflow takes it from there."
else
    echo "not pushed. When ready:  git push --atomic origin main $tag"
    echo "to undo instead:         git tag -d $tag && git reset --hard origin/main"
fi
