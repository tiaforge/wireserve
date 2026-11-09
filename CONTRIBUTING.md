# Contributing to wireserve

Thank you for wanting to help. Bug reports, ideas and pull requests are all
welcome on GitHub: <https://github.com/tiaforge/wireserve>.

## Reporting a bug

Open an issue and include:

- what you ran, and what you expected to happen;
- what happened instead, with the output of `wireserve status` and the
  relevant lines from `journalctl -u wireserve-agent`;
- your distribution, kernel version (`uname -r`) and wireserve version
  (`wireserve --version`).

If you think you have found a security problem, do not open a public
issue. Report it privately instead: on GitHub, open the Security tab and
choose "Report a vulnerability".

## Sending a pull request

1. For anything bigger than a small fix, open an issue first and describe
   what you want to change. That saves you work if the change does not fit
   the project.
2. Build and test as described in [Building from source](docs/building.md).
   `cargo test --workspace` and `cargo clippy --workspace` should pass.
3. Do not run `cargo fmt`. The code is not rustfmt-formatted, and a run
   rewrites dozens of unrelated files. Match the style around your change.
4. Open the pull request against `main`.

### Licensing of contributions

wireserve is licensed under the [Apache License 2.0](LICENSE), and so is
what you contribute: section 5 of the license says a contribution you
submit is under its terms unless you say otherwise. There is no agreement
to sign and nothing to add to your commits.

## How pull requests are merged

Development happens on a separate Forgejo server, and GitHub is a mirror of
it. A pull request is therefore not merged with GitHub's "Merge" button.
Your commits are merged on the main server, unchanged, and when the mirror
updates, GitHub shows the pull request as merged. This can take a few
minutes after the maintainer says it is done.
