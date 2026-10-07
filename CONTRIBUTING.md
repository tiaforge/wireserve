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

### The contributor agreement

The first time you open a pull request, a bot asks you to sign the
[Contributor License Agreement](CLA.md). You sign by posting one sentence as
a comment. You only do this once.

Why it is needed: wireserve is free for noncommercial use, and businesses
buy a commercial license. That is only possible if we can license every
part of wireserve commercially, including your contribution. You keep the
copyright in your work, and every published version that contains it stays
available under wireserve's free license. Read [CLA.md](CLA.md) for the
details. It is short.

If you contribute as part of your job, check with your employer first. See
section 8 of the agreement.

## How pull requests are merged

Development happens on a separate Forgejo server, and GitHub is a mirror of
it. A pull request is therefore not merged with GitHub's "Merge" button.
Your commits are merged on the main server, unchanged, and when the mirror
updates, GitHub shows the pull request as merged. This can take a few
minutes after the maintainer says it is done.
