<!--
SPDX-FileCopyrightText: 2026 TII (SSRC) and the Ghaf contributors
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Contributing

Contributions to Ghaf FortiVPN are welcome. Use a personal fork, create a
focused branch, and submit a pull request to `tiiuae/ghaf-fortivpn`.

## Before submitting a change

Run the following checks from the repository root:

```console
cargo fmt --manifest-path gui/Cargo.toml --all -- --check
cargo fmt --manifest-path service/Cargo.toml --all -- --check
cargo clippy --locked --manifest-path gui/Cargo.toml --all-targets -- --deny warnings
cargo clippy --locked --manifest-path service/Cargo.toml --all-targets -- --deny warnings
cargo test --locked --manifest-path gui/Cargo.toml
cargo test --locked --manifest-path service/Cargo.toml
reuse lint
```

Changes affecting the D-Bus interface, certificate handling, secret handling,
filesystem permissions, or NetworkManager settings should explain their
security impact in the pull request.

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/) with an
optional scope:

```text
feat(gui): add trusted-certificate validation
fix(service): reject expired client certificates
docs: clarify the cross-VM security boundary
```

Keep the subject imperative and concise. Add a body when the motivation,
security implications, or behavior are not obvious from the subject.

## Licensing

Add SPDX headers to new files. Use Apache-2.0 for source code and configuration
and CC-BY-SA-4.0 for documentation. Run `reuse lint` before submitting.
