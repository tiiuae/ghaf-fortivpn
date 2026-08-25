<!--
SPDX-FileCopyrightText: 2026 TII (SSRC) and the Ghaf contributors
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Ghaf FortiVPN

Ghaf FortiVPN is a native COSMIC application for creating NetworkManager
FortiSSLVPN profiles in [Ghaf](https://github.com/tiiuae/ghaf).

The application is split across Ghaf's security boundary:

- `gui/` contains the unprivileged libcosmic frontend that runs in `gui-vm`.
- `service/` contains the privileged backend that runs in `net-vm`, validates
  profile and certificate input, stores certificate material, and creates the
  NetworkManager connection.

Packaging is maintained separately in
[`tiiuae/ghafpkgs`](https://github.com/tiiuae/ghafpkgs), while VM deployment,
systemd hardening, and cross-VM D-Bus policy belong to
[`tiiuae/ghaf`](https://github.com/tiiuae/ghaf).

## Features

The profile form supports:

- connection name, gateway, port, optional realm, username, and VPN password;
- an optional trusted-gateway SHA-256 certificate fingerprint;
- an optional PKCS#12 bundle (`.p12` or `.pfx`) and import password;
- alternatively, an X.509 client certificate and a matching private key in
  supported PEM or DER formats; and
- an optional gateway CA certificate.

New profiles appear in **COSMIC Settings → Network & Wireless → VPN**, where
NetworkManager handles normal connection management.

## Architecture

```text
gui-vm                                      net-vm

ghaf-fortivpn                              ghaf-fortivpn-service
      │                                              │
      └── org.ghaf.FortiVpn1 over D-Bus ────────────┤
                                                     │
                                                     └── NetworkManager D-Bus
```

The backend owns the privileged operations. The frontend never writes
NetworkManager system connections or certificate material directly.

The D-Bus contract currently uses:

- bus name: `org.ghaf.FortiVpn`
- object path: `/org/ghaf/FortiVpn`
- interface: `org.ghaf.FortiVpn1`

## Security model

- VPN and certificate passwords are never passed through command-line
  arguments or environment variables.
- Import passwords and private-key passphrases are not persisted by the
  application.
- Certificate inputs have strict size limits and are parsed by the backend
  with OpenSSL.
- The backend checks certificate validity and verifies that a client
  certificate matches its private key.
- Imported private keys are normalized to unencrypted PKCS#8 and stored as
  root-owned mode `0600` files below `/var/lib/ghaf/fortivpn` by default.
- The backend creates profiles through NetworkManager's D-Bus API rather than
  invoking `nmcli` with secrets.

The consuming Ghaf configuration must restrict access to the backend's D-Bus
interface, sandbox its systemd service, and make the service available only to
the intended `gui-vm` identity. Those deployment controls are not defined in
this source repository.

## Development

Install a current stable Rust toolchain. The GUI additionally requires the
development libraries for Wayland, `libxkbcommon`, Vulkan, and `pkg-config`.
The service requires OpenSSL development headers.

Build both components:

```console
cargo build --locked --manifest-path gui/Cargo.toml
cargo build --locked --manifest-path service/Cargo.toml
```

Run the local checks used by CI:

```console
cargo fmt --manifest-path gui/Cargo.toml --all -- --check
cargo fmt --manifest-path service/Cargo.toml --all -- --check
cargo clippy --locked --manifest-path gui/Cargo.toml --all-targets -- --deny warnings
cargo clippy --locked --manifest-path service/Cargo.toml --all-targets -- --deny warnings
cargo test --locked --manifest-path gui/Cargo.toml
cargo test --locked --manifest-path service/Cargo.toml
reuse lint
```

The backend expects a system bus and NetworkManager. Running it directly on a
development machine does not reproduce Ghaf's cross-VM authorization model.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow. Please
report suspected vulnerabilities according to [SECURITY.md](SECURITY.md), not
through a public issue.

## License

Source code is licensed under Apache-2.0. Documentation is licensed under
CC-BY-SA-4.0. See [LICENSES](LICENSES/) for the full license texts.

Fortinet product names are used only to identify compatibility. This project
is not affiliated with or endorsed by Fortinet.
