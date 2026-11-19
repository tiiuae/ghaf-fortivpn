<!--
SPDX-FileCopyrightText: 2026 TII (SSRC) and the Ghaf contributors
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Ghaf FortiVPN

Ghaf FortiVPN is a native COSMIC application for creating NetworkManager
Fortinet SSL VPN profiles using OpenConnect in [Ghaf](https://github.com/tiiuae/ghaf).
It is intended for regular VPN use on Ghaf systems.

The application is split across Ghaf's security boundary:

- `gui/` contains the unprivileged libcosmic frontend that runs in `gui-vm`.
- `service/` contains the privileged backend that runs in `net-vm`, validates
  profile and certificate input, stores certificate material, creates the
  NetworkManager connection, and authenticates with OpenConnect.

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
NetworkManager handles normal connection management. Connections are saved
through NetworkManager, and the backend stores their authentication material
for reuse on subsequent connections and service starts.

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
- Deleting a VPN profile also removes its saved password and imported keys from
  `net-vm`. The backend checks for missed deletions at startup, when NetworkManager
  returns, and before creating a profile. Up to 32 OpenConnect Fortinet profiles are allowed.
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

## OpenConnect authentication

Profiles use `org.freedesktop.NetworkManager.openconnect` with
`protocol=fortinet`. NetworkManager still owns the tunnel, routes, DNS and
connect/disconnect controls. The existing `CreateProfile` D-Bus method and
profile-creation form are unchanged.

The net-VM OpenConnect plugin calls the existing backend on demand for managed
profiles. The desktop listens for `AuthenticationPending` and invokes
`ghaf-fortivpn --present-pending` to display outstanding password or MFA
requests. Both helpers exit after the operation.

OpenConnect's tunnel plugin consumes a session cookie, not a saved VPN password.
The backend therefore stores authentication input in a mode `0600` `auth.json`
inside each private profile directory. These files include the VPN password;
protect and persist the existing `/var/lib/ghaf/fortivpn` directory accordingly.
Certificate import passwords and private-key passphrases are still discarded.
Changing managed authentication settings through a generic connection editor
is rejected if they disagree with the private record, to prevent sending saved
credentials to a substituted gateway. Network settings such as routes and DNS
remain editable. Use the existing profile form to replace authentication
settings; a corrected login password entered during authentication is saved
only after successful authentication.

Authentication runs in a short-lived backend subprocess linked to
`libopenconnect`. It reads private keys in `net-vm`, uses private pipes for
credentials and authentication results, and creates no tunnel itself. Each
attempt is limited to 100 seconds and sixteen prompts; at most four
connections authenticate concurrently. Cancellation terminates its worker.
Cookies are returned only to the local tunnel plugin; they never enter the GUI or a persistent profile.

CA/hostname verification remains enabled. A configured trusted-gateway
fingerprint is a SHA-256 digest of the complete DER certificate and can accept
that specific certificate when normal verification fails. The separate
`gwcert` value passed to the tunnel is OpenConnect's own peer-certificate pin;
these two formats are deliberately not treated as interchangeable.

The on-demand GUI displays password retries and the plaintext or
HTML form challenges supported by OpenConnect's Fortinet implementation. It
works with the profile-creation window closed. Cancelling or closing the
prompt cancels that attempt. Gateway-supplied challenge text is displayed as
plain text. Browser SAML, IPsec, and Fortinet's non-PPP tunnel protocol are not
implemented by this integration. See [OpenConnect's Fortinet support and
reconnection limitations](https://www.infradead.org/openconnect/fortinet.html).
Real-gateway testing is required before claiming compatibility with a particular
FortiOS version or MFA configuration.

The [integration sources](integrations/) connect the NetworkManager OpenConnect plugin to the
backend and the COSMIC settings daemon to the prompt helper. The `ghafpkgs` flake builds both
hooks from the same revision as the application.

## Development

Install a current stable Rust toolchain. The GUI additionally requires the
development libraries for Wayland, `libxkbcommon`, Vulkan, and `pkg-config`.
The service requires a C compiler, `pkg-config`, OpenSSL and OpenConnect 9.12
or later development headers/libraries. The TLS tests require loopback TCP sockets. Profile tests cover credential binding. TLS tests
exercise the real OpenConnect library against a local authentication endpoint,
including a client-certificate handshake. They do not establish full tunnel or
real FortiGate interoperability.

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

Application code and the COSMIC integration use Apache-2.0. The NetworkManager
OpenConnect patch uses GPL-2.0-only. Documentation uses CC-BY-SA-4.0. See [LICENSES](LICENSES/) for the full license texts.

Fortinet product names are used only to identify compatibility. This project
is not affiliated with or endorsed by Fortinet.
