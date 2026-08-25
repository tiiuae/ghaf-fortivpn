<!--
SPDX-FileCopyrightText: 2026 TII (SSRC) and the Ghaf contributors
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Security policy

## Supported versions

Until the first stable release, security fixes are applied to the latest
revision of the `main` branch. After releases begin, the latest release will
receive security fixes.

## Reporting a vulnerability

Do not report suspected vulnerabilities in a public issue.

Use GitHub's
[private vulnerability reporting](https://github.com/tiiuae/ghaf-fortivpn/security/advisories/new)
form. Include the affected revision, expected and observed behavior, potential
impact, and reproduction steps when they can be shared safely.

Particularly sensitive areas include:

- the `org.ghaf.FortiVpn1` authorization boundary;
- certificate and private-key parsing;
- secret lifetime, logging, and persistence;
- filesystem paths, ownership, and permissions; and
- construction of NetworkManager connection settings.

The Ghaf security team will acknowledge and assess reports through the private
advisory. Disclosure will be coordinated after a fix or mitigation is
available.
