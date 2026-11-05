# RahaWRT development progress

Updated: 2026-11-05. This is a working development implementation, not a signed
production release. Changes were developed locally before the first source push.

Implemented: Persian/English panel, authenticated HTTPS CGI/API, PassWall2 ACL
adapter, device/account policies, directional caps and quotas, schedules,
parental DNS, guest provisioning and captive portal, voucher/accounting API,
reports, optional native-tunnel provisioning/source routes, backup/rollback and
independent enforcement guards. See README.md and docs/api.md for exact scope.

## Dashboard update

The overview now has Persian/English navigation, six API-backed status/resource
cards, readable device/usage tables and role-aware account/report views. Technical
policy details are collapsed. Session expiry clears authenticated views and cached
data. Real Chromium screenshots use seeded test devices, not a connected router:
[Persian dashboard](docs/screenshots/dashboard-fa-desktop.png),
[English dashboard](docs/screenshots/dashboard-en-desktop.png).

Guest provisioning now restarts its uhttpd listener; DHCP-only reservations no
longer restart it. The 101-test suite, Chromium, real TLS/CGI and isolated direct
guest lifecycle passed after this change. Current native IPK/APK packaging and
integrity checks passed; the current-source official SDK leaf rebuild also passed.

## Verified

- 101 Python/HTTP/CGI/DNS/SQLite tests.
- Real Chromium interface checks, including RTL/LTR, account issuance and roles.
- Real isolated Linux packet paths: caps, quota/session gates, MAC checks,
  parental DNS, captive redirect, pre-login portal DNS replies and native routes.
- Real host-built uhttpd with verified TLS and the packaged CGI; fixes cover its
  header allowlist, actual error status codes, cookies and guest isolation.
- Complete direct-node guest lifecycle across separate guest/WAN namespaces:
  local captive discovery, UDP/TCP DNS, HTTP redirect, HTTPS login, routed WAN,
  SQLite usage and logout closure. DHCP/router/upstream-DNS inputs are fixtures.
- Real OpenWrt 24.10.8 UCI userspace transactions and rollback.
- Native architecture-all IPK/noarch APK development packaging and native
  signature/integrity fixture checks. No release signing key was created.
- Official x86 SDK leaf-package build for the current dashboard and guest
  lifecycle payload; complete bytes, metadata, permissions and ownership verified.

## Outstanding

- Full SDK dependency rebuild: ncurses source access returned HTTP policy 403.
  Required domain additions are saved in the environment configuration draft.
- Latest complete setup rerun: automatic approval review could not execute it
  because its usage limit was reached. This was not an unsafe-action ruling.
- Real PassWall2/core, native peer handshake, firmware emulator and physical x86
  validation. No router connection or peer credentials have been supplied.
- Other architectures are not certified. Architecture-independent packaging
  does not certify their dependencies or hardware.
- Full end-to-end health/failover/reconnect, automatic IKE provisioning, hard
  TCP/UDP flow caps and production migration/retention work remain incomplete.

The reusable setup/start instructions are saved; saving does not apply network
changes or publish the cloud environment. See docs/validation.md for the detailed
ledger and x86 acceptance checklist. Never include passwords/private keys in
issues, commits, logs or chat.
