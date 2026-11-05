# RahaWRT

Open-source Persian/English management for OpenWrt with **PassWall2 already
installed**. MIT licensed; no commercial activation or mandatory cloud service.

## Implemented development version

- Responsive Persian RTL/English LTR panel at `/wrt/`; HTTPS router API, PBKDF2
  passwords, revocable sessions, administrator/operator/user/accounting roles.
- DHCP discovery and reservation, MAC-based DHCP rebinding, existing PassWall2
  node selection per device, direct/global/specific-node modes and independent
  internet/VPN schedules including overnight windows.
- Persistent per-device/account usage, shared directional account speed budgets,
  quota block/reduced-speed plans, expiry, online duration, device/login-session
  limits, session history, UTC daily/monthly reports and CSV export.
- Invoice-idempotent account/renewal issuance, printable voucher batches, scoped
  hashed API keys, request limits, audit metadata and account lifecycle controls.
- Optional isolated guest bridge/Wi-Fi provisioning, DHCP captive discovery
  (RFC 8908/8910), legacy HTTP discovery redirect, isolated HTTPS account portal
  on port 8443 and unknown/unauthenticated guest denial.
- Per-device DNS parental profiles, allow/block suffixes, attributed adult-list
  refresh, selected SafeSearch names, DoT/DoQ and known DoH-name restrictions.
- Optional native WireGuard/OpenVPN/OpenConnect configuration/import and guarded
  L2TP over pre-existing IPsec; these interfaces remain separate from PassWall2
  nodes; per-client source routing keeps the router default route intact.
  Strict native paths retain an unreachable route when the interface goes down.
- Independent boot/firewall/stall guard, confirmation watchdog for
  guest/DHCP/tunnel configuration, sensitive backups,
  offline restore with preimage rollback, resource observations and route diagnostics.

**Not a production-ready router release.** Host tests, actual Linux packet tests
and real Chromium UI checks pass. The OpenWrt 24.10.8 x86 SDK leaf package builds; its full prerequisite rebuild
is network-blocked. Real OpenWrt UCI and host uhttpd HTTPS/CGI pass; firmware
netifd/procd daemons,
actual PassWall2/proxy routing, emulator and physical router tests have not run.
x86 is the first physical target. Architecture `all` is not a compatibility badge.
No signed installable release has been published.

```sh
make check test build
sh scripts/dev-setup.sh
python3 scripts/test-nft.py
python3 scripts/test-packets.py
python3 scripts/test-native-dns.py
sh scripts/uhttpd-setup.sh
python3 scripts/test-uhttpd.py
python3 scripts/test-portal-flow.py
sh scripts/browser-setup.sh
node scripts/test-browser.cjs
```

- [Development, installation and recovery](docs/development.md)
- [API v1 and accounting examples](docs/api.md)
- [Validation evidence, limitations and x86 checklist](docs/validation.md)
- [Architecture inventory and official refresh](docs/architectures.md)
- [Third-party licensing and attribution](THIRD_PARTY.md)

The one-command installer accepts a **local native package, signed manifest and
independently trusted public key**. There is no release URL to pipe into a root
shell. Installation and activation are separate. Read the limitations before
using enforcement: concrete Xray/sing-box nodes have a private same-node DNS transport and native
tunnels have a marked DNS worker. Unsupported/failed strict DNS paths return
SERVFAIL; direct fallback requires explicit policy. Boot/firewall guards and these
proxy integrations still require real x86/PassWall2 acceptance tests.

Native development archives can also be built without an SDK: `make build`
produces the portable source archive and an architecture-all IPK; after
`sh scripts/packaging-setup.sh`, `make apk` produces a noarch APK v3.
`python3 scripts/test-packages.py` checks the official IPK payload and native APK
signature/integrity behavior with temporary fixture keys. These archives are
unsigned development artifacts, not published or hardware-certified releases.

### Dashboard screenshots

Real Chromium captures with seeded test devices and usage. Resources belong to
the preview host; these images do not demonstrate a connected OpenWrt router.

- [Persian dashboard](docs/screenshots/dashboard-fa-desktop.png)
- [English dashboard](docs/screenshots/dashboard-en-desktop.png)
