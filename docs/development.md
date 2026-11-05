# Development, router bring-up and recovery

Python 3.11+ and its standard library/SQLite are runtime requirements. There is no
pip/npm dependency on the router. Node/Playwright/Chromium are development tests
only. The first implementation favors portability and testability over tiny-router
footprint: reserve at least 128 MiB RAM and 64 MiB free overlay for the initial
installer check, then budget additional storage for domain lists, accounting,
backups and Python dependencies. Measure actual requirements on x86 before release.
Architecture coverage is conditional on resources and native dependencies.

## Local checks and startup

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
sh scripts/packaging-setup.sh
python3 scripts/test-packages.py
make apk
# Optional Docker checks (managed proxy/CA preserved):
python3 scripts/test-openwrt-userspace.py
sh scripts/test-sdk.sh leaf
# Full SDK prerequisite rebuild, when source access is available:
sh scripts/test-sdk.sh full
```

The Debian x86_64 helper downloads nftables and its matching library using signed
Debian metadata/checksums into ignored `.local/`, without changing host networking.
Packet checks also require native `ip`/iproute2. All kernel scripts create a new
user/network namespace and refuse the parent's namespace. Namespace permissions,
veth, nft and CAP_NET_ADMIN are required; unavailable capabilities are blockers,
not passing checks. The host kernel lacks the connlimit expression used in a
separate feasibility check, so a hard TCP/UDP flow-count feature is not shipped.
`max_sessions` limits authenticated sessions only.

The browser helper pins Playwright 1.64.1, uses installed Chromium when available,
and otherwise downloads its normal browser with verification enabled. Set
`RAHAWRT_CHROMIUM=bundled` for Playwright's browser or provide its executable path.
CI declares host, isolated-kernel, native-package, host-uhttpd and browser jobs; these jobs have not been run
remotely simply because the workflow file exists.

Local preview, with no router enforcement:

```sh
mkdir -p .local
python3 -m rahawrt.server --db .local/state.db --create-admin owner
python3 -m rahawrt.server --db .local/state.db --web web --port 9080 --timezone Asia/Tehran
```

Administrator creation uses a non-echoing password prompt. Never put credentials
in command arguments, checked-in files or logs. Backend binding is loopback only;
on the router use uhttpd HTTPS. In cloud onboarding use internal HTTP requests and
tests; there is no user-facing localhost preview. Future tasks use the existing
isolated checkout; do not create a worktree unless explicitly requested.

## Native OpenWrt package

Use an exact OpenWrt SDK and a compatible PassWall2 feed. Copy this repository to
`package/rahawrt`, select `CONFIG_PACKAGE_rahawrt=m`, resolve trusted feed
prerequisites and run:

```sh
make package/rahawrt/compile V=s -j2
```

`PKGARCH=all` describes Python/shell/browser payloads with no native project binary.
It is not evidence of SDK compilation, installability, kernel compatibility or
PassWall2 availability on any architecture. `make build` creates a reproducible
source archive, architecture-all IPK and digest sidecars. The IPK payload is
compared byte-for-byte, with modes and root ownership, against the pinned official
OpenWrt packager. `sh scripts/packaging-setup.sh` builds the exact apk-tools 3.0.5
revision used by OpenWrt 25.12, using pinned local Meson/Ninja. It requires a C
compiler, pkg-config, OpenSSL and zlib development headers. `make apk` builds a
reproducible noarch APK v3 with OpenWrt conffile sidecars. Native tests reject
unsigned/corrupt packages, verify temporary fixture signatures using an explicit
trusted key, extract and compare the payload. None is a published signed release.
The SDK and official-index results are tracked separately in validation.md. The actual 24.10.8 x86 SDK leaf
package has been built and its complete payload/metadata verified. A full
prerequisite rebuild separately failed on policy-denied ncurses downloads.
`sh scripts/test-sdk.sh leaf` repeats only the package-recipe check; `full` is
the default and retains dependency failures. Never label leaf mode a successful
full dependency build. Both preserve proxy/TLS verification and use a pinned
SDK image, exact feeds, SDK host tools and umask 022.
Direct `downloads.openwrt.org` access currently returns policy HTTP 403; its domain
addition is saved in the environment draft. The official OpenWrt Docker SDK is
also distributed through approved registries; it is tested independently,
with the managed proxy and read-only CA mount preserved.

The one-command installation interface is:

```sh
sh scripts/install.sh rahawrt_VERSION.ipk release.manifest release.manifest.sig trusted-release.pub
```

Inputs are a local native package and an independently trusted usign public key.
The signed manifest contains exact `release VERSION PACKAGE_ARCH` and `checksum
SHA256 PACKAGE_BASENAME` entries only after matching SDK tests. No project release
key, signed support manifest or release package is published. Never invent those
inputs or fetch a key beside an unverified artifact and assume trust.

The installer requires OpenWrt, root, usign, existing/configured PassWall2, an
appropriate package manager, a signed exact support entry, verified SHA-256 and
free overlay. Native package management resolves dependencies through trusted
feeds. It preserves conffiles, does not install PassWall2 itself, never flashes
firmware or upgrades the distribution, and never activates enforcement. apk
installation dispatch exists but has not run. Core package dependencies include
Python/SQLite, ca-bundle, uhttpd, nftables-json and luci-app-passwall2; optional VPN
modules require their separate native protocol/core/kernel packages.

## First x86 router bring-up

1. Keep console access. Record exact firmware/release/target/architecture and
   PassWall2/core versions. Verify existing PassWall2 before installing RahaWRT.
2. Configure uhttpd HTTPS with a certificate trusted by the intended clients.
   The package uses `/www/wrt` and executable `/www/cgi-bin/rahawrt`; uhttpd's CGI
   prefix must be `/cgi-bin`. Nonstandard document roots need deliberate package
   configuration. Real OpenWrt UCI serialization/rollback is tested in an isolated official rootfs.
   Host-built uhttpd from the exact official recipe is tested with real verified
   TLS, the packaged CGI, secure cookies, header spoofing defenses and separate
   guest document roots in a disposable namespace. Its router adapters are
   fixtures; OpenWrt-target netifd/procd/PassWall2 integration remains unverified.
3. Create admin with `PYTHONPATH=/usr/lib/rahawrt python3 -m rahawrt.server
   --create-admin owner`. Enable `rahawrt.main.enabled=1`, commit and start its
   procd service. Keep enforcement off for initial panel/node/lease inspection.
4. Register one client. Existing DHCP static leases are suitable; the reservation
   API and DHCP MAC rebinding are available once explicitly enforcing. Record
   original settings and create a sensitive backup before network mutations.
5. Enable PassWall2 ACLs in LuCI and disable both flow-offload modes, then reload
   firewall. Active flowtables cause preflight rejection. The recognized Lua ACL
   schema uses `mode`/`node` with 0=direct, 1=specific node, 2=global node. Pending
   UCI edits, overlapping/ambiguous ACLs and unowned section conflicts are refused.
6. Set `rahawrt.main.enforce=1`, commit and restart RahaWRT. Check authenticated
   `status.applied/error` and follow every x86 acceptance check in validation.md.
   Enforcement starts the DNS policy listener on IPv4 port 1053. Public router
   zones must not expose that listener; unknown non-loopback clients are refused.
   The default upstream is 1.1.1.1:53; CLI `--dns-upstream` and
   `--dns-upstream-port` support an explicit local encrypted-DNS stub or resolver.
7. Configure a non-overlapping guest subnet only after the single-client path
   passes. Provision bridge/radio and a portal hostname with a trusted HTTPS
   certificate, inspect the pending change, reconnect and confirm within three
   minutes. It rolls back otherwise. Do not auto-confirm without testing access.
   Guest HTTPS uses `https://HOST:8443/wrt/` in a separate uhttpd instance with only
   RahaWRT files/CGI. Main LuCI management ports are not permitted in the guest
   zone. The existing main uhttpd certificate/key paths are reused. External
   TCP/80 discovery is redirected to local 2080 and then the configured HTTPS
   portal; HTTP never accepts credentials. Policy DNS permits the local portal
   while unauthenticated/exhausted clients cannot resolve upstream.

PassWall2 schema reviewed at upstream
`176e27cb8d9852ce9b30d2e180810b544d8fc9dc` on 2026-11-05, from
`luasrc/model/cbi/passwall2/client/acl_config.lua`, `root/usr/share/passwall2/app.sh`
and `root/usr/share/passwall2/nftables.sh`. Future/other schemas are unsupported
until reviewed; those upstream files are not redistributed here.

## Optional native VPN modules

POST `tunnels` with validated JSON or use the panel's JSON/file import form.
IDs are 1–7 letters/digits/underscores; native interfaces are named `rv_ID` and
remain distinct from PassWall2 nodes. A new reject-forwarding firewall zone and
no-default-route configuration prevent accidental global route takeover. Existing
sections/files are not overwritten. These are real configuration adapters, but
handshakes and reconnect behavior still require actual peers. Confirmed tunnels
can be selected by devices and plans (`node:"direct", tunnel:"rv_ID"`). Per-client
source/DNS-mark rules use protocol 242, free tables 40001–49999, source priorities
10001–19999 and DNS priorities 20001–29999. They preserve other tables/rules and
refuse collisions. A terminal unreachable default closes a strict down path;
explicit direct fallback removes only that client's rules. The nft forward guard
checks both tunnel directions. Real veth tests cover two simultaneous interfaces,
one going down, explicit fallback and independent cleanup; these are not actual
WireGuard/OpenVPN handshakes. Interface-name observations are checked against the
selected protocol's expected naming contract.

Manual WireGuard fields: `kind:"wireguard"`, `id`, `private_key`, `addresses`
(list including IPv4), `public_key`, `server`, numeric `port`, `allowed_ips` and
optional `preshared_key`, `keepalive`, `mtu`, `listen_port`. Alternatively `profile`
imports one `[Interface]` and one `[Peer]`. Script hooks are rejected. Imported DNS
is not installed globally; allowed_ips does not install default routes.

OpenVPN accepts `kind:"openvpn"`, `id` and `profile` with inline CA and optionally
inline client cert/key/tls-auth/tls-crypt. It rejects scripts/plugins/external file
references and enforces TUN/client TLS 1.2+, remote server certificate checking,
no route/DNS pushes and limited logging. Manual mode instead requires `server`,
CA PEM, optional port/proto/server_name and complete username/password or a client
certificate/key pair. Username/password alone do not define a usable server.
Generated profile files are private and credentials are not returned in listings.

OpenConnect accepts `kind:"openconnect"`, `id`, `server`, `username`, `password`,
optional `port`, `authgroup`, CA PEM and an explicit `sha256:HEX` certificate pin.
System certificate verification is retained when no pin/custom CA is supplied;
there is no accept-any-certificate switch. The adapter selects AnyConnect.

L2TP/IPsec accepts `kind:"l2tp-ipsec"`, `id`, IPv4 `server`, `username`, `password`
and `ipsec_reqid`. A matching **pre-existing established IPsec transport child SA**
is required; automatic IKE/PSK/certificate provisioning is not included. An nft
XFRM policy guard rejects UDP/1701 without the matching outbound policy. L2TP is
not enabled automatically at boot and must not be started before that guard.
The upstream options directory must be root-owned/private. This optional path
requires the nft IPsec expression and is not kernel/hardware-tested here.

Reviewed official sources: `openwrt/packages` openwrt-24.10 branch
`43f8e71106193791c2e338d9d58fd54ff682bf06`, files for OpenConnect, OpenVPN and
xl2tpd; `openwrt/openwrt` openwrt-24.10 branch
`34fa4b1af5a30d3a789f07078b91e23e78dad622`, wireguard-tools protocol script.
New tunnel interfaces can be brought up/down after confirming the change. A
reported interface `up` is not a verified tunnel-health/Internet-egress check.

## Backup, restore, rollback and upgrade

```sh
sh scripts/router.sh backup /secure/new-backup.zip
/etc/init.d/rahawrt stop
sh scripts/router.sh restore /secure/trusted-backup.zip
/etc/init.d/rahawrt start
```

ZIP backups include SQLite's consistent online snapshot, present OpenWrt config
exports and owned OpenVPN/OpenConnect files. They may contain VPN/Wi-Fi secrets
and private cached list data/license records. Store offline with mode 0600.
The authenticated HTTPS backup endpoint downloads the same format. Pending router
changes block snapshots. Size is capped at 64 MiB; archive checksums detect
corruption, not authenticity. Restore only your trusted backups.

Offline restore validates paths, sizes, checksums, SQLite integrity/schema and an
administrator account before changing state. It creates a private preimage under
`/etc/rahawrt/recovery/`, restores config/database/files, revokes all sessions and
API keys, then reloads services including uhttpd. Current owned kernel routes are
cleaned before replacing their database journal. HTTPS certificate/key files
outside managed VPN paths must be preserved separately. Exceptions trigger preimage rollback; the
preimage is retained even if rollback fails. Power loss still requires console
recovery from the preimage; offline restore is not a power-loss-atomic transaction.

Guest/reservation/tunnel provisioning uses a separate persistent three-minute
confirmation watchdog, automatic failure/timeout rollback and restart recovery.
Snapshots and confirmation secrets are never listed publicly and confirmed
snapshots are purged. A tiny crash window after exclusive file creation but before
recording cleanup can leave an orphan owned file; it is not blindly removed.

An independent procd watchdog checks a private monotonic heartbeat every five
seconds. Worker errors immediately attempt this guard; the independent watchdog covers
worker stalls. A stale/missing heartbeat (15 seconds) installs a separate guard for
managed MAC/IPs and the guest subnet. Enforcement uses the service database
`/etc/rahawrt/state.db`; an alternate unrelated CLI database is refused, so the
watchdog cannot accidentally read a different policy. The owned fw4 script include also installs
it on boot/reload. A successful worker tick removes it only after applying the
policy and reconciling routes, with DNS/portal/backend listeners already bound.
Local administration/portal and DHCP remain
reachable; ordinary router DNS is not exempted. Real host packet tests cover the
main policy being absent while the guard blocks traffic and subsequent recovery.
Actual boot ordering, offload/driver behavior and worst-case outage intervals
remain x86 acceptance tests; this is not a measured zero-gap hardware guarantee.

Policy updates use atomic nft replacement and temporary source guards while
PassWall2 ACLs restart. They preserve user nodes and compensate UCI on failures.
This is not a distributed transaction and is not a universal management-loss
watchdog. The console `sh scripts/router.sh rollback` stops policy enforcement,
removes RahaWRT's main/transition/boot tables, owned source/DNS routes, firewall
include/route grants, DNS helpers and ACLs, then restarts PassWall2. Pending UCI
edits must first be saved or reverted.
It returns to ordinary PassWall2 behavior, which may permit direct access. It does
not delete confirmed guest networks, optional tunnels or accounting data.

Before upgrade: back up, stop/revert enforcement, install a trusted signed native
package, validate preview, then explicitly reactivate. Schema changes currently
use additive table creation, not a production downgrade framework. After policy
rollback and reviewing confirmed native networks, remove with `opkg remove
rahawrt` or `apk del rahawrt`; retain the sensitive backup unless erasure is intended.

## Accounting and network boundaries

- Named nft token buckets enforce independent byte policers (drops), not fair-queue
  shaping. Device and shared account buckets apply together, and downloads share
  the same bucket across forwarded/local-proxy output paths. A 16-identity packet
  test verifies the aggregate bucket. Real router throughput remains unmeasured.
- Raw upload and forwarded/proxied download counters include IP bytes, exclude
  packets dropped before the counter and exempt IPv4 router management/DNS replies.
  Quotas/expiry close on a five-second policy tick; overshoot, burst allowance and
  scheduling delay are expected. Reports are not WAN link-wire billing counters.
- SQLite totals and generation checkpoints prevent double counting after daemon
  restart. Unexpected power loss can lose the last poll and replacement gap;
  duration excludes daemon downtime. UTC day/month buckets attribute each sampled
  delta to its poll date. Evaluate flash wear, external storage and retention.
- Guest DHCP discovery requires clients to use the trusted DHCP server. Known MAC
  rebinding revokes sessions; unregistered guests remain denied. Spoofing another
  valid MAC/IP is not prevented as Layer-2 NAC, and driver/switch isolation needs
  hardware checks. No dual-stack user accounting: managed/guest IPv6 is blocked.
- The forward guard cannot certify proxy-internal direct/shunt behavior, router
  DNS, boot/reload races, unrelated rule writers or the complete WAN path. VPN-only
  DNS transport, private SOCKS helpers and marked native DNS need real PassWall2
  acceptance despite the host transport tests. Unsupported strict paths fail closed.
