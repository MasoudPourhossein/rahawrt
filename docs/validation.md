# Validation ledger — 2026-11-05

These levels are separate; no SDK or physical compatibility badge is implied.

| Level | Result | Evidence and limit |
| --- | --- | --- |
| Host unit/HTTP/CGI/DNS/SQLite tests | 101 passed | `make test`; daemon startup, RBAC/HTTPS, concurrent invoices, lifecycle, quota/expiry, safe import, DNS UDP/TCP, backup/rollback and mocked OpenWrt commands |
| Syntax | passed | Python including CGI/scripts, browser JavaScript and POSIX shell parsing |
| Real Chromium UI | passed | RTL/LTR, login, plan creation, issuance/retry, secret clearing, operator restrictions and mobile viewport |
| End-to-end guest lifecycle | passed | Separate guest/WAN namespaces, real policy DNS UDP/TCP and HTTP NAT, verified uhttpd TLS/CGI login, routed WAN gate and SQLite usage, logout closure with portal retained; DHCP/router/upstream-DNS fixtures and direct-node policy |
| Real host-built uhttpd HTTPS/CGI | passed | Exact OpenWrt recipe revisions; trusted fixture TLS and untrusted-cert rejection, cookies, actual status codes, CGI header/query forwarding, guest/source/key isolation and separate docroots; router adapters are fixtures |
| Native Linux nft installation | passed | Isolated user/network namespace; named limits, atomic replacement, DNS and guest bootstrap rules |
| Native Linux routed packets | passed | veth topology, direct baseline, accounting, quota/login/MAC/CIDR/unknown-guest denial, VPN forward guard, DNS capture, DoT restriction, two simultaneous native source routes, interface-down closure and explicit independent fallback |
| Independent direction caps | passed in host packet test | 1/32 packets through each configured test policer versus 32/32 baseline; not a hardware Mbps benchmark |
| Shared account cap | passed in host packet test | 1/16 packets across 16 identities under one account budget |
| Live adult-list refresh | passed | 91,928 entries, provider-documented HTTPS URL, GPL license/attribution retained; not content-classification certification |
| Source archive | passed/reproducible | `make build`; tests included, cached tools/data excluded |
| Native IPK/APK archives | passed | Architecture-all/noarch archives; official IPK payload comparison; APK unsigned rejection, fixture trusted signature, extraction and tamper rejection; no production signing |
| OpenWrt 24.10.8 x86 SDK leaf package | passed and payload verified | Official pinned SDK; package-discovery/architecture defects corrected; complete metadata, bytes, modes, root ownership and private state checked |
| Full SDK dependency rebuild | blocked/failed | Real root SDK target tried; ncurses 6.4 source endpoints returned policy HTTP 403. Expat built, but this is not a successful complete dependency build |
| Real OpenWrt UCI userspace | passed | Official 24.10.8 x86_64 rootfs, network disabled/all capabilities dropped; missing-PassWall installer rejection, guest/DHCP/firewall/uhttpd serialization, exact rollback and pending-edit preservation |
| Concrete-node SOCKS DNS | passed with test peers | Distinct real SOCKS TCP peers, helper ownership checks, strict failure/direct-fallback policy; actual Xray/sing-box not run |
| Native marked DNS | passed with test peer | Separate network namespace, real route/interface binding, DNS framing, down-path closure and independent direct/WAN resolution; mapped test GID stands in for actual PassWall2 GID 9912 |
| Captive TCP and independent boot guard | passed with real host packets | TCP redirect, cached-flow denial, authorized HTTP and actual pre-login portal DNS replies before reverse NAT; Internet denied while main table absent, then recovered |
| Other SDK architectures | not run | x86 leaf result does not certify other toolchains or dependency availability |
| OpenWrt emulator | not run | No firmware image booted |
| OpenWrt-target netifd/procd/PassWall2 daemons | not run | Real UCI and host uhttpd CGI pass; firmware daemon/kernel/core interaction still needs router acceptance |
| Native VPN handshake/egress | not run | No peer credentials/server/device attached; L2TP requires pre-existing IPsec |
| x86 physical router | not run | First hardware target; no connected router |
| Other hardware architectures | not run | Inventory and `all` payload do not certify support |

The packet test's “tunnel down” case means no transparent proxy intercepts the
packet, so the forward guard must drop it. It does **not** establish behavior of
an actual failed PassWall2 core, shunt rules, DNS routing or real tunnel restart.
The current host kernel also rejects the connlimit expression with missing kernel
support. Hard TCP/UDP flow-count caps are not shipped; login-session caps are.
CI files declare checks but no remote CI run is claimed.

## Required x86 acceptance

Record release, target/subtarget, package architecture, PassWall2/core versions,
firmware/SDK hashes, RAM/storage, offload state, topology, exact commands/results,
packet captures and timestamps. Do not record passwords, private keys or raw tokens.

1. Rebuild the package and prerequisites with exact SDK/feeds. The existing x86
   leaf build is not a complete prerequisite rebuild or install test. Verify install rejects
   missing PassWall2, unsupported signed support entry, bad signatures/checksums,
   missing dependencies and insufficient storage. Verify install remains inactive.
2. Test procd/uhttpd HTTPS, trusted certificates, CGI, all roles, HTTP rejection,
   source binding, brute-force limits, API-key scopes/revocation and logout gates.
3. Select distinct PassWall2 nodes for two clients simultaneously. Record real
   observed egress, direct/global modes, schedule changes and unchanged user nodes.
   Verify IPv6/DNS/direct bypass while killing the real proxy with WAN captures.
4. Measure both directions, direct/proxied/mixed paths, simultaneous account
   devices, burst behavior and offload rejection. Cross quotas/expiry/duration;
   test established flows, throttle plans and access to the account page afterward.
5. Test midnight/week boundaries, configured timezone and clock corrections.
   Reboot under traffic and quantify lost usage/boot gaps; reload firewall while
   verifying fail-closed behavior and counter continuity. These remain release gates.
6. Provision a non-overlapping guest Wi-Fi/bridge. Verify management/guest and
   guest/guest isolation in the actual Wi-Fi/switch driver, DHCP enrollment,
   trusted-certificate DHCP 114 discovery, login/voucher/logout and expiry. Confirm
   legacy HTTP probes reach the HTTPS 8443 portal, while guest clients cannot
   reach LuCI/other CGI or authenticate with a privileged account. Validate the
   manual-login fallback and existing-connection handling on the router.
7. Test DNS via UDP/TCP and SafeSearch on the actual clients, encrypted-DNS bypass
   attempts, list refresh failures and IPv6 behavior. VPN-only parental upstream
   DNS must be captured on WAN to verify the selected concrete node/private helper
   or marked native worker; unsupported strict paths must fail closed.
8. Provision optional VPNs with real packages/certificates/peers. Verify no default
   route takeover, no competing PassWall2 rules, private credential files,
   reconnect/up/down and L2TP's no-plaintext behavior after IPsec failure/reboot.
   Per-device source routes are implemented and host-packet-tested; verify their
   actual peer egress and real PassWall2 coexistence.
9. Disconnect management during a pending guest/reservation/tunnel change. Verify
   timeout rollback, restart recovery, failed UCI/service handling and inability to
   confirm expired tokens. Also test the separate console policy rollback path.
10. Restore a trusted backup offline, force failure and validate preimage recovery.
    Verify session/key revocation, full storage, power-loss recovery, upgrade and
    removal. Measure CPU/RAM/flash wear and decide supported device resource bounds.

## Remaining work before a production release

Full SDK dependency/signing/support matrix; emulator and physical validation;
actual boot/firewall-reload continuity and PassWall2/core same-node DNS
integration; complete IKE/IPsec
provisioning rather than using an existing SA; end-to-end tunnel-health monitoring
and automatic failover/reconnect policy; hard TCP/UDP flow caps; production schema
migrations/downgrade and retention controls. No MikroTik feature-parity claim.

## Reproduction and SDK scope

`sh scripts/test-sdk.sh leaf` uses official image
`openwrt/sdk@sha256:b28d5e4087dbd3f815a8bf5440a11e54e6bbd3d7400c3729d872e7940a4a77c1`.
The leaf SDK IPK was verified with `scripts/verify-sdk-package.py`;
the build output and logs live under ignored `.local/sdk-24.10.8*/`.
The default `sh scripts/test-sdk.sh full` rebuilds prerequisites and keeps failures
visible. The fresh helper is validated separately from the original container run.
Host-tool initialization must precede the leaf PATH override; SDK host sed and
umask 022 are required to avoid invalid control-file modes in this image.

`python3 scripts/test-openwrt-userspace.py` uses official rootfs image
`openwrt/rootfs@sha256:9972a4b4747cd136abd597475d7b88c51a49fd849d0d53f069a2f4bf446061b9`.
It never starts network daemons, changes host interfaces or downloads packages
inside that container. This is a native userspace test, not an emulated router.

`sh scripts/uhttpd-setup.sh && python3 scripts/test-uhttpd.py` builds host-only
uhttpd, libubox and the OpenSSL ustream provider from the exact 24.10.8 recipe
commits. The test found and corrected two real integration defects: uhttpd's CGI
header allowlist discarded the original custom request marker, and reason-less
CGI Status headers made errors appear as HTTP 200. The test uses real source IPs
inside a disposable namespace and real certificate validation; TLS verification
is never bypassed. Optional Lua/ucode/ubus fixture modules are not built; upstream
source confirms ubus is initialized only with an explicit prefix, omitted by the
guest instance. Actual firmware/service integration remains separate.

The exact saved onboarding script completed successfully in this cloud instance:
local tool refresh, 99 tests at that run, kernel/packet/native-DNS checks, real host uhttpd,
Chromium, OpenWrt UCI userspace, native package verification, fresh SDK leaf build
and source/IPK/APK build. Configuration is saved for review; runtime network
changes/publication and a new-task restore have not been established by that save.
The final additional packet regression reproduced a pre-login DNS reply being
dropped at OUTPUT before reverse NAT changed source port 1053 back to 53; the
policy now preserves these local control replies without opening upstream DNS.

A further PID-reuse regression verifies private DNS helper cleanup rechecks the
owned config argument after opening the pidfd, before sending a signal; an
unrelated replacement process is never signaled. The current suite has 101 tests.

`python3 scripts/test-portal-flow.py` verifies the complete guest lifecycle over
real veth/TCP/UDP paths. Known OS HTTP-probe hostnames resolve locally to the guest
gateway with zero TTL while closed; ordinary upstream DNS remains refused.
Authentication restores normal probe resolution and WAN traffic; logout closes
WAN again while local portal DNS/HTTPS still works. Fixture upstream DNS and
router/DHCP data are explicit; this is not a PassWall2 or firmware acceptance test.

## Current handoff status

See `PROGRESS.md`. The latest complete workflow rerun was not executed because
automatic approval review was unavailable at its usage limit, not because the
action was deemed unsafe. The final guest-discovery changes were independently
tested (101 tests and the end-to-end guest flow), but the recorded SDK package is
an earlier payload. Its evidence explicitly marks the current-source mismatch;
no final-source SDK success or production release is claimed.
