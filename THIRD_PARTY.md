# Third-party attribution

RahaWRT source is MIT licensed. It does not redistribute PassWall2/OpenWrt source,
Python, Chromium or VPN cores in its source payload. Their native packages retain
their own licenses, metadata and required notices. OpenWrt package dependencies
must come from trusted feeds; installing RahaWRT does not relicense them.

The optional adult-domain list is **HaGeZi DNS Blocklists**, published under
GPL-3.0: https://github.com/hagezi/dns-blocklists . The updater retrieves the
provider-documented `wildcard/nsfw-onlydomains.txt` plus its LICENSE over verified
HTTPS, and stores the full license, attribution, source URL, date and SHA-256
alongside cached data. It is not bundled into the repository/source artifact.
If redistributing a runtime cache or environment snapshot, preserve those license
and source records; inspect them with the administrator `parental/sources` API.
The upstream README also identifies source-data terms; using an upstream list is
not a certification that it perfectly classifies content.

Browser development tests use Playwright 1.64.1 (Apache-2.0) and installed Chromium
(with its bundled third-party notices). These are ignored local test dependencies,
not router runtime code. Their installed LICENSE/NOTICE files are retained.

Native package tests use OpenWrt's pinned `ipkg-build` and apk-tools 3.0.5
(GPL-2.0-only), retained with upstream license files under ignored `.local/`.
They are development build tools, excluded from router/source artifacts. The APK
utility comes from the exact upstream revision named by OpenWrt 25.12's recipe;
its crypto verification remains enabled. Integration tests generate temporary
fixture keys, never release keys, and delete them after each run.

The optional real-uhttpd host integration fixture builds exact official uhttpd,
libubox and ustream-ssl revisions from OpenWrt 24.10.8's recipes (ISC), using
CMake 3.31.10 (BSD-3-Clause), OpenSSL and json-c (MIT). Source/license notices and
signed Debian json-c package notices stay in the ignored development cache.
Those native fixture binaries are not included in RahaWRT router/source archives.
The uhttpd fixture disables optional Lua/ucode/ubus modules and tests real TLS/CGI;
it does not stand in for a firmware/netifd/PassWall2 acceptance test.
