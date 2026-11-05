# Architecture inventory

Checked: 2026-11-05. Scope: official package architectures in OpenWrt 25.12.6 and 24.10.8, not all historical releases.

Sources:
- https://downloads.openwrt.org/releases/25.12.6/packages/
- https://downloads.openwrt.org/releases/24.10.8/packages/
- https://downloads.openwrt.org/releases/25.12.6/targets/

## OpenWrt 25.12.6: 35 package architectures

- `aarch64_cortex-a53`
- `aarch64_cortex-a72`
- `aarch64_cortex-a76`
- `aarch64_generic`
- `arm_arm1176jzf-s_vfp`
- `arm_arm926ej-s`
- `arm_cortex-a15_neon-vfpv4`
- `arm_cortex-a5_vfpv4`
- `arm_cortex-a7`
- `arm_cortex-a7_neon-vfpv4`
- `arm_cortex-a7_vfpv4`
- `arm_cortex-a8_vfpv3`
- `arm_cortex-a9`
- `arm_cortex-a9_neon`
- `arm_cortex-a9_vfpv3-d16`
- `arm_fa526`
- `arm_xscale`
- `armeb_xscale`
- `i386_pentium-mmx`
- `i386_pentium4`
- `loongarch64_generic`
- `mips64_mips64r2`
- `mips64_octeonplus`
- `mips64el_mips64r2`
- `mips_24kc`
- `mips_mips32`
- `mipsel_24kc`
- `mipsel_24kc_24kf`
- `mipsel_74kc`
- `mipsel_mips32`
- `powerpc64_e5500`
- `powerpc_464fp`
- `powerpc_8548`
- `riscv64_generic`
- `x86_64`

## OpenWrt 24.10.8

36 architectures: the same list except replace `riscv64_generic` with `riscv64_riscv64` and add `mips_4kec`.

## Validation policy

Package architecture, target/subtarget and device model are distinct. SDK and kernel-module compatibility require exact target/release matching. The inventory does not assert availability of PassWall2 or every VPN core on every architecture.

Track separately: discovered, SDK build passed, emulator tested, hardware tested. The inherited inventory has not been independently refreshed. The 24.10.8 x86 SDK
leaf package is built/verified; its full prerequisite rebuild is blocked. No
emulator or hardware target has passed. x86 is the first physical target.

Use SDK cross-builds without owning every router. Emulators can cover selected CPUs and network paths but cannot validate device Wi-Fi drivers, switch offload, flash capacity or sustained hardware throughput. Keep unsupported features disabled with an explanation.

## One-command installation contract

`scripts/install.sh` detects OpenWrt release, package manager, package architecture, storage and existing dependencies. It selects only an explicitly supported release/architecture entry, verifies signed metadata, preserves existing settings and rejects missing prerequisites. It never flashes firmware or performs a distribution upgrade. Installation and activation are separate.

The documented local one-command installer requires an independently trusted key
and signed release manifest. Unsigned development IPK/APK archives are built,
but no signed production release or download installer URL is published.

## Reproducible refresh

The inventory above was present in the initial documentation. During initial
implementation, direct retrieval from the official index returned HTTP 403 under
the environment network policy, so these entries were **not independently
refreshed** and no architecture has been promoted to SDK-tested support.

`scripts/discover-architectures.py RELEASE` extracts architecture directories from
the exact official HTTPS package index with TLS verification enabled and emits
JSON with source URL and retrieval timestamp. It fails on denied/empty responses.
For example, after allowing `downloads.openwrt.org` in environment settings:

```sh
python3 scripts/discover-architectures.py 24.10.8
python3 scripts/discover-architectures.py 25.12.6
```

Review actual official releases/indexes before preparing a signed support
manifest. The source package declares architecture `all`, but this does not mean
that its dependencies, PassWall2 core or every optional VPN client are available
on every architecture. No hand-written manifest entries are treated as tested.
