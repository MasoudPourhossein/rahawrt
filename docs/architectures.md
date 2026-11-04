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

Track separately: discovered, SDK build passed, emulator tested, hardware tested. Currently every architecture is discovered only. x86 is the first planned hardware test; none has passed yet.

Use SDK cross-builds without owning every router. Emulators can cover selected CPUs and network paths but cannot validate device Wi-Fi drivers, switch offload, flash capacity or sustained hardware throughput. Keep unsupported features disabled with an explanation.

## One-command installation contract

A future versioned installer will detect OpenWrt release, package manager, package architecture, storage and existing dependencies. It must select only an explicitly supported release/architecture entry, verify signed package metadata, preserve existing settings and fail on missing dependencies. It must not automatically flash firmware or perform a distribution upgrade. Installation and later activation must remain separate, with rollback for network changes.

No install command is published yet because no tested release artifact exists. Do not pipe a placeholder URL into a root shell.
