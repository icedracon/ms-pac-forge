# Changelog

All notable changes to `ms-pac-forge` will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
project adheres to [SemVer](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Notes
- Typed `PacForgeError` enum planned for the next feature bump (0.2.0);
  today the crate uses `anyhow::Result` for CLI-friendliness.

## [0.1.3] — 2026-08-23

### Added
- `ForgeIdentity.extra_sids: Vec<Vec<u32>>` — populates PAC's
  `KERB_VALIDATION_INFO.SidCount` + `ExtraSids` (KERB_SID_AND_ATTRIBUTES
  conformant array, MS-PAC 2.5) for cross-forest golden-ticket forging.
  Empty vec = same on-wire layout as 0.1.2 (backwards-compat, verified
  byte-for-byte in `extra_sids_empty_matches_previous_layout`).
- `impl Default for ForgeIdentity` (unblocks `..Default::default()` at
  call sites).

## [0.1.2] — 2026-08-16

### Fixed
- **`parse_pac` bounded-alloc preflight** — attacker-controlled
  `c_buffers` `u32` is now capped at `(pac.len() - 8) / 16` before the
  `Vec::with_capacity`. Closes an OOM from a hostile-server-returned PAC.

## [0.1.1] — 2026-08-14

### Added
- **Diamond ticket** — `forge_diamond_tgt`: identity swap on a real
  TGT envelope, preserving flags / times / session key. Bypasses PAC-
  signature detections that only compare against forged-from-scratch
  golden shape.
- **Sapphire primitives** — building blocks for the S4U2Self-based
  identity-forge flow:
  - `build_pa_for_user` (PA-FOR-USER envelope construction).
  - `extract_pac_from_enc_ticket_part`.
  - `forge_sapphire_service_ticket`.
  - `pac::re_sign_pac` (re-sign an existing PAC with a new key).

## [0.1.0] — 2026-08-13

Initial stable release. Extracted from `adhammer/crates/kerberos/pac.rs`.

### Added
- Full PAC marshal / parse (`KERB_VALIDATION_INFO` TypeSer-v1 NDR).
- Server + KDC signature construction: AES (RFC 8009 AES-SHA2 etypes
  17/18/19/20) + RC4 `KERB_CHECKSUM_HMAC_MD5`.
- `PAC_REQUESTOR` / `PAC_ATTRIBUTES` buffers required by KB5020805
  (November 2022 Windows Server hardening).
- Golden / silver ticket byte-exact round-trip test vectors.
- **Live-validated against Windows Server 2025 KDC** — forged
  Domain-Admin TGT is accepted, TGS-REQ issued, service ticket
  obtained, cifs/DC01 access as SYSTEM proven end-to-end.

## [0.1.0-dev] — 2026-08-09 [pre-release]

Pre-release dev build for early integration testing. Superseded by
0.1.0.
