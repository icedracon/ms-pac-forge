# Changelog

All notable changes to `ms-pac-forge` will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
project adheres to [SemVer](https://semver.org/spec/v2.0.0.html).

## [0.2.0] — 2026-10-29

### Added
- **Diamond ticket forgery (`diamond` module).** `forge_diamond_tgt` decrypts a
  real TGT with the krbtgt key, preserves its flags / session key / timestamps,
  and swaps only the identity-carrying PAC + cname. `build_diamond_ticket` exposes
  the rebuild step for callers that already hold a decrypted `EncTicketPart`.
- **Sapphire / S4U2Self primitives (`sapphire` module).** `build_pa_for_user`
  (PA-FOR-USER padata, type 129; HMAC-MD5 checksum at key usage 17 over an RC4 TGT
  session key), `extract_pac_from_enc_ticket_part`, and
  `forge_sapphire_service_ticket` (mint a service ticket around a KDC-populated
  PAC, both signatures re-signed under the service key). No KDC transport — the
  S4U2Self wire exchange lives in adhammer-kerberos.
- `pac::re_sign_pac` is now public (used by the Sapphire path).
- Constant-time RC4-HMAC checksum compare in `checksum::rc4_decrypt` (audit M-1).
- `#![forbid(unsafe_code)]` crate-wide (audit M-3).

### Changed
- **Crypto + DER backend swapped `picky-krb` → `kerbcore` 0.3.** EncTicketPart
  build/parse and AES256-CTS-HMAC-SHA1-96 now go through kerbcore's from-scratch,
  no-panic DER + RFC 3961 crypto; RC4-HMAC stays on the crate's own `checksum`.
  Key usages (2 for the sealed ticket, 17 for PAC checksums) and the on-wire DER
  layout are unchanged from the picky-validated version. Dropped dependencies:
  `picky-krb`, `picky-asn1`, `picky-asn1-der`, `anyhow`.
- **BREAKING — typed errors.** Every public function now returns
  `Result<T, PacForgeError>` (a `thiserror` enum) instead of `anyhow::Result<T>`.
  Callers can match specific modes: `Decode`, `Encode`, `Decrypt`, `Encrypt`,
  `Signature`, `MissingBuffer(u32)`, `Truncated`, `NoAuthData`,
  `InvalidVersion(u32)`, `InvalidIdentity`. `PacForgeError` implements
  `std::error::Error`, so existing `?`-into-`anyhow` call sites keep compiling.
  `checksum::rc4_decrypt` keeps its `Result<_, &'static str>` signature.
- `PacForgeError` is `#[non_exhaustive]` — future variants are additive (patch), not breaking.
- MSRV raised to **1.88** (was an inaccurate `1.80`, then `1.85`). picky-krb is
  gone; the floor is now set by the `kerbcore` 0.3 dependency (rust-version 1.88).

### Validation
- Crypto-backend: the picky→kerbcore swap preserves the key usages and on-wire DER,
  and kerbcore's RFC 3961/3962 primitives are known-answer-tested. Against a live
  Windows Server 2025 DC: AES256 **golden** TGT accepted (TGS-REP for krbtgt); AES256
  **silver** ticket authenticated over SMB (Kerberos AP-REQ → `C$` tree-connect);
  **golden + ExtraSids** (foreign-SID injection) accepted (TGS-REP for ldap/); **diamond**
  crypto confirmed (DC decrypted the ticket; policy-rejected with KDC_ERR_TGT_REVOKED
  from KB5020805 PAC-consistency checks — a technique limitation, not a crypto bug).
  Together these exercise both PAC signatures (KDC + server), the ExtraSids NDR path,
  and multiple SPNs. RC4 is rejected by this DC's etype policy and rests on unit + KAT
  coverage; Sapphire remains in-crate-test-only. `cargo publish --dry-run` verified
  against the registry `kerbcore = "0.3"` (89 KiB, 16 files, clean verify-build).
  Crate stays pre-alpha.

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
