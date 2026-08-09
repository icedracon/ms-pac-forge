# ms-pac-forge

[![Crates.io](https://img.shields.io/crates/v/ms-pac-forge.svg)](https://crates.io/crates/ms-pac-forge)
[![Docs.rs](https://docs.rs/ms-pac-forge/badge.svg)](https://docs.rs/ms-pac-forge)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Pure-Rust [MS-PAC](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/) marshaling and Golden / Silver Kerberos ticket forgery. For AD red-teamers and detection engineers who want a scriptable, embeddable ticket forge without shelling out to Rubeus or Impacket. Part of the [icedracon](https://github.com/icedracon) offensive-AD Rust ecosystem, extracted from `adhammer` 1.3.1.

## Status

**`0.1.0-dev`** — pre-alpha, expect breaking changes before `0.1.0`. Golden and Silver builders are byte-validated against a live Windows Server 2025 KDC PAC; Diamond and Sapphire modes are on the roadmap. No live KDC transport lives here — this crate emits raw `Ticket` / session-key / PAC bytes; wire them to your own AS/TGS layer or MIT ccache serializer.

## What it does

Builds a `KERB_VALIDATION_INFO` NDR buffer whose layout was diffed byte-for-byte against a live 2025 DC PAC, signs it (`SERVER_CHECKSUM` + `KDC_CHECKSUM`, AES256-HMAC-SHA1-96 via `picky-krb` or RC4-HMAC-MD5 via the hand-rolled `checksum` module), wraps it in an `EncTicketPart`, and seals it under the krbtgt key (Golden) or a service-account key (Silver). **KB5020805 posture is respected out-of-the-box** — both PAC signatures are emitted and `PAC_ATTRIBUTES` + `PAC_REQUESTOR` buffers are always present, so tickets survive DC-side signature enforcement that broke pre-2022 forgers.

## Usage

```rust,no_run
use ms_pac_forge::pac::ForgeIdentity;
use ms_pac_forge::forge::forge_golden_tgt;

let id = ForgeIdentity {
    user: "Administrator".into(),
    rid: 500,
    primary_gid: 513,
    group_rids: vec![513, 512, 520, 518, 519], // Domain Users + the big three
    domain_subauths: vec![21, 1111111111, 2222222222, 3333333333],
    logon_server: "DC01".into(),
    logon_domain: "CORP".into(),
};
let krbtgt_aes256 = [0x42u8; 32]; // from `dcsync krbtgt` or a lab dump
let tgt = forge_golden_tgt(&id, "CORP.LOCAL", &krbtgt_aes256, /*rc4=*/false)
    .expect("forge_golden_tgt");

// tgt.ticket_cipher() is the sealed EncTicketPart ready to drop into a KRB_CRED
// or ccache; tgt.session_key gets you the AP-REQ authenticator.
let _cipher = tgt.ticket_cipher();
```

`forge::forge_silver_tgt` takes the same shape with the service-account key instead of the krbtgt.

## What works / what does not (this version)

- ✅ Working: `KERB_VALIDATION_INFO` NDR build + parse (byte-verified vs live 2025 KDC), `PAC_CLIENT_INFO` / `PAC_ATTRIBUTES` / `PAC_REQUESTOR` / `SERVER_CHECKSUM` / `KDC_CHECKSUM` buffers, Golden TGT forge (krbtgt-sealed, AES256 or RC4), Silver TGS forge (service-account-sealed), RC4-HMAC (etype 23) + `KERB_CHECKSUM_HMAC_MD5` (-138) hand-rolls, KB5020805 extended-signatures posture.
- ⚠ Deferred: Diamond (TGS-REP tamper) and Sapphire (S4U2self-driven, KB5020805-native from the start — breaks the Rubeus-only monopoly on this technique) modes. Full PAC dissector for arbitrary buffers beyond `KERB_VALIDATION_INFO`. AS/TGS transport (see `ms-kile`).

## Related icedracon crates

- [`ms-nrpc`](https://github.com/icedracon/ms-nrpc) — Netlogon secure channel + read-only Zerologon cred probe; upstream source for machine-account credentials that seed Silver forges.
- [`credssp`](https://github.com/icedracon/credssp) — feed a forged ticket into `CredSspClient::with_kerberos_ticket` for RDP/WinRM NLA pass-through.
- [`ms-gkdi`](https://github.com/icedracon/ms-gkdi) — LAPS-v2 + gMSA + dMSA key derivation; recover the service-account key Silver forges seal under.

## License

MIT © 2026 [zevs](https://github.com/icedracon)
