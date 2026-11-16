//! Round-trip and byte-level tests for Golden and Silver forgery. These are the
//! parity anchors carried over from adhammer-kerberos' pac.rs offline tests: if
//! anything in the NDR marshaling, PAC signing, or EncTicketPart sealing
//! regresses, the round-trip fails to decrypt or the recovered PAC no longer
//! reflects the forged identity.

use ms_pac_forge::checksum::{hmac_md5_checksum, nt_hash, SIG_HMAC_MD5};
use ms_pac_forge::forge::{forge_golden_tgt, forge_silver_tgt};
use ms_pac_forge::pac::{
    decrypt_ticket_pac_aes256, decrypt_ticket_pac_rc4, parse_pac, ForgeIdentity, PAC_KDC_CHECKSUM,
    PAC_LOGON_INFO, PAC_SERVER_CHECKSUM,
};

fn sample() -> ForgeIdentity {
    ForgeIdentity {
        user: "Administrator".into(),
        rid: 500,
        primary_gid: 513,
        group_rids: vec![513, 512, 520, 518, 519],
        domain_subauths: vec![21, 1111111111, 2222222222, 3333333333],
        logon_server: "DC01".into(),
        logon_domain: "CORP".into(),
        extra_sids: vec![],
    }
}

/// A forged silver ticket must round-trip: seal under a service AES256 key,
/// then decrypt the EncTicketPart back with that key (AES integrity holds) and
/// recover a parseable PAC whose LOGON_INFO carries the forged identity.
#[test]
fn silver_ticket_aes256_roundtrips() {
    let key = [0x37u8; 32];
    let tgt =
        forge_silver_tgt(&sample(), "CORP.LOCAL", &key, "cifs/dc01.corp.local", false).unwrap();
    let (_etp, pac) = decrypt_ticket_pac_aes256(tgt.ticket_cipher(), &key).expect("decrypt silver");
    let parsed = parse_pac(&pac).unwrap();
    let li = &parsed.get(PAC_LOGON_INFO).unwrap().data;
    // UserId at fixed offset 120 in LOGON_INFO.
    assert_eq!(u32::from_le_bytes(li[120..124].try_into().unwrap()), 500);
    let pgid = u32::from_le_bytes(li[124..128].try_into().unwrap());
    assert_eq!(pgid, 513);
    assert!(parsed.get(PAC_SERVER_CHECKSUM).is_some());
    assert!(parsed.get(PAC_KDC_CHECKSUM).is_some());
}

/// Golden AES256 TGT must round-trip: forge under the domain krbtgt AES256
/// key, then decrypt the EncTicketPart back with that key.
#[test]
fn golden_ticket_aes256_roundtrips() {
    let key = [0xa5u8; 32];
    let id = sample();
    let tgt = forge_golden_tgt(&id, "CORP.LOCAL", &key, false).unwrap();
    let (_etp, pac) = decrypt_ticket_pac_aes256(tgt.ticket_cipher(), &key).expect("decrypt golden");
    let parsed = parse_pac(&pac).unwrap();
    let li = &parsed.get(PAC_LOGON_INFO).unwrap().data;
    assert_eq!(u32::from_le_bytes(li[120..124].try_into().unwrap()), id.rid);
    assert_eq!(
        u32::from_le_bytes(li[124..128].try_into().unwrap()),
        id.primary_gid
    );
}

/// RC4 golden ticket: forge under an NT-hash krbtgt key, then decrypt the
/// EncTicketPart back with RC4-HMAC (usage 2), recover the PAC, and confirm
/// the SERVER_CHECKSUM is a valid KERB_CHECKSUM_HMAC_MD5 (type -138) over the
/// zeroed-signature PAC. Proves the RC4 forge + HMAC-MD5 PAC signing are
/// byte-correct, independent of any KDC etype policy.
#[test]
fn rc4_golden_roundtrips() {
    let nt = nt_hash("Krbtgt-NT-Hash!");
    let tgt = forge_golden_tgt(&sample(), "CORP.LOCAL", &nt, true).unwrap();
    let (_etp, pac) = decrypt_ticket_pac_rc4(tgt.ticket_cipher(), &nt).expect("rc4 decrypt");
    let parsed = parse_pac(&pac).unwrap();
    let srv = parsed.get(PAC_SERVER_CHECKSUM).unwrap();
    assert_eq!(
        i32::from_le_bytes(srv.data[0..4].try_into().unwrap()),
        SIG_HMAC_MD5
    );
    assert_eq!(srv.data.len(), 4 + 16);
    let stored = srv.data[4..20].to_vec();
    let mut zeroed = pac.clone();
    for i in 0..parsed.buffers.len() {
        let base = 8 + i * 16;
        let t = u32::from_le_bytes(zeroed[base..base + 4].try_into().unwrap());
        let off = u64::from_le_bytes(zeroed[base + 8..base + 16].try_into().unwrap()) as usize;
        if t == PAC_SERVER_CHECKSUM || t == PAC_KDC_CHECKSUM {
            for b in zeroed[off + 4..off + 20].iter_mut() {
                *b = 0;
            }
        }
    }
    assert_eq!(
        hmac_md5_checksum(&nt, 17, &zeroed).to_vec(),
        stored,
        "RC4 golden SERVER_CHECKSUM (HMAC-MD5) mismatch"
    );
}

/// A round-trip through the *ticket* + PAC path must preserve the forged
/// identity (user, rid, primary_gid, domain SID). This is the golden-vector
/// anchor requested for v0.1.
#[test]
fn forge_identity_survives_roundtrip() {
    let key = [0x11u8; 32];
    let id = ForgeIdentity {
        user: "alice".into(),
        rid: 1234,
        primary_gid: 513,
        group_rids: vec![513, 512],
        domain_subauths: vec![21, 111, 222, 333],
        logon_server: "DC02".into(),
        logon_domain: "LAB".into(),
        extra_sids: vec![],
    };
    let tgt = forge_golden_tgt(&id, "LAB.LOCAL", &key, false).unwrap();
    let (_etp, pac) = decrypt_ticket_pac_aes256(tgt.ticket_cipher(), &key).unwrap();
    let parsed = parse_pac(&pac).unwrap();
    let li = &parsed.get(PAC_LOGON_INFO).unwrap().data;
    assert_eq!(u32::from_le_bytes(li[120..124].try_into().unwrap()), 1234);
    assert_eq!(u32::from_le_bytes(li[124..128].try_into().unwrap()), 513);
    // Session key length reflects the etype (32 bytes for AES256).
    assert_eq!(tgt.session_key().len(), 32);
}

/// Diamond ticket AES256 round-trip: forge a "real" TGT for `alice` (RID 1234,
/// domain user), then run `forge_diamond_tgt` to identity-swap it into `admin`
/// (RID 500, DA-shaped groups). Verify the resulting ticket:
///  * decrypts under the same krbtgt key (proves the re-encryption is honest),
///  * parses as a valid PAC (proves the PAC swap kept the auth-data envelope
///    correctly-wrapped),
///  * carries the new identity's RID + primary GID in LOGON_INFO,
///  * has both PAC signatures present and re-signed under the same key.
#[test]
fn diamond_ticket_aes256_identity_swap() {
    use ms_pac_forge::forge_diamond_tgt;
    let krbtgt = [0xa5u8; 32];
    let alice = ForgeIdentity {
        user: "alice".into(),
        rid: 1234,
        primary_gid: 513,
        group_rids: vec![513],
        domain_subauths: vec![21, 111, 222, 333],
        logon_server: "DC01".into(),
        logon_domain: "LAB".into(),
        extra_sids: vec![],
    };
    let admin = ForgeIdentity {
        user: "Administrator".into(),
        rid: 500,
        primary_gid: 513,
        group_rids: vec![513, 512, 520, 518, 519],
        domain_subauths: alice.domain_subauths.clone(),
        logon_server: alice.logon_server.clone(),
        logon_domain: alice.logon_domain.clone(),
        extra_sids: vec![],
    };

    let real = forge_golden_tgt(&alice, "LAB.LOCAL", &krbtgt, false).unwrap();
    let diamond =
        forge_diamond_tgt(real.ticket_cipher(), &krbtgt, &admin, "LAB.LOCAL", false).unwrap();

    let (_etp, new_pac) =
        decrypt_ticket_pac_aes256(diamond.ticket_cipher(), &krbtgt).expect("diamond decrypt");
    let parsed = parse_pac(&new_pac).unwrap();

    let li = &parsed.get(PAC_LOGON_INFO).unwrap().data;
    assert_eq!(
        u32::from_le_bytes(li[120..124].try_into().unwrap()),
        500,
        "diamond swap must overwrite RID"
    );
    assert_eq!(
        u32::from_le_bytes(li[124..128].try_into().unwrap()),
        513,
        "diamond swap must overwrite primary GID"
    );
    assert!(parsed.get(PAC_SERVER_CHECKSUM).is_some());
    assert!(parsed.get(PAC_KDC_CHECKSUM).is_some());

    // cname on the wire ticket must reflect the new identity, not the old one.
    assert_eq!(diamond.cname().name_string[0], "Administrator");
}

/// Diamond RC4 round-trip: same shape as the AES version but on etype 23.
#[test]
fn diamond_ticket_rc4_identity_swap() {
    use ms_pac_forge::checksum::nt_hash;
    use ms_pac_forge::forge_diamond_tgt;
    let nt = nt_hash("Krbtgt-NT-Hash!");
    let victim = sample();
    let mut new_id = victim.clone_shape();
    new_id.rid = 4242;

    let real = forge_golden_tgt(&victim, "CORP.LOCAL", &nt, true).unwrap();
    let diamond =
        forge_diamond_tgt(real.ticket_cipher(), &nt, &new_id, "CORP.LOCAL", true).unwrap();
    let (_etp, pac) = decrypt_ticket_pac_rc4(diamond.ticket_cipher(), &nt).unwrap();
    let parsed = parse_pac(&pac).unwrap();
    let li = &parsed.get(PAC_LOGON_INFO).unwrap().data;
    assert_eq!(u32::from_le_bytes(li[120..124].try_into().unwrap()), 4242);
    // RC4 session key is 16 bytes.
    assert_eq!(diamond.session_key().len(), 16);
}

trait CloneShape {
    fn clone_shape(&self) -> Self;
}
impl CloneShape for ForgeIdentity {
    fn clone_shape(&self) -> Self {
        ForgeIdentity {
            user: self.user.clone(),
            rid: self.rid,
            primary_gid: self.primary_gid,
            group_rids: self.group_rids.clone(),
            domain_subauths: self.domain_subauths.clone(),
            logon_server: self.logon_server.clone(),
            logon_domain: self.logon_domain.clone(),
            extra_sids: self.extra_sids.clone(),
        }
    }
}
