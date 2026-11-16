//! RC4-HMAC (etype 23, RFC 4757 / MS-KILE) primitives used by RC4 golden/silver
//! ticket forging. picky-krb does not ship this cipher — it's a legacy MS-KILE
//! algorithm whose string-to-key is simply the NT hash, which is what makes
//! **overpass-the-hash** possible. Lifted from adhammer-kerberos' rc4.rs.

use hmac::{Hmac, Mac};
use md4::Md4;
use md5::{Digest, Md5};

type HmacMd5 = Hmac<Md5>;

/// RC4-HMAC string-to-key: the NT hash, `MD4(UTF-16LE(password))`.
pub fn nt_hash(password: &str) -> [u8; 16] {
    let mut md4 = Md4::new();
    for u in password.encode_utf16() {
        md4.update(u.to_le_bytes());
    }
    md4.finalize().into()
}

fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut m = <HmacMd5 as Mac>::new_from_slice(key).expect("hmac key");
    m.update(data);
    m.finalize().into_bytes().into()
}

/// Hand-rolled RC4 keystream (RFC 6229); keys here are always the 16-byte HMAC-MD5 output.
fn rc4_apply(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut s: [u8; 256] = std::array::from_fn(|i| i as u8);
    let mut j = 0usize;
    for i in 0..256 {
        j = (j + s[i] as usize + key[i % key.len()] as usize) & 0xff;
        s.swap(i, j);
    }
    let (mut i, mut j) = (0usize, 0usize);
    data.iter()
        .map(|&b| {
            i = (i + 1) & 0xff;
            j = (j + s[i] as usize) & 0xff;
            s.swap(i, j);
            b ^ s[(s[i] as usize + s[j] as usize) & 0xff]
        })
        .collect()
}

/// MS-KILE key-usage remapping for RC4-HMAC (RFC 4757 §3): a few usages are aliased.
fn usage_t(usage: i32) -> [u8; 4] {
    let ms = match usage {
        3 => 8,   // AS-REP enc-part
        9 => 8,   // TGS-REP enc-part (subkey)
        23 => 13, // (per RFC 4757)
        u => u,
    };
    (ms as u32).to_le_bytes()
}

/// RC4-HMAC encrypt. `confounder` is 8 bytes (pass `None` for random).
pub fn rc4_encrypt(
    key: &[u8],
    usage: i32,
    plaintext: &[u8],
    confounder: Option<[u8; 8]>,
) -> Vec<u8> {
    let conf = confounder.unwrap_or_else(|| {
        let mut c = [0u8; 8];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut c);
        c
    });
    let ki = hmac_md5(key, &usage_t(usage));
    let mut data = conf.to_vec();
    data.extend_from_slice(plaintext);
    let cksum = hmac_md5(&ki, &data);
    let ke = hmac_md5(&ki, &cksum);
    let mut out = cksum.to_vec();
    out.extend_from_slice(&rc4_apply(&ke, &data));
    out
}

/// RC4-HMAC decrypt. Verifies the HMAC checksum in constant time (1.5.3 audit M-1 — kerbcore's
/// own rc4::decrypt uses CT compare, this brings ms-pac-forge to parity), then returns the
/// plaintext (confounder stripped).
pub fn rc4_decrypt(key: &[u8], usage: i32, ciphertext: &[u8]) -> Result<Vec<u8>, &'static str> {
    if ciphertext.len() < 16 + 8 {
        return Err("RC4-HMAC ciphertext too short");
    }
    let (cksum, enc) = ciphertext.split_at(16);
    let ki = hmac_md5(key, &usage_t(usage));
    let ke = hmac_md5(&ki, cksum);
    let data = rc4_apply(&ke, enc);
    let expected = hmac_md5(&ki, &data);
    if !ct_eq_16(&expected, cksum) {
        return Err("RC4-HMAC checksum mismatch (wrong key)");
    }
    Ok(data[8..].to_vec())
}

/// Constant-time equality for a fixed 16-byte HMAC-MD5 tag. Volatile-black-box read of the OR
/// accumulator so the optimiser can't short-circuit the loop; both slices are always fully
/// traversed regardless of where they first differ (mirrors `subtle::ConstantTimeEq` on `[u8;16]`).
#[inline(always)]
fn ct_eq_16(a: &[u8], b: &[u8]) -> bool {
    debug_assert_eq!(a.len(), 16);
    debug_assert_eq!(b.len(), 16);
    let mut acc: u8 = 0;
    for i in 0..16 {
        // `read_volatile` around the accumulator prevents the optimiser from breaking
        // constant-time by observing `acc != 0` and exiting early.
        acc |= a[i] ^ b[i];
        acc = std::hint::black_box(acc);
    }
    acc == 0
}

/// KERB_CHECKSUM_HMAC_MD5 (checksum type -138, RFC 4757 §4) — the PAC signature
/// algorithm that pairs with an RC4 key.
pub fn hmac_md5_checksum(key: &[u8], usage: i32, data: &[u8]) -> [u8; 16] {
    let ksign = hmac_md5(key, b"signaturekey\0");
    let mut md5 = Md5::new();
    md5.update(usage.to_le_bytes());
    md5.update(data);
    let tmp = md5.finalize();
    hmac_md5(&ksign, &tmp)
}

/// SignatureType for the PAC checksum buffers when signing with an RC4 key.
pub const SIG_HMAC_MD5: i32 = -138;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nt_hash_known_vector() {
        assert_eq!(
            hex::encode(nt_hash("password")),
            "8846f7eaee8fb117ad06bdd830b7586c"
        );
    }

    #[test]
    fn rc4_roundtrip() {
        let k = nt_hash("Passw0rd!");
        let pt = b"the quick brown fox";
        let ct = rc4_encrypt(&k, 2, pt, None);
        assert_eq!(rc4_decrypt(&k, 2, &ct).unwrap(), pt);
    }

    #[test]
    fn hmac_md5_checksum_deterministic() {
        let k = nt_hash("k");
        assert_eq!(
            hmac_md5_checksum(&k, 17, b"data"),
            hmac_md5_checksum(&k, 17, b"data")
        );
        assert_ne!(
            hmac_md5_checksum(&k, 17, b"data"),
            hmac_md5_checksum(&k, 17, b"datb")
        );
    }
}
