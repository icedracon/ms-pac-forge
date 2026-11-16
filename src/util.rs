//! Small helpers shared by [`pac`] / [`forge`] / [`diamond`] / [`sapphire`]: Kerberos
//! generalized-time strings + `PrincipalName` builders. 1.5.3: kerbcore types (was picky-krb).

pub const ETYPE_RC4_HMAC: u8 = 23;
pub const ETYPE_AES256: u8 = 18;

/// NT-PRINCIPAL name type (user principals).
pub const NT_PRINCIPAL: i32 = 1;
/// NT-SRV-INST name type (service principals, e.g. `krbtgt/REALM`, `cifs/host`).
pub const NT_SRV_INST: i32 = 2;

/// Far-future ticket expiry (`till`) as a Kerberos generalized-time string (2037-09-13 02:48:05Z).
/// Must be after the start time or the KDC rejects with KDC_ERR_NEVER_VALID.
pub const FAR_FUTURE: &str = "20370913024805Z";

/// A kerbcore [`kerbcore::types::PrincipalName`] from a name-type + component parts.
pub fn principal(name_type: i32, parts: &[&str]) -> kerbcore::types::PrincipalName {
    kerbcore::types::PrincipalName {
        name_type,
        name_string: parts.iter().map(|p| (*p).to_string()).collect(),
    }
}

/// Current UTC as a Kerberos generalized-time string (`YYYYMMDDHHMMSSZ`, second granularity).
pub fn now_kerberos_time() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    kerbcore::client::unix_to_kerberos_time(secs)
}
