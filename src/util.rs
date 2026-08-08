//! Small helpers shared by [`pac`] and [`forge`]: Kerberos time construction
//! and `PrincipalName` / `GeneralString` builders. Lifted from adhammer-kerberos.

use picky_asn1::date::Date;
use picky_asn1::restricted_string::Ia5String;
use picky_asn1::wrapper::{
    Asn1SequenceOf, ExplicitContextTag0, ExplicitContextTag1, GeneralStringAsn1, IntegerAsn1,
};
use picky_krb::data_types::{KerberosTime, PrincipalName};

pub const ETYPE_RC4_HMAC: u8 = 23;
pub const ETYPE_AES256: u8 = 18;

pub fn krb_string(s: &str) -> GeneralStringAsn1 {
    GeneralStringAsn1::from(Ia5String::from_string(s.to_owned()).unwrap())
}

pub fn principal(name_type: u8, parts: &[&str]) -> PrincipalName {
    let strings = parts
        .iter()
        .map(|p| GeneralStringAsn1::from(Ia5String::from_string((*p).to_owned()).unwrap()))
        .collect::<Vec<_>>();
    PrincipalName {
        name_type: ExplicitContextTag0::from(IntegerAsn1(vec![name_type])),
        name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(strings)),
    }
}

/// Current UTC as a Kerberos GeneralizedTime (second granularity).
pub fn now_kerberos_time() -> KerberosTime {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    let tod = secs.rem_euclid(86_400);
    KerberosTime::from(
        Date::new(
            y,
            m,
            d,
            (tod / 3600) as u8,
            ((tod % 3600) / 60) as u8,
            (tod % 60) as u8,
        )
        .unwrap(),
    )
}

/// A far-future Kerberos ticket expiry (`till`). Must be after the start time or the KDC
/// rejects the request with KDC_ERR_NEVER_VALID.
pub fn far_future_time() -> KerberosTime {
    KerberosTime::from(Date::new(2037, 9, 13, 2, 48, 5).unwrap())
}

/// days since 1970-01-01 → (year, month, day). Howard Hinnant's civil_from_days.
fn civil_from_days(z: i64) -> (u16, u8, u8) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    ((y + i64::from(m <= 2)) as u16, m as u8, d as u8)
}
