//! The one X.509 profile a private transport identity may have (interface v3.3, "Private
//! identities"): an individual self-signed P-256 end-entity leaf, version 3, one SAN, one
//! explicit extended key usage, nothing else. Every other shape is refused, so a pinned
//! digest can never stand for a certificate this reader did not fully understand.
//!
//! The pin (leaf and SPKI digests) is the trust anchor. The self-signature is checked only
//! to show the leaf is self-issued, never as authority; possession of the private key is
//! proved by the TLS handshake.

use super::{
    clock::{ClockSource, QualifiedClock},
    sealed::prim::HexDigest,
};
use ring::{
    rand::SystemRandom,
    signature::{
        EcdsaKeyPair, KeyPair, UnparsedPublicKey, ECDSA_P256_SHA256_ASN1,
        ECDSA_P256_SHA256_ASN1_SIGNING,
    },
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const MAX_NAME: usize = 253;

/// `Pair`: SHA-256 of the leaf DER and of its DER SubjectPublicKeyInfo.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Pair {
    pub leaf: HexDigest,
    pub spki: HexDigest,
}

/// A certificate name: lowercase LDH DNS text without wildcard or trailing dot, or a
/// canonical IP literal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Name {
    Dns(String),
    Ip(IpAddr),
}

impl Name {
    pub fn dns(text: &str) -> Option<Self> {
        let label = |label: &str| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        };
        let numeric = text.bytes().all(|b| b.is_ascii_digit() || b == b'.');
        (text.len() <= MAX_NAME && !numeric && text.split('.').all(label))
            .then(|| Self::Dns(text.to_owned()))
    }
}

const MAX_CERT: usize = 4096;

const ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const SERVER_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
const CLIENT_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];
const SAN: &[u8] = &[0x55, 0x1d, 0x11];
const EKU: &[u8] = &[0x55, 0x1d, 0x25];
const KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
const BASIC: &[u8] = &[0x55, 0x1d, 0x13];
const SKI: &[u8] = &[0x55, 0x1d, 0x0e];
const AKI: &[u8] = &[0x55, 0x1d, 0x23];

/// `SubjectPublicKeyInfo` of an uncompressed P-256 `id-ecPublicKey` key, up to the point.
const SPKI_PREFIX: [u8; 27] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
];
const SPKI_LEN: usize = 91;

const SEQUENCE: u8 = 0x30;
const INTEGER: u8 = 0x02;
const BIT_STRING: u8 = 0x03;
const OCTET_STRING: u8 = 0x04;
const OID: u8 = 0x06;
const BOOLEAN: u8 = 0x01;
const UTC_TIME: u8 = 0x17;
const GENERALIZED_TIME: u8 = 0x18;
const VERSION: u8 = 0xa0;
const EXTENSIONS: u8 = 0xa3;
const DNS_NAME: u8 = 0x82;
const IP_ADDRESS: u8 = 0x87;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Usage {
    Server,
    Client,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CertError {
    Encoding,
    Profile,
    Pin,
    Name,
    Time,
}

impl std::fmt::Display for CertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Encoding => "certificate encoding refused",
            Self::Profile => "certificate profile refused",
            Self::Pin => "certificate does not match its pin",
            Self::Name => "certificate name refused",
            Self::Time => "certificate not valid at the qualified time",
        })
    }
}

impl std::error::Error for CertError {}

#[derive(Debug)]
pub struct Leaf {
    spki: [u8; SPKI_LEN],
    pub name: Name,
    not_before: u64,
    not_after: u64,
}

impl Leaf {
    /// The uncompressed public point, as `ring` reports it for the matching private key.
    pub fn point(&self) -> &[u8] {
        &self.spki[SPKI_PREFIX.len() - 1..]
    }

    pub fn spki_digest(&self) -> HexDigest {
        HexDigest::of(&self.spki)
    }

    /// The whole qualified interval lies inside the certificate's validity.
    pub fn valid_at(&self, clock: &dyn ClockSource) -> Result<(), CertError> {
        let QualifiedClock { interval, .. } = clock.qualified().ok_or(CertError::Time)?;
        let lower = interval.now.checked_sub(interval.uncertainty);
        let upper = interval.now.checked_add(interval.uncertainty);
        match (lower, upper) {
            (Some(lower), Some(upper)) if lower >= self.not_before && upper <= self.not_after => {
                Ok(())
            }
            _ => Err(CertError::Time),
        }
    }
}

/// Check a presented or provisioned DER against its pin and the profile for `usage`. The
/// digest comparison comes first: only the exact enrolled bytes reach the parser.
pub fn verify(der: &[u8], pin: &Pair, usage: Usage) -> Result<Leaf, CertError> {
    if HexDigest::of(der) != pin.leaf {
        return Err(CertError::Pin);
    }
    let leaf = parse(der, usage)?;
    if leaf.spki_digest() != pin.spki {
        return Err(CertError::Pin);
    }
    Ok(leaf)
}

/// The SPKI digest of the P-256 key inside an unencrypted PKCS#8 DER, from the same `ring`
/// parse the transport uses to build its signing key: other algorithms, curves, encodings
/// and trailing bytes are refused, and the digest is of the derived public key, never of a
/// private byte.
pub fn key_spki_digest(pkcs8: &[u8]) -> Result<HexDigest, CertError> {
    let pair =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8, &SystemRandom::new())
            .map_err(|_| CertError::Profile)?;
    let point = pair.public_key().as_ref();
    if point.len() != SPKI_LEN - SPKI_PREFIX.len() + 1 {
        return Err(CertError::Profile);
    }
    let mut spki = [0; SPKI_LEN];
    spki[..SPKI_PREFIX.len() - 1].copy_from_slice(&SPKI_PREFIX[..SPKI_PREFIX.len() - 1]);
    spki[SPKI_PREFIX.len() - 1..].copy_from_slice(point);
    Ok(HexDigest::of(&spki))
}

/// The SPKI digest of one complete DER certificate of any profile: exactly one object, every
/// element well formed, no trailing byte. Neither names, usages nor the signature are
/// interpreted; the caller compares this digest with the key it expects and pins the bytes.
pub fn leaf_spki_digest(der: &[u8]) -> Result<HexDigest, CertError> {
    let mut cert = sequence(der)?;
    let mut tbs = sequence(cert.take_raw(SEQUENCE)?)?;
    cert.take(SEQUENCE)?;
    cert.take(BIT_STRING)?;
    cert.end()?;
    if tbs.peek() == Some(VERSION) {
        tbs.take(VERSION)?;
    }
    tbs.take(INTEGER)?;
    tbs.take(SEQUENCE)?;
    tbs.take(SEQUENCE)?;
    tbs.take(SEQUENCE)?;
    tbs.take(SEQUENCE)?;
    let spki = tbs.take_raw(SEQUENCE)?;
    while !tbs.0.is_empty() {
        tbs.take_any()?;
    }
    Ok(HexDigest::of(spki))
}

pub fn parse(der: &[u8], usage: Usage) -> Result<Leaf, CertError> {
    if der.len() > MAX_CERT {
        return Err(CertError::Encoding);
    }
    let mut cert = sequence(der)?;
    let tbs_whole = cert.take_raw(SEQUENCE)?;
    let tbs_raw = Reader(tbs_whole).take(SEQUENCE)?;
    let signature_algorithm = cert.take(SEQUENCE)?;
    let signature = cert.take(BIT_STRING)?;
    cert.end()?;
    algorithm(signature_algorithm)?;
    if signature.first() != Some(&0) || signature.len() < 2 {
        return Err(CertError::Encoding);
    }

    let mut tbs = Reader(tbs_raw);
    if tbs.take(VERSION)? != [0x02, 0x01, 0x02] {
        return Err(CertError::Profile);
    }
    let serial = tbs.take(INTEGER)?;
    if serial.is_empty()
        || serial.len() > 20
        || serial[0] & 0x80 != 0
        || (serial.len() > 1 && serial[0] == 0 && serial[1] & 0x80 == 0)
    {
        return Err(CertError::Encoding);
    }
    let inner_algorithm = tbs.take(SEQUENCE)?;
    if inner_algorithm != signature_algorithm {
        return Err(CertError::Profile);
    }
    let issuer = tbs.take_raw(SEQUENCE)?;
    let mut validity = Reader(tbs.take(SEQUENCE)?);
    let not_before = time(&mut validity)?;
    let not_after = time(&mut validity)?;
    validity.end()?;
    if not_before > not_after {
        return Err(CertError::Profile);
    }
    let subject = tbs.take_raw(SEQUENCE)?;
    if issuer != subject {
        return Err(CertError::Profile);
    }
    let spki: [u8; SPKI_LEN] = tbs
        .take_raw(SEQUENCE)?
        .try_into()
        .map_err(|_| CertError::Profile)?;
    if spki[..SPKI_PREFIX.len()] != SPKI_PREFIX {
        return Err(CertError::Profile);
    }
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &spki[SPKI_PREFIX.len() - 1..])
        .verify(tbs_whole, &signature[1..])
        .map_err(|_| CertError::Profile)?;
    let mut extensions = sequence(tbs.take(EXTENSIONS)?)?;
    tbs.end()?;

    let (mut name, mut eku, mut seen) = (None, false, Vec::new());
    while !extensions.0.is_empty() {
        let mut extension = Reader(extensions.take(SEQUENCE)?);
        let id = extension.take(OID)?;
        if seen.contains(&id) {
            return Err(CertError::Profile);
        }
        seen.push(id);
        let critical = if extension.peek() == Some(BOOLEAN) {
            if extension.take(BOOLEAN)? != [0xff] {
                return Err(CertError::Encoding);
            }
            true
        } else {
            false
        };
        let value = extension.take(OCTET_STRING)?;
        extension.end()?;
        match id {
            SAN => name = Some(subject_name(value)?),
            EKU => {
                extended_usage(value, usage)?;
                eku = true;
            }
            KEY_USAGE => key_usage(value)?,
            BASIC => basic_constraints(value)?,
            SKI | AKI if !critical => (),
            _ => return Err(CertError::Profile),
        }
    }
    if !eku {
        return Err(CertError::Profile);
    }
    Ok(Leaf {
        spki,
        name: name.ok_or(CertError::Name)?,
        not_before,
        not_after,
    })
}

fn algorithm(body: &[u8]) -> Result<(), CertError> {
    let mut reader = Reader(body);
    if reader.take(OID)? != ECDSA_SHA256 {
        return Err(CertError::Profile);
    }
    reader.end()
}

fn subject_name(value: &[u8]) -> Result<Name, CertError> {
    let mut names = sequence(value)?;
    let entry = names.take_any()?;
    names.end()?;
    match entry {
        (DNS_NAME, text) => {
            let text = std::str::from_utf8(text).map_err(|_| CertError::Name)?;
            Name::dns(text).ok_or(CertError::Name)
        }
        (IP_ADDRESS, [a, b, c, d]) => Ok(Name::Ip(IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d)))),
        (IP_ADDRESS, raw) if raw.len() == 16 => {
            let raw: [u8; 16] = raw.try_into().map_err(|_| CertError::Name)?;
            Ok(Name::Ip(IpAddr::V6(Ipv6Addr::from(raw))))
        }
        _ => Err(CertError::Name),
    }
}

fn extended_usage(value: &[u8], usage: Usage) -> Result<(), CertError> {
    let mut usages = sequence(value)?;
    let only = usages.take(OID)?;
    usages.end()?;
    let wanted = match usage {
        Usage::Server => SERVER_AUTH,
        Usage::Client => CLIENT_AUTH,
    };
    if only == wanted {
        Ok(())
    } else {
        Err(CertError::Profile)
    }
}

fn key_usage(value: &[u8]) -> Result<(), CertError> {
    let mut reader = Reader(value);
    let bits = reader.take(BIT_STRING)?;
    reader.end()?;
    let [unused, first, ..] = bits else {
        return Err(CertError::Encoding);
    };
    let digital_signature = first & 0x80 != 0;
    let certificate_signing = first & 0x04 != 0 || first & 0x02 != 0;
    if *unused > 7 || !digital_signature || certificate_signing {
        return Err(CertError::Profile);
    }
    Ok(())
}

fn basic_constraints(value: &[u8]) -> Result<(), CertError> {
    sequence(value)?.end().map_err(|_| CertError::Profile)
}

/// UTCTime before 2050 and GeneralizedTime from 2050, whole seconds, `Z` only.
fn time(reader: &mut Reader<'_>) -> Result<u64, CertError> {
    let (tag, text) = reader.take_any()?;
    let digits = |from: usize, to: usize| -> Result<u64, CertError> {
        let part = text.get(from..to).ok_or(CertError::Encoding)?;
        if !part.iter().all(u8::is_ascii_digit) {
            return Err(CertError::Encoding);
        }
        Ok(part.iter().fold(0, |n, d| n * 10 + u64::from(d - b'0')))
    };
    let (year, rest) = match (tag, text.len()) {
        (UTC_TIME, 13) => {
            let yy = digits(0, 2)?;
            (if yy < 50 { 2000 + yy } else { 1900 + yy }, 2)
        }
        (GENERALIZED_TIME, 15) => (digits(0, 4)?, 4),
        _ => return Err(CertError::Encoding),
    };
    let (month, day) = (digits(rest, rest + 2)?, digits(rest + 2, rest + 4)?);
    let (hour, minute, second) = (
        digits(rest + 4, rest + 6)?,
        digits(rest + 6, rest + 8)?,
        digits(rest + 8, rest + 10)?,
    );
    if text.get(rest + 10) != Some(&b'Z')
        || (tag == GENERALIZED_TIME && year < 2050)
        || year < 1970
        || !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(CertError::Encoding);
    }
    Ok(days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second)
}

fn days_in_month(year: u64, month: u64) -> u64 {
    match month {
        4 | 6 | 9 | 11 => 30,
        2 if year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400)) => {
            29
        }
        2 => 28,
        _ => 31,
    }
}

fn days_from_civil(year: u64, month: u64, day: u64) -> u64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year / 400;
    let year_of_era = year - era * 400;
    let shifted = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * shifted + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// The content of `bytes` as exactly one SEQUENCE: nothing may follow it.
fn sequence(bytes: &[u8]) -> Result<Reader<'_>, CertError> {
    let mut outer = Reader(bytes);
    let inner = Reader(outer.take(SEQUENCE)?);
    outer.end()?;
    Ok(inner)
}

/// A cursor over definite-length DER with single-byte tags and minimal lengths.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn peek(&self) -> Option<u8> {
        self.0.first().copied()
    }

    fn end(&self) -> Result<(), CertError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(CertError::Encoding)
        }
    }

    fn take_any(&mut self) -> Result<(u8, &'a [u8]), CertError> {
        let (tag, value, rest) = split(self.0)?;
        self.0 = rest;
        Ok((tag, value))
    }

    fn take(&mut self, tag: u8) -> Result<&'a [u8], CertError> {
        match self.take_any()? {
            (found, value) if found == tag => Ok(value),
            _ => Err(CertError::Encoding),
        }
    }

    /// The element with its own header, for byte-for-byte comparison.
    fn take_raw(&mut self, tag: u8) -> Result<&'a [u8], CertError> {
        let whole = self.0;
        let (found, _, rest) = split(whole)?;
        if found != tag {
            return Err(CertError::Encoding);
        }
        self.0 = rest;
        Ok(&whole[..whole.len() - rest.len()])
    }
}

fn split(bytes: &[u8]) -> Result<(u8, &[u8], &[u8]), CertError> {
    let [tag, first, rest @ ..] = bytes else {
        return Err(CertError::Encoding);
    };
    if tag & 0x1f == 0x1f {
        return Err(CertError::Encoding);
    }
    let (length, rest) = match *first {
        0x80 => return Err(CertError::Encoding),
        short if short < 0x80 => (usize::from(short), rest),
        long => {
            let count = usize::from(long & 0x7f);
            if count == 0 || count > 2 || rest.len() < count || rest[0] == 0 {
                return Err(CertError::Encoding);
            }
            let length = rest[..count]
                .iter()
                .fold(0usize, |n, byte| (n << 8) | usize::from(*byte));
            if length < 0x80 {
                return Err(CertError::Encoding);
            }
            (length, &rest[count..])
        }
    };
    if rest.len() < length {
        return Err(CertError::Encoding);
    }
    Ok((*tag, &rest[..length], &rest[length..]))
}

#[cfg(test)]
mod tests;
