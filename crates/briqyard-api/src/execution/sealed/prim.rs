//! The scalar vocabulary of the sealed wire. Each type validates when it is built or
//! deserialized; none of them coerces. Text types carry exactly the enumerated ASCII
//! alphabets of the contract, so none needs a JSON escape.

use super::canonical::{CodecError, MAX_SAFE_INTEGER};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::fmt;

fn valid_ident(s: &str) -> bool {
    crate::execution::verify::id(s)
}

fn valid_build(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_-.:/+".contains(&c))
}

fn lower_hex(c: u8) -> bool {
    matches!(c, b'0'..=b'9' | b'a'..=b'f')
}

fn valid_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, &c)| match i {
            8 | 13 | 18 | 23 => c == b'-',
            _ => lower_hex(c),
        })
}

fn valid_v4(s: &str) -> bool {
    valid_uuid(s)
        && s.as_bytes()[14] == b'4'
        && matches!(s.as_bytes()[19], b'8' | b'9' | b'a' | b'b')
}

fn valid_hex_digest(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(lower_hex)
}

/// Exact length, URL-safe alphabet, no padding, zero residual bits: decoded and re-encoded
/// it is the identical text.
fn decode_b64<const L: usize>(s: &str) -> Result<[u8; L], CodecError> {
    let bad = CodecError::Value("base64url");
    if s.len() != (L * 4).div_ceil(3) {
        return Err(bad);
    }
    let raw = URL_SAFE_NO_PAD.decode(s).map_err(|_| bad)?;
    let raw: [u8; L] = raw.try_into().map_err(|_| bad)?;
    if URL_SAFE_NO_PAD.encode(raw) != s {
        return Err(bad);
    }
    Ok(raw)
}

macro_rules! text_type {
    ($(#[$meta:meta])* $name:ident, $check:ident, $what:literal) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(String);

        impl $name {
            pub fn new(text: impl Into<String>) -> Result<Self, CodecError> {
                let text = text.into();
                if $check(&text) {
                    Ok(Self(text))
                } else {
                    Err(CodecError::Value($what))
                }
            }
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let text = String::deserialize(d)?;
                Self::new(text).map_err(de::Error::custom)
            }
        }
    };
}

text_type!(
    /// `I`: 1..128 ASCII bytes of `[A-Za-z0-9_.:/-]`, the native ID validator.
    Ident,
    valid_ident,
    "identifier"
);
text_type!(
    /// A build label: `I` plus ASCII `+`, 1..128 bytes.
    Build,
    valid_build,
    "build label"
);
text_type!(
    /// A lowercase Linux boot ID, UUID text 8-4-4-4-12.
    BootId,
    valid_uuid,
    "boot id"
);
text_type!(
    /// `V4`: lowercase canonical RFC 4122 version-4 UUID (variant nibble 8, 9, a or b).
    V4,
    valid_v4,
    "version-4 uuid"
);
text_type!(
    /// `D`: 64 lowercase hex digits.
    HexDigest,
    valid_hex_digest,
    "hex digest"
);

impl HexDigest {
    /// `h(bytes)`: hex SHA-256.
    pub fn of(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    pub fn from_raw(raw: [u8; 32]) -> Self {
        Self(hex::encode(raw))
    }

    pub fn to_raw(&self) -> [u8; 32] {
        let mut raw = [0u8; 32];
        raw.copy_from_slice(&hex::decode(&self.0).expect("validated lowercase hex"));
        raw
    }
}

/// `N`, `K` (32 bytes) and `S` (64 bytes): strict unpadded base64url. Decoding checks
/// the exact length, the alphabet, zero trailing bits, and re-encodes to the same text.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Bytes<const L: usize>([u8; L]);

/// `N`: a 32-byte nonce, challenge or digest.
pub type Nonce = Bytes<32>;
/// `K`: a raw 32-byte Ed25519 public key.
pub type KeyBytes = Bytes<32>;
/// `S`: a 64-byte Ed25519 signature.
pub type SigBytes = Bytes<64>;

impl<const L: usize> Bytes<L> {
    pub const fn from_array(raw: [u8; L]) -> Self {
        Self(raw)
    }

    pub const fn as_array(&self) -> &[u8; L] {
        &self.0
    }

    pub fn parse(text: &str) -> Result<Self, CodecError> {
        decode_b64::<L>(text).map(Self)
    }

    pub fn to_text(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }
}

impl<const L: usize> fmt::Debug for Bytes<L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Bytes<{L}>({})", self.to_text())
    }
}

impl<const L: usize> Serialize for Bytes<L> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_text())
    }
}

impl<'de, const L: usize> Deserialize<'de> for Bytes<L> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        Self::parse(&text).map_err(de::Error::custom)
    }
}

/// `U`: an integer 0..9007199254740991.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Uint(u64);

impl Uint {
    pub fn new(value: u64) -> Result<Self, CodecError> {
        if value > MAX_SAFE_INTEGER {
            return Err(CodecError::Value("integer"));
        }
        Ok(Self(value))
    }
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// `P`: `U` except 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PosInt(u64);

impl PosInt {
    pub fn new(value: u64) -> Result<Self, CodecError> {
        if value == 0 || value > MAX_SAFE_INTEGER {
            return Err(CodecError::Value("positive integer"));
        }
        Ok(Self(value))
    }
    pub const fn get(self) -> u64 {
        self.0
    }
}

macro_rules! int_type {
    ($name:ident) => {
        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_u64(self.0)
            }
        }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                Self::new(u64::deserialize(d)?).map_err(de::Error::custom)
            }
        }
    };
}
int_type!(Uint);
int_type!(PosInt);

/// `E`: the audience environment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Env {
    #[serde(rename = "staging")]
    Staging,
    #[serde(rename = "production")]
    Production,
}

/// A JSON boolean fixed by the schema, e.g. `timed_out:false`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LitBool<const V: bool>;

impl<const V: bool> Serialize for LitBool<V> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bool(V)
    }
}

impl<'de, const V: bool> Deserialize<'de> for LitBool<V> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if bool::deserialize(d)? == V {
            Ok(Self)
        } else {
            Err(de::Error::custom("literal"))
        }
    }
}

/// An integer fixed by the schema, e.g. `exit_code:0`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LitU<const V: u64>;

impl<const V: u64> Serialize for LitU<V> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(V)
    }
}

impl<'de, const V: u64> Deserialize<'de> for LitU<V> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if u64::deserialize(d)? == V {
            Ok(Self)
        } else {
            Err(de::Error::custom("literal"))
        }
    }
}

/// The zero-length string a schema fixes (`stderr`, `cwd`, `stdin`): never null.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EmptyStr;

impl Serialize for EmptyStr {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str("")
    }
}

impl<'de> Deserialize<'de> for EmptyStr {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if String::deserialize(d)?.is_empty() {
            Ok(Self)
        } else {
            Err(de::Error::custom("literal"))
        }
    }
}

/// The empty map a schema fixes (`env`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EmptyMap;

impl Serialize for EmptyMap {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        s.serialize_map(Some(0))?.end()
    }
}

impl<'de> Deserialize<'de> for EmptyMap {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let map = std::collections::BTreeMap::<String, String>::deserialize(d)?;
        if map.is_empty() {
            Ok(Self)
        } else {
            Err(de::Error::custom("literal"))
        }
    }
}

/// Deserializes `T?`: a value or an explicit JSON null. Used with `deserialize_with`, which
/// makes serde reject an omitted field instead of defaulting it to `None`.
pub fn nullable<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(d)
}
