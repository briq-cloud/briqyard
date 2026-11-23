//! Closed scalar forms used only by the native input manifest.

use crate::execution::sealed::canonical::{CodecError, MAX_MESSAGE_BYTES};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

macro_rules! text_type {
    ($name:ident, $check:ident, $what:literal) => {
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
                Self::new(String::deserialize(d)?).map_err(de::Error::custom)
            }
        }
    };
}

fn valid_git(s: &str) -> bool {
    s.len() == 40
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn valid_version(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 3
        && parts.iter().all(|part| {
            !part.is_empty()
                && part.bytes().all(|b| b.is_ascii_digit())
                && (part.len() == 1 || !part.starts_with('0'))
                && part.parse::<u64>().is_ok()
        })
}

fn valid_hex32(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

text_type!(Git, valid_git, "git commit");
text_type!(Version, valid_version, "release version");
text_type!(Hex32, valid_hex32, "32-character lowercase hex string");

/// `T`: strict unpadded base64url of nonempty bounded UTF-8 without controls.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Text(String);

impl Text {
    pub fn new(text: impl Into<String>) -> Result<Self, CodecError> {
        let text = text.into();
        if text.is_empty() || text.len() > 2048 || text.chars().any(|c| c == '\0' || c.is_control())
        {
            return Err(CodecError::Value("bounded text"));
        }
        Ok(Self(text))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn from_base64(text: &str) -> Result<Self, CodecError> {
        let bytes = decode_b64(text)?;
        let decoded = String::from_utf8(bytes).map_err(|_| CodecError::Value("UTF-8 text"))?;
        Self::new(decoded)
    }

    pub fn to_base64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0.as_bytes())
    }
}

impl Serialize for Text {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_base64())
    }
}

impl<'de> Deserialize<'de> for Text {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Self::from_base64(&String::deserialize(d)?).map_err(de::Error::custom)
    }
}

fn decode_b64(text: &str) -> Result<Vec<u8>, CodecError> {
    if text.is_empty() || text.len() > MAX_MESSAGE_BYTES * 2 || text.ends_with('=') {
        return Err(CodecError::Value("base64url"));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|_| CodecError::Value("base64url"))?;
    if URL_SAFE_NO_PAD.encode(&bytes) != text {
        return Err(CodecError::Value("base64url"));
    }
    Ok(bytes)
}

/// `Path`: `T` of one canonical absolute ASCII pathname. It is a locator, never authority
/// to open it or a claim that its current contents have any particular identity.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Path(Text);

impl Path {
    pub fn new(text: impl Into<String>) -> Result<Self, CodecError> {
        let text = Text::new(text)?;
        let path = text.as_str();
        let valid = path.starts_with('/')
            && path.len() > 1
            && !path.ends_with('/')
            && path.is_ascii()
            && path
                .split('/')
                .skip(1)
                .all(|component| !component.is_empty() && component != "." && component != "..");
        if !valid {
            return Err(CodecError::Value("canonical absolute path"));
        }
        Ok(Self(text))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl Serialize for Path {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(s)
    }
}

impl<'de> Deserialize<'de> for Path {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = Text::deserialize(d)?;
        Self::new(text.as_str()).map_err(de::Error::custom)
    }
}

/// Public DER or other certificate bytes in strict unpadded base64url. This contains no
/// private value and does not parse or validate a certificate.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DerBytes(Vec<u8>);

impl DerBytes {
    pub fn new(bytes: Vec<u8>) -> Result<Self, CodecError> {
        if bytes.is_empty() || bytes.len() > MAX_MESSAGE_BYTES {
            return Err(CodecError::Value("DER byte bounds"));
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Serialize for DerBytes {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&URL_SAFE_NO_PAD.encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for DerBytes {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Self::new(decode_b64(&String::deserialize(d)?).map_err(de::Error::custom)?)
            .map_err(de::Error::custom)
    }
}
