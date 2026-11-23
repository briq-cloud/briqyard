//! `C(t)`: the strict canonical JSON codec of interface v3.
//!
//! UTF-8 without BOM, object keys recursively sorted by unsigned ASCII byte, arrays in
//! order, unsigned integers in shortest decimal, strings drawn from printable ASCII with
//! neither `"` nor `\` (so none needs escaping). Everything else is refused: whitespace,
//! escapes, negative zero, floats, exponents, non-ASCII bytes, trailing bytes, duplicate
//! or unsorted keys at any depth. A message is parsed from its raw bytes under explicit
//! bounds, decoded into a typed schema, and must re-encode to the received bytes.

use super::prim::HexDigest;
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{Map, Number, Value};

/// A message is at most 64 KiB.
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;
/// At most 24 nested objects and arrays.
pub const MAX_DEPTH: usize = 24;
/// At most 256 elements in an array unless a schema says less.
pub const MAX_ARRAY: usize = 256;
/// Custody frames are at most 4 KiB per packet.
pub const MAX_CUSTODY_PACKET_BYTES: usize = 4 * 1024;
/// Integers are `U`: 0..2^53-1.
pub const MAX_SAFE_INTEGER: u64 = crate::execution::MAX_SAFE_INTEGER;

/// Explicit parse bounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_bytes: usize,
    pub max_depth: usize,
    pub max_array: usize,
}

impl Limits {
    pub const MESSAGE: Limits = Limits {
        max_bytes: MAX_MESSAGE_BYTES,
        max_depth: MAX_DEPTH,
        max_array: MAX_ARRAY,
    };
    pub const CUSTODY_PACKET: Limits = Limits {
        max_bytes: MAX_CUSTODY_PACKET_BYTES,
        max_depth: MAX_DEPTH,
        max_array: MAX_ARRAY,
    };
}

/// Why bytes were refused. Messages are static: they never echo payload bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CodecError {
    #[error("message exceeds the byte bound")]
    TooLarge,
    #[error("nesting exceeds the depth bound")]
    TooDeep,
    #[error("array exceeds the length bound")]
    ArrayTooLong,
    #[error("not canonical JSON: {0}")]
    Syntax(&'static str),
    #[error("duplicate object key")]
    DuplicateKey,
    #[error("object keys are not in ascending byte order")]
    UnsortedKeys,
    #[error("invalid {0}")]
    Value(&'static str),
    #[error("does not match the schema")]
    Schema,
    #[error("re-encoding differs from the received bytes")]
    NotCanonical,
}

/// A typed wire object. Deserialization is the schema; `validate` holds cross-field
/// rules that a field type cannot express. Both run on every decode.
pub trait Wire: Serialize + DeserializeOwned {
    fn validate(&self) -> Result<(), CodecError> {
        Ok(())
    }
}

/// Implements [`Wire`] with no cross-field rule.
macro_rules! wire {
    ($($t:ty),* $(,)?) => { $(impl $crate::execution::sealed::canonical::Wire for $t {})* };
}
pub(crate) use wire;

/// Decode `bytes` as `T` under the default message bounds.
pub fn decode<T: Wire>(bytes: &[u8]) -> Result<T, CodecError> {
    decode_with(bytes, Limits::MESSAGE)
}

/// Parse strictly, decode by schema, validate, and require byte equality with `C(value)`.
pub fn decode_with<T: Wire>(bytes: &[u8], limits: Limits) -> Result<T, CodecError> {
    let value = parse_strict(bytes, limits)?;
    let typed: T = serde_json::from_value(value).map_err(|_| CodecError::Schema)?;
    typed.validate()?;
    if encode_with(&typed, limits)? != bytes {
        return Err(CodecError::NotCanonical);
    }
    Ok(typed)
}

/// `C(t)` under the default message bounds.
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, CodecError> {
    encode_with(value, Limits::MESSAGE)
}

pub fn encode_with<T: Serialize>(value: &T, limits: Limits) -> Result<Vec<u8>, CodecError> {
    let tree = serde_json::to_value(value).map_err(|_| CodecError::Schema)?;
    if !tree.is_object() {
        return Err(CodecError::Schema);
    }
    let mut out = Vec::new();
    write_canonical(&tree, 1, limits, &mut out)?;
    if out.len() > limits.max_bytes {
        return Err(CodecError::TooLarge);
    }
    Ok(out)
}

/// `H(t) = h(C(t))`.
pub fn h<T: Serialize>(value: &T) -> Result<HexDigest, CodecError> {
    Ok(HexDigest::of(&encode(value)?))
}

fn write_canonical(
    value: &Value,
    depth: usize,
    limits: Limits,
    out: &mut Vec<u8>,
) -> Result<(), CodecError> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(number) => match number.as_u64() {
            Some(n) if n <= MAX_SAFE_INTEGER => out.extend_from_slice(n.to_string().as_bytes()),
            _ => return Err(CodecError::Value("integer")),
        },
        Value::String(text) => write_string(text, out)?,
        Value::Array(items) => {
            if depth > limits.max_depth {
                return Err(CodecError::TooDeep);
            }
            if items.len() > limits.max_array {
                return Err(CodecError::ArrayTooLong);
            }
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical(item, depth + 1, limits, out)?;
            }
            out.push(b']');
        }
        Value::Object(fields) => {
            if depth > limits.max_depth {
                return Err(CodecError::TooDeep);
            }
            let mut keys: Vec<&String> = fields.keys().collect();
            keys.sort_unstable();
            out.push(b'{');
            for (i, key) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_string(key, out)?;
                out.push(b':');
                write_canonical(&fields[key], depth + 1, limits, out)?;
            }
            out.push(b'}');
        }
    }
    if out.len() > limits.max_bytes {
        return Err(CodecError::TooLarge);
    }
    Ok(())
}

/// Printable ASCII other than the quote and the backslash: no escape is ever needed.
fn plain_ascii(byte: u8) -> bool {
    matches!(byte, 0x20..=0x7e) && byte != b'"' && byte != b'\\'
}

fn write_string(text: &str, out: &mut Vec<u8>) -> Result<(), CodecError> {
    if !text.bytes().all(plain_ascii) {
        return Err(CodecError::Value("string alphabet"));
    }
    out.push(b'"');
    out.extend_from_slice(text.as_bytes());
    out.push(b'"');
    Ok(())
}

/// Parse raw bytes strictly into a tree. Only [`decode_with`] turns the tree into a typed value.
pub fn parse_strict(bytes: &[u8], limits: Limits) -> Result<Value, CodecError> {
    if bytes.len() > limits.max_bytes {
        return Err(CodecError::TooLarge);
    }
    let mut parser = Parser {
        bytes,
        at: 0,
        limits,
    };
    if parser.peek() != Some(b'{') {
        return Err(CodecError::Syntax("a message is an object"));
    }
    let value = parser.value(1)?;
    if parser.at != bytes.len() {
        return Err(CodecError::Syntax("trailing bytes"));
    }
    Ok(value)
}

struct Parser<'a> {
    bytes: &'a [u8],
    at: usize,
    limits: Limits,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    fn expect(&mut self, byte: u8) -> Result<(), CodecError> {
        if self.peek() != Some(byte) {
            return Err(CodecError::Syntax("unexpected byte"));
        }
        self.at += 1;
        Ok(())
    }

    fn literal(&mut self, word: &[u8], value: Value) -> Result<Value, CodecError> {
        if !self.bytes[self.at..].starts_with(word) {
            return Err(CodecError::Syntax("unexpected byte"));
        }
        self.at += word.len();
        Ok(value)
    }

    fn value(&mut self, depth: usize) -> Result<Value, CodecError> {
        match self.peek() {
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => self.string().map(Value::String),
            Some(b't') => self.literal(b"true", Value::Bool(true)),
            Some(b'f') => self.literal(b"false", Value::Bool(false)),
            Some(b'n') => self.literal(b"null", Value::Null),
            Some(b'0'..=b'9') => self.integer(),
            _ => Err(CodecError::Syntax("unexpected byte")),
        }
    }

    fn integer(&mut self) -> Result<Value, CodecError> {
        let start = self.at;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.at += 1;
        }
        let digits = &self.bytes[start..self.at];
        if matches!(self.peek(), Some(b'.' | b'e' | b'E')) {
            return Err(CodecError::Syntax("float or exponent"));
        }
        if digits.len() > 1 && digits[0] == b'0' {
            return Err(CodecError::Syntax("leading zero"));
        }
        if digits.len() > 16 {
            return Err(CodecError::Syntax("integer out of range"));
        }
        let value = digits
            .iter()
            .fold(0u64, |acc, digit| acc * 10 + u64::from(digit - b'0'));
        if value > MAX_SAFE_INTEGER {
            return Err(CodecError::Syntax("integer out of range"));
        }
        Ok(Value::Number(Number::from(value)))
    }

    fn string(&mut self) -> Result<String, CodecError> {
        self.expect(b'"')?;
        let start = self.at;
        loop {
            match self.peek() {
                None => return Err(CodecError::Syntax("unterminated string")),
                Some(b'"') => break,
                Some(byte) if plain_ascii(byte) => self.at += 1,
                Some(_) => return Err(CodecError::Syntax("string outside the canonical alphabet")),
            }
        }
        let text = String::from_utf8(self.bytes[start..self.at].to_vec())
            .map_err(|_| CodecError::Syntax("string outside the canonical alphabet"))?;
        self.at += 1;
        Ok(text)
    }

    fn array(&mut self, depth: usize) -> Result<Value, CodecError> {
        if depth > self.limits.max_depth {
            return Err(CodecError::TooDeep);
        }
        self.expect(b'[')?;
        let mut items = Vec::new();
        if self.peek() == Some(b']') {
            self.at += 1;
            return Ok(Value::Array(items));
        }
        loop {
            if items.len() >= self.limits.max_array {
                return Err(CodecError::ArrayTooLong);
            }
            items.push(self.value(depth + 1)?);
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b']') => {
                    self.at += 1;
                    return Ok(Value::Array(items));
                }
                _ => return Err(CodecError::Syntax("unexpected byte")),
            }
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value, CodecError> {
        if depth > self.limits.max_depth {
            return Err(CodecError::TooDeep);
        }
        self.expect(b'{')?;
        let mut fields = Map::new();
        if self.peek() == Some(b'}') {
            self.at += 1;
            return Ok(Value::Object(fields));
        }
        let mut previous: Option<String> = None;
        loop {
            let key = self.string()?;
            match previous
                .as_deref()
                .map(|last| last.as_bytes().cmp(key.as_bytes()))
            {
                Some(std::cmp::Ordering::Equal) => return Err(CodecError::DuplicateKey),
                Some(std::cmp::Ordering::Greater) => return Err(CodecError::UnsortedKeys),
                _ => {}
            }
            self.expect(b':')?;
            let value = self.value(depth + 1)?;
            fields.insert(key.clone(), value);
            previous = Some(key);
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b'}') => {
                    self.at += 1;
                    return Ok(Value::Object(fields));
                }
                _ => return Err(CodecError::Syntax("unexpected byte")),
            }
        }
    }
}
