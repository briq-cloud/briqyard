//! What the host and `briqyard-init` agree on: the config drive the init reads at boot, and
//! the vsock protocol the host uses to run commands and move files.
//!
//! Every message is one frame: a 4-byte big-endian length, then JSON. One request per
//! connection; a request gets one response, except `exec`, which streams `stdout`/`stderr`
//! frames and ends with `exit`.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{self, Read, Write};

/// The vsock port briqyard-init listens on.
pub const PORT: u32 = 7421;

/// The largest frame.
pub const MAX_FRAME: usize = 4 << 20;

/// The entry of the config drive that holds [`Config`].
pub const CONFIG_NAME: &str = "config.json";

/// The directory of the config drive that holds boot files, under their guest path.
pub const FILES_PREFIX: &str = "files/";

/// What the init reads from the config drive at every boot.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Config {
    pub hostname: String,
    /// On eth0, CIDR notation.
    pub ip: String,
    pub gateway: String,
    pub dns: Vec<String>,
    /// Extra /etc/hosts entries: name → address.
    #[serde(default)]
    pub hosts: BTreeMap<String, String>,
    /// Resolved against the image's config.
    pub entrypoint: Vec<String>,
    pub cmd: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub workdir: String,
    /// "name", "uid", "name:group" or "uid:gid", as in an OCI config; empty is root.
    pub user: String,
    pub mounts: Vec<Mount>,
    /// The boot files present under [`FILES_PREFIX`], with their modes.
    pub files: Vec<FileMeta>,
    /// How long the main process gets after SIGTERM before SIGKILL.
    pub stop_timeout_sec: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Mount {
    pub device: String,
    pub path: String,
    pub fstype: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileMeta {
    pub path: String,
    pub mode: u32,
}

/// One operation over one connection.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Request {
    /// exec, put, get, ping, shutdown
    pub op: String,
    #[serde(default)]
    pub cmd: Vec<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub cwd: String,
    #[serde(default, with = "b64")]
    pub stdin: Vec<u8>,
    #[serde(default)]
    pub timeout_ms: u64,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub mode: u32,
    #[serde(default, with = "b64")]
    pub data: Vec<u8>,
    #[serde(default)]
    pub grace_sec: u64,
}

/// Responses: stdout and stderr chunks then exit; or ok, file, pong, error.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Response {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default, with = "b64")]
    pub data: Vec<u8>,
    #[serde(default)]
    pub code: i32,
    #[serde(default)]
    pub timed_out: bool,
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub uptime: f64,
    #[serde(default)]
    pub main_pid: i32,
}

impl Response {
    pub fn new(kind: &str) -> Self {
        Self {
            kind: kind.into(),
            ..Default::default()
        }
    }
    pub fn error(msg: impl Into<String>) -> Self {
        Self {
            kind: "error".into(),
            message: msg.into(),
            ..Default::default()
        }
    }
    pub fn chunk(kind: &str, data: Vec<u8>) -> Self {
        Self {
            kind: kind.into(),
            data,
            ..Default::default()
        }
    }
    pub fn exit(code: i32, timed_out: bool) -> Self {
        Self {
            kind: "exit".into(),
            code,
            timed_out,
            ..Default::default()
        }
    }
}

mod b64 {
    use serde::{Deserialize, Deserializer, Serializer};

    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    pub fn encode(data: &[u8]) -> String {
        let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
        for chunk in data.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
            out.push(T[(n >> 18) as usize & 63] as char);
            out.push(T[(n >> 12) as usize & 63] as char);
            out.push(if chunk.len() > 1 {
                T[(n >> 6) as usize & 63] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                T[n as usize & 63] as char
            } else {
                '='
            });
        }
        out
    }

    pub fn decode(s: &str) -> Result<Vec<u8>, String> {
        let mut out = Vec::with_capacity(s.len() / 4 * 3);
        let mut buf = 0u32;
        let mut bits = 0;
        for c in s.bytes() {
            let v = match c {
                b'A'..=b'Z' => c - b'A',
                b'a'..=b'z' => c - b'a' + 26,
                b'0'..=b'9' => c - b'0' + 52,
                b'+' | b'-' => 62,
                b'/' | b'_' => 63,
                b'=' | b'\n' | b'\r' | b' ' => continue,
                _ => return Err(format!("invalid base64 byte {c}")),
            };
            buf = buf << 6 | v as u32;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((buf >> bits) as u8);
                buf &= (1 << bits) - 1;
            }
        }
        Ok(out)
    }

    pub fn serialize<S: Serializer>(data: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&encode(data))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        decode(&s).map_err(serde::de::Error::custom)
    }
}

pub use b64::{decode as base64_decode, encode as base64_encode};

/// Writes one frame.
pub fn write_frame<W: Write, T: Serialize>(w: &mut W, v: &T) -> io::Result<()> {
    let body = serde_json::to_vec(v)?;
    if body.len() > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    w.write_all(&(body.len() as u32).to_be_bytes())?;
    w.write_all(&body)?;
    w.flush()
}

/// Reads one frame.
pub fn read_frame<R: Read, T: for<'de> Deserialize<'de>>(r: &mut R) -> io::Result<T> {
    let mut hdr = [0u8; 4];
    r.read_exact(&mut hdr)?;
    let n = u32::from_be_bytes(hdr) as usize;
    if n > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut body = vec![0u8; n];
    r.read_exact(&mut body)?;
    serde_json::from_slice(&body).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Encodes a frame for an async writer.
pub fn encode_frame<T: Serialize>(v: &T) -> io::Result<Vec<u8>> {
    let body = serde_json::to_vec(v)?;
    if body.len() > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Decodes a frame body (after its length) for an async reader.
pub fn decode_frame<T: for<'de> Deserialize<'de>>(body: &[u8]) -> io::Result<T> {
    serde_json::from_slice(body).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trip() {
        for s in ["", "a", "ab", "abc", "hello, briqyard\n", "\u{0}\u{ff}"] {
            let e = base64_encode(s.as_bytes());
            assert_eq!(base64_decode(&e).unwrap(), s.as_bytes(), "{s:?} -> {e}");
        }
        assert_eq!(base64_encode(b"hello"), "aGVsbG8=");
    }

    #[test]
    fn frames() {
        let mut buf = Vec::new();
        let req = Request {
            op: "exec".into(),
            cmd: vec!["ls".into()],
            stdin: b"x".to_vec(),
            ..Default::default()
        };
        write_frame(&mut buf, &req).unwrap();
        let back: Request = read_frame(&mut &buf[..]).unwrap();
        assert_eq!(back.cmd, vec!["ls"]);
        assert_eq!(back.stdin, b"x");
    }
}
