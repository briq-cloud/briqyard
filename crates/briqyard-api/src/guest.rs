//! What the host and `briqyard-init` agree on: the config drive the init reads at boot, and
//! the vsock protocol the host uses to run commands and move files.
//!
//! Every message is one frame: a 4-byte big-endian length, then JSON. One request per
//! connection; a request gets one response, except `exec`, which streams `stdout`/`stderr`
//! frames and ends with `exit`. `put_stream` and `get_stream` exchange a framed ready
//! handshake; uploads use bounded binary chunks and a zero-length terminal, downloads
//! send a declared number of raw bytes (ADR 0061). After an `exec` the host may send more frames on the same
//! connection (`stdin`, `resize`, `close_stdin`), and its close ends the command (ADR 0029).
//!
//! One connection goes the other way: when the main process ends, the init connects to the
//! host on [`EXIT_PORT`] and sends one [`ExitReport`] frame, then waits for the host to close
//! before it resets the machine.
//!
//! A machine keeps the init it booted with while daemons are upgraded under it, so both sides
//! read what the other's version writes (ADR 0027): changes are additive (a field is added
//! with a default that means what its absence meant, never renamed, retyped or removed);
//! unknown fields are ignored; an unknown `op` is answered `error` "unknown op <op>"; an
//! unknown response `type` in a stream is skipped. The init says its version in `pong`.

mod clone;
mod destination;
pub use clone::{CloneConfigure, CloneIdentity, CloneStatus, INIT_READY_V1};
pub use destination::{DestinationBind, DestinationFile, SANDBOX_READY_V1};

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{self, Read, Write};

/// The vsock port briqyard-init listens on.
pub const PORT: u32 = 7421;

/// The host port the init connects to with its [`ExitReport`].
pub const EXIT_PORT: u32 = 7422;

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
    /// Internal, reviewed template recipe; absent retains ordinary boot behavior.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template_profile: Option<String>,
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

/// One operation over one connection; after an `exec`, its input: `stdin` (`data`), `resize`
/// (`cols`, `rows`), `close_stdin`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Request {
    /// exec, put, get, put_stream, get_stream, ping, shutdown; then stdin, resize, close_stdin
    pub op: String,
    #[serde(default)]
    pub cmd: Vec<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub cwd: String,
    /// Written to the command first; without `interactive` its stdin then ends.
    #[serde(default, with = "b64")]
    pub stdin: Vec<u8>,
    /// The command's deadline; 0 is none.
    #[serde(default)]
    pub timeout_ms: u64,
    /// Stdin stays open for `stdin` frames until `close_stdin`.
    #[serde(default)]
    pub interactive: bool,
    /// Run the command on a pseudo-terminal of `cols` by `rows` (0: 80 by 24).
    #[serde(default)]
    pub tty: bool,
    #[serde(default)]
    pub cols: u16,
    #[serde(default)]
    pub rows: u16,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub mode: u32,
    #[serde(default, with = "b64")]
    pub data: Vec<u8>,
    #[serde(default)]
    pub grace_sec: u64,
    /// Optional declared total for put_stream; absent for older operations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// Streaming upload permissions; absent preserves a regular destination's mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_mode: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clone_configure: Option<CloneConfigure>,
    /// Complete destination configuration, accepted only at the sandbox barrier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_bind: Option<DestinationBind>,
    /// Clone activation is bound to the acknowledged generation.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub clone_generation: String,
    /// Fresh host wall time applied only before the first activation, never on replay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clone_activation_realtime_sec: Option<u64>,
}

/// Responses: stdout and stderr chunks then exit; or ok, file, pong, ready, error.
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
    /// The init's version, in a `pong` (ADR 0027); empty from an init older than the field.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub version: String,
    /// Raw bytes following a get_stream ready response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// SHA-256 of a committed streaming upload.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sha256: String,
    /// Explicit live capability: version numbers alone do not distinguish development builds.
    #[serde(default, skip_serializing_if = "is_false")]
    pub file_stream_v1: bool,
    /// Present only for guests born at the reviewed pre-main template barrier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clone_status: Option<CloneStatus>,
    /// Digest of the actual running init executable, cached from /proc/self/exe.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub init_sha256: String,
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// How the main process ended, sent by the init on [`EXIT_PORT`] before the machine resets.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitReport {
    pub code: i32,
    /// The kernel's OOM killer ended it.
    pub oom: bool,
    /// The host asked for the stop (`shutdown`).
    pub requested: bool,
    /// The main process ran: false when the init failed before it (its own 125, 126, 127).
    #[serde(default)]
    pub started: bool,
    /// The init's version, as in its `pong` (ADR 0027): a process that exits at once may end
    /// the machine before the host's first ping. Empty from an init older than this field.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub version: String,
    /// Why the init could not start the main process, with `started` false: its own console
    /// line, e.g. `start "/run.sh": Operation not permitted (os error 1)`. Empty once it
    /// started, and from an init older than this field.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error: String,
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
        let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
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
    use serde_json::{json, Value};

    /// Parses `input` as a `T` and checks it serializes to exactly `expected`.
    fn round_trip<T>(input: Value, expected: Value) -> T
    where
        T: Serialize + for<'de> Deserialize<'de>,
    {
        let v: T = serde_json::from_value(input.clone()).unwrap_or_else(|e| panic!("{input}: {e}"));
        assert_eq!(serde_json::to_value(&v).unwrap(), expected);
        v
    }

    fn same<T>(input: Value) -> T
    where
        T: Serialize + for<'de> Deserialize<'de>,
    {
        round_trip(input.clone(), input)
    }

    #[test]
    fn constants() {
        // The init listens on this port and the daemon writes the drive under these names.
        assert_eq!(PORT, 7421);
        assert_eq!(EXIT_PORT, 7422);
        assert_eq!(MAX_FRAME, 4 * 1024 * 1024);
        assert_eq!(CONFIG_NAME, "config.json");
        assert_eq!(FILES_PREFIX, "files/");
    }

    #[test]
    fn config() {
        let input = json!({
            "hostname": "db", "ip": "10.64.1.2/24", "gateway": "10.64.1.1",
            "dns": ["10.64.1.1"], "hosts": {"cache.internal": "10.64.1.3"},
            "entrypoint": ["docker-entrypoint.sh"], "cmd": ["postgres"],
            "env": {"POSTGRES_PASSWORD": "x"}, "workdir": "/", "user": "postgres",
            "mounts": [{"device": "/dev/vdc", "path": "/var/lib/postgresql/data", "fstype": "ext4"}],
            "files": [{"path": "/etc/app.conf", "mode": 384}],
            "stop_timeout_sec": 10
        });
        let c: Config = same(input);
        assert_eq!(
            c.hosts.get("cache.internal").map(String::as_str),
            Some("10.64.1.3")
        );
        assert_eq!(c.mounts[0].path, "/var/lib/postgresql/data");
        assert_eq!(c.files[0].mode, 0o600);
        // Only hosts has a default: a drive from an older daemon may leave it out, nothing else.
        let c: Config = round_trip(
            json!({
                "hostname": "", "ip": "", "gateway": "", "dns": [], "entrypoint": [], "cmd": [],
                "env": {}, "workdir": "", "user": "", "mounts": [], "files": [], "stop_timeout_sec": 0
            }),
            json!({
                "hostname": "", "ip": "", "gateway": "", "dns": [], "hosts": {}, "entrypoint": [],
                "cmd": [], "env": {}, "workdir": "", "user": "", "mounts": [], "files": [],
                "stop_timeout_sec": 0
            }),
        );
        assert!(c.hosts.is_empty());
        assert!(serde_json::from_value::<Config>(json!({"hostname": "x"})).is_err());
    }

    #[test]
    fn request_defaults() {
        // Only op is required; the binary fields come back as empty base64.
        let r: Request = round_trip(
            json!({"op": "ping"}),
            json!({
                "op": "ping", "cmd": [], "env": {}, "cwd": "", "stdin": "", "timeout_ms": 0,
                "interactive": false, "tty": false, "cols": 0, "rows": 0,
                "path": "", "mode": 0, "data": "", "grace_sec": 0
            }),
        );
        assert!(r.stdin.is_empty());
        assert!(serde_json::from_value::<Request>(json!({"cmd": ["ls"]})).is_err());
    }

    #[test]
    fn request_binary_fields() {
        let r: Request = same(json!({
            "op": "exec", "cmd": ["cat"], "env": {"A": "1"}, "cwd": "/tmp", "stdin": "aGk=",
            "timeout_ms": 100, "interactive": true, "tty": true, "cols": 100, "rows": 30,
            "path": "/etc/x", "mode": 420, "data": "AP8=", "grace_sec": 5
        }));
        assert!(r.interactive && r.tty);
        assert_eq!((r.cols, r.rows), (100, 30));
        assert_eq!(r.stdin, b"hi");
        assert_eq!(r.data, [0u8, 0xff]);
        assert_eq!(r.mode, 0o644);
        assert!(
            serde_json::from_value::<Request>(json!({"op": "put", "data": "not base64!"})).is_err()
        );
    }

    #[test]
    fn response_on_the_wire() {
        // The kind is `type`; every other field has a default.
        let r: Response = round_trip(
            json!({"type": "exit", "code": 3, "timed_out": true}),
            json!({
                "type": "exit", "data": "", "code": 3, "timed_out": true, "message": "",
                "uptime": 0.0, "main_pid": 0
            }),
        );
        assert_eq!(r.kind, "exit");
        let r: Response = same(json!({
            "type": "pong", "data": "", "code": 0, "timed_out": false, "message": "",
            "uptime": 12.5, "main_pid": 42
        }));
        assert_eq!(r.main_pid, 42);
        let r: Response = same(json!({
            "type": "stdout", "data": "aGVsbG8=", "code": 0, "timed_out": false, "message": "",
            "uptime": 0.0, "main_pid": 0
        }));
        assert_eq!(r.data, b"hello");
        assert!(serde_json::from_value::<Response>(json!({"kind": "ok"})).is_err());
    }

    #[test]
    fn exit_report_on_the_wire() {
        // Every field is written, and a report from an init that knows fewer still reads.
        let r: ExitReport = same(json!({
            "code": 137, "oom": true, "requested": false, "started": true, "version": "0.1.0"
        }));
        assert_eq!(
            r,
            ExitReport {
                code: 137,
                oom: true,
                requested: false,
                started: true,
                version: "0.1.0".into(),
                error: String::new(),
            }
        );
        // A program the init could not start: why, in its own words.
        let r: ExitReport = same(json!({
            "code": 127, "oom": false, "requested": false, "started": false, "version": "0.1.2",
            "error": "start \"/run.sh\": Operation not permitted (os error 1)"
        }));
        assert_eq!(
            r.error,
            "start \"/run.sh\": Operation not permitted (os error 1)"
        );
        assert!(serde_json::from_value::<ExitReport>(json!({"code": 1})).is_err());
        // One frame, read back by the sync reader the way the host reads it.
        let mut buf = Vec::new();
        write_frame(&mut buf, &r).unwrap();
        let back: ExitReport = read_frame(&mut &buf[..]).unwrap();
        assert_eq!(back, r);
        assert_eq!(ExitReport::default().code, 0);
    }

    #[test]
    fn a_pong_says_the_inits_version() {
        let r: Response = same(json!({
            "type": "pong", "data": "", "code": 0, "timed_out": false, "message": "",
            "uptime": 1.0, "main_pid": 7, "version": "0.1.0+fdad892eeefa"
        }));
        assert_eq!(r.version, "0.1.0+fdad892eeefa");
        // Written only when there is one: every other frame is as it was.
        assert!(serde_json::to_value(Response::new("ok"))
            .unwrap()
            .get("version")
            .is_none());
    }

    /// What each side of the oldest version still running may send (ADR 0027): the current
    /// types read it, and read what a newer side adds (fields, an op, a type) without failing.
    #[test]
    fn old_and_new_shapes_decode() {
        // A pong from an init older than its version: no version, which the daemon shows as
        // unknown.
        let r: Response =
            serde_json::from_value(json!({"type": "pong", "uptime": 3.5, "main_pid": 9})).unwrap();
        assert_eq!((r.version.as_str(), r.main_pid), ("", 9));
        // The first exit report, and one with a field a later init adds.
        // An init older than `started`, `version` and `error`: not said to have started,
        // version unknown, no reason.
        let r: ExitReport =
            serde_json::from_value(json!({"code": 1, "oom": false, "requested": true})).unwrap();
        assert!(r.requested);
        assert_eq!(
            (r.started, r.version.as_str(), r.error.as_str()),
            (false, "", "")
        );
        let r: ExitReport = serde_json::from_value(
            json!({"code": 2, "oom": true, "requested": false, "signal": 9}),
        )
        .unwrap();
        assert_eq!((r.code, r.oom), (2, true));
        // A request with a field and an op this init does not know: decoded, the op answered
        // `unknown op` by the init's dispatch.
        let r: Request =
            serde_json::from_value(json!({"op": "resize", "rows": 40, "cols": 120})).unwrap();
        assert_eq!(r.op, "resize");
        // A response of a type the daemon does not know, with a field it does not know.
        let r: Response =
            serde_json::from_value(json!({"type": "progress", "percent": 50})).unwrap();
        assert_eq!(r.kind, "progress");
        // A drive from a newer daemon: its new field ignored by this init.
        let c: Config = serde_json::from_value(json!({
            "hostname": "a", "ip": "10.64.0.2/24", "gateway": "10.64.0.1", "dns": [],
            "entrypoint": [], "cmd": ["sleep"], "env": {}, "workdir": "/", "user": "",
            "mounts": [], "files": [], "stop_timeout_sec": 10, "sysctls": {"a": "1"}
        }))
        .unwrap();
        assert_eq!(c.cmd, ["sleep"]);
    }

    #[test]
    fn response_constructors() {
        let r = Response::new("ok");
        assert_eq!(r.kind, "ok");
        assert!(r.data.is_empty() && r.message.is_empty() && r.code == 0);
        let r = Response::error("no such file");
        assert_eq!(
            (r.kind.as_str(), r.message.as_str()),
            ("error", "no such file")
        );
        let r = Response::chunk("stderr", b"oops".to_vec());
        assert_eq!((r.kind.as_str(), &r.data[..]), ("stderr", &b"oops"[..]));
        let r = Response::exit(137, true);
        assert_eq!((r.kind.as_str(), r.code, r.timed_out), ("exit", 137, true));
        assert_eq!(
            serde_json::to_value(Response::chunk("file", vec![1, 2, 3])).unwrap()["data"],
            json!("AQID")
        );
    }

    #[test]
    fn base64_round_trip() {
        for s in ["", "a", "ab", "abc", "hello, briqyard\n", "\u{0}\u{ff}"] {
            let e = base64_encode(s.as_bytes());
            assert_eq!(base64_decode(&e).unwrap(), s.as_bytes(), "{s:?} -> {e}");
        }
        assert_eq!(base64_encode(b"hello"), "aGVsbG8=");
        // Every byte value, at every length modulo 3.
        let all: Vec<u8> = (0..=255).collect();
        for n in [254, 255, 256] {
            let e = base64_encode(&all[..n]);
            assert_eq!(e.len() % 4, 0);
            assert_eq!(base64_decode(&e).unwrap(), &all[..n]);
        }
    }

    #[test]
    fn base64_padding() {
        assert_eq!(base64_encode(b"h"), "aA==");
        assert_eq!(base64_encode(b"hi"), "aGk=");
        assert_eq!(base64_encode(b"hey"), "aGV5");
        // Padding is optional on the way in.
        assert_eq!(base64_decode("aGk=").unwrap(), b"hi");
        assert_eq!(base64_decode("aGk").unwrap(), b"hi");
        assert_eq!(base64_decode("aA==").unwrap(), b"h");
        assert_eq!(base64_decode("aA").unwrap(), b"h");
        assert_eq!(base64_decode("").unwrap(), b"");
        assert_eq!(base64_decode("====").unwrap(), b"");
    }

    #[test]
    fn base64_lenient_input() {
        // The URL alphabet and whitespace, which a JSON client may send, are accepted.
        assert_eq!(base64_decode("+/8=").unwrap(), [0xfb, 0xff]);
        assert_eq!(base64_decode("-_8=").unwrap(), [0xfb, 0xff]);
        assert_eq!(base64_decode("aGVs\nbG8=\r\n").unwrap(), b"hello");
        assert_eq!(base64_decode("aGVs bG8=").unwrap(), b"hello");
        // Anything else is refused and names the byte.
        for bad in ["aGk!", "aGk*", "é", "aG.k"] {
            let e = base64_decode(bad).unwrap_err();
            assert!(e.starts_with("invalid base64 byte "), "{bad}: {e}");
        }
        assert_eq!(base64_decode("aGk!").unwrap_err(), "invalid base64 byte 33");
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
        // 4-byte big-endian length, then the JSON.
        let n = u32::from_be_bytes(buf[..4].try_into().unwrap()) as usize;
        assert_eq!(n, buf.len() - 4);
        assert_eq!(
            serde_json::from_slice::<Value>(&buf[4..]).unwrap()["op"],
            "exec"
        );
        let back: Request = read_frame(&mut &buf[..]).unwrap();
        assert_eq!(back.cmd, vec!["ls"]);
        assert_eq!(back.stdin, b"x");
        // Two frames back to back read one at a time.
        let mut two = buf.clone();
        write_frame(&mut two, &Response::exit(0, false)).unwrap();
        let mut r = &two[..];
        let _: Request = read_frame(&mut r).unwrap();
        let resp: Response = read_frame(&mut r).unwrap();
        assert_eq!(resp.kind, "exit");
        assert!(r.is_empty());
    }

    #[test]
    fn frames_sync_and_async_agree() {
        let resp = Response::chunk("stdout", b"out".to_vec());
        let encoded = encode_frame(&resp).unwrap();
        let mut written = Vec::new();
        write_frame(&mut written, &resp).unwrap();
        assert_eq!(encoded, written);
        let back: Response = decode_frame(&encoded[4..]).unwrap();
        assert_eq!(back.data, b"out");
        assert!(decode_frame::<Response>(b"{not json").is_err());
        assert!(decode_frame::<Response>(b"").is_err());
    }

    #[test]
    fn frame_of_zero_length() {
        // A length of zero is a frame with no JSON in it: an error, not a default value.
        let e = read_frame::<_, Request>(&mut &[0u8, 0, 0, 0][..]).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn frame_truncated() {
        let mut buf = Vec::new();
        write_frame(&mut buf, &Response::new("ok")).unwrap();
        // The header promises more than follows.
        let short = &buf[..buf.len() - 3];
        let e = read_frame::<_, Response>(&mut &short[..]).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);
        // Not even a whole header.
        let e = read_frame::<_, Response>(&mut &buf[..2]).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);
        assert!(read_frame::<_, Response>(&mut &[][..]).is_err());
    }

    #[test]
    fn frame_too_long_is_refused_before_reading_it() {
        // A header one past the limit is refused without allocating or reading the body.
        let hdr = ((MAX_FRAME + 1) as u32).to_be_bytes();
        let mut r = &hdr[..];
        let e = read_frame::<_, Response>(&mut r).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        assert_eq!(e.to_string(), "frame too large");
        assert!(
            r.is_empty(),
            "the header was consumed, nothing more was asked for"
        );
        let hdr = u32::MAX.to_be_bytes();
        assert!(read_frame::<_, Response>(&mut &hdr[..]).is_err());
    }

    /// A `get` request whose JSON is exactly `len` bytes.
    fn request_of_len(len: usize) -> Request {
        let base = serde_json::to_vec(&Request {
            op: "get".into(),
            ..Default::default()
        })
        .unwrap()
        .len();
        Request {
            op: "get".into(),
            path: "a".repeat(len - base),
            ..Default::default()
        }
    }

    #[test]
    fn frame_at_the_limit() {
        let at = request_of_len(MAX_FRAME);
        assert_eq!(serde_json::to_vec(&at).unwrap().len(), MAX_FRAME);
        let mut buf = Vec::new();
        write_frame(&mut buf, &at).unwrap();
        assert_eq!(buf.len(), 4 + MAX_FRAME);
        let back: Request = read_frame(&mut &buf[..]).unwrap();
        assert_eq!(back.path.len(), at.path.len());
        assert_eq!(encode_frame(&at).unwrap().len(), 4 + MAX_FRAME);

        // One byte more is refused by both writers.
        let over = request_of_len(MAX_FRAME + 1);
        let mut buf = Vec::new();
        let e = write_frame(&mut buf, &over).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        assert!(buf.is_empty(), "nothing is written for a refused frame");
        assert_eq!(
            encode_frame(&over).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
