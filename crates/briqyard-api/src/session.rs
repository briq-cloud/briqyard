//! An exec session (ADR 0029): a command whose stdin, stdout and stderr stream over a
//! WebSocket, on a terminal of its own with `tty`. `GET /v1/machines/{id}/exec` with the
//! upgrade headers and [`ExecSession`] in the query; then every message is binary, its first
//! byte a [`channel`], the rest the payload, as Kubernetes' `v5.channel.k8s.io`.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The first byte of every message.
pub mod channel {
    /// To the command's stdin (client to server).
    pub const STDIN: u8 = 0;
    /// What it prints: the terminal's output with `tty`.
    pub const STDOUT: u8 = 1;
    /// Empty with `tty`: a terminal has one output.
    pub const STDERR: u8 = 2;
    /// The last message from the server: a [`super::SessionEnd`] as JSON.
    pub const EXIT: u8 = 3;
    /// A [`super::Resize`] as JSON (client to server).
    pub const RESIZE: u8 = 4;
    /// The client closed a stream: the payload is the channel, [`STDIN`] (its end of input).
    pub const CLOSE: u8 = 255;
}

/// What a session runs: the query of its upgrade request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecSession {
    pub cmd: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub cwd: String,
    /// The command's deadline; 0 is none: the session lasts as long as its connection.
    pub timeout_ms: u64,
    /// Wake a sleeping machine for the session (the default), as the JSON exec does.
    pub wake: bool,
    /// Run the command on a pseudo-terminal: one output, the size below, `TERM` from `env`
    /// (`xterm` when absent).
    pub tty: bool,
    /// The terminal's size at the start; 0 is 80 columns, 24 rows.
    pub cols: u16,
    pub rows: u16,
}

impl Default for ExecSession {
    fn default() -> Self {
        Self {
            cmd: Vec::new(),
            env: BTreeMap::new(),
            cwd: String::new(),
            timeout_ms: 0,
            wake: true,
            tty: false,
            cols: 0,
            rows: 0,
        }
    }
}

impl ExecSession {
    /// The query pairs: `cmd` and `env` (`K=V`) once per item, the rest once when not the
    /// default.
    pub fn to_query(&self) -> Vec<(&'static str, String)> {
        let mut q: Vec<(&'static str, String)> =
            self.cmd.iter().map(|c| ("cmd", c.clone())).collect();
        q.extend(self.env.iter().map(|(k, v)| ("env", format!("{k}={v}"))));
        let d = Self::default();
        if self.cwd != d.cwd {
            q.push(("cwd", self.cwd.clone()));
        }
        if self.timeout_ms != d.timeout_ms {
            q.push(("timeout_ms", self.timeout_ms.to_string()));
        }
        if self.wake != d.wake {
            q.push(("wake", self.wake.to_string()));
        }
        if self.tty != d.tty {
            q.push(("tty", self.tty.to_string()));
        }
        if self.cols != d.cols {
            q.push(("cols", self.cols.to_string()));
        }
        if self.rows != d.rows {
            q.push(("rows", self.rows.to_string()));
        }
        q
    }

    /// Reads the query pairs back. An unknown key or a value that does not parse is refused
    /// by name: a mistyped `tty` must not give a session without a terminal.
    pub fn from_query<K, V>(pairs: impl IntoIterator<Item = (K, V)>) -> Result<Self, String>
    where
        K: AsRef<str>,
        V: AsRef<str>,
    {
        fn num<T: std::str::FromStr>(k: &str, v: &str) -> Result<T, String> {
            v.parse()
                .map_err(|_| format!("{k}={v:?}: want a number in range"))
        }
        fn flag(k: &str, v: &str) -> Result<bool, String> {
            match v {
                "true" => Ok(true),
                "false" => Ok(false),
                _ => Err(format!("{k}={v:?}: want true or false")),
            }
        }
        let mut s = Self::default();
        for (k, v) in pairs {
            let (k, v) = (k.as_ref(), v.as_ref());
            match k {
                "cmd" => s.cmd.push(v.to_string()),
                "env" => {
                    let (name, value) = v
                        .split_once('=')
                        .filter(|(n, _)| !n.is_empty())
                        .ok_or_else(|| format!("env={v:?}: want NAME=VALUE"))?;
                    s.env.insert(name.to_string(), value.to_string());
                }
                "cwd" => s.cwd = v.to_string(),
                "timeout_ms" => s.timeout_ms = num(k, v)?,
                "wake" => s.wake = flag(k, v)?,
                "tty" => s.tty = flag(k, v)?,
                "cols" => s.cols = num(k, v)?,
                "rows" => s.rows = num(k, v)?,
                other => {
                    return Err(format!(
                        "{other:?} is not a session parameter: cmd, env, cwd, timeout_ms, wake, tty, cols, rows"
                    ))
                }
            }
        }
        if s.cmd.is_empty() {
            return Err("cmd is required".into());
        }
        Ok(s)
    }
}

/// A terminal's new size, on [`channel::RESIZE`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resize {
    pub cols: u16,
    pub rows: u16,
}

/// The last message of a session, on [`channel::EXIT`]: how the command ended, or, with
/// `code` set, why the session ended without it (`code` and `error` as an `ApiError`'s).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionEnd {
    #[serde(default)]
    pub exit_code: i32,
    #[serde(default)]
    pub timed_out: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub code: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error: String,
}

impl SessionEnd {
    pub fn failed(code: &str, error: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            error: error.into(),
            ..Default::default()
        }
    }
}

/// A message: the channel byte, then the payload.
pub fn message(channel: u8, payload: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(1 + payload.len());
    m.push(channel);
    m.extend_from_slice(payload);
    m
}

/// A message's channel and payload; `None` for an empty message.
pub fn parse(message: &[u8]) -> Option<(u8, &[u8])> {
    message.split_first().map(|(c, rest)| (*c, rest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn query(pairs: &[(&str, &str)]) -> Result<ExecSession, String> {
        ExecSession::from_query(pairs.iter().copied())
    }

    #[test]
    fn query_round_trip() {
        let s = ExecSession {
            cmd: vec!["sh".into(), "-c".into(), "echo a=b".into()],
            env: [("TERM".to_string(), "xterm-256color".to_string())].into(),
            cwd: "/work".into(),
            timeout_ms: 5000,
            wake: false,
            tty: true,
            cols: 120,
            rows: 40,
        };
        let q = s.to_query();
        assert_eq!(
            q,
            vec![
                ("cmd", "sh".to_string()),
                ("cmd", "-c".into()),
                ("cmd", "echo a=b".into()),
                ("env", "TERM=xterm-256color".into()),
                ("cwd", "/work".into()),
                ("timeout_ms", "5000".into()),
                ("wake", "false".into()),
                ("tty", "true".into()),
                ("cols", "120".into()),
                ("rows", "40".into()),
            ]
        );
        assert_eq!(ExecSession::from_query(q).unwrap(), s);
    }

    #[test]
    fn query_defaults() {
        // Only the command goes out when nothing else is asked; it reads back the same.
        let s = ExecSession {
            cmd: vec!["cat".into()],
            ..Default::default()
        };
        assert_eq!(s.to_query(), vec![("cmd", "cat".to_string())]);
        let back = query(&[("cmd", "cat")]).unwrap();
        assert_eq!(back, s);
        assert!(back.wake && !back.tty && back.timeout_ms == 0);
        // An env value may hold `=`; only the first one splits.
        let s = query(&[("cmd", "env"), ("env", "A=b=c")]).unwrap();
        assert_eq!(s.env["A"], "b=c");
    }

    #[test]
    fn query_refusals() {
        assert_eq!(query(&[]).unwrap_err(), "cmd is required");
        assert_eq!(query(&[("tty", "true")]).unwrap_err(), "cmd is required");
        let e = query(&[("cmd", "sh"), ("ty", "true")]).unwrap_err();
        assert!(e.starts_with("\"ty\" is not a session parameter"), "{e}");
        assert_eq!(
            query(&[("cmd", "sh"), ("tty", "yes")]).unwrap_err(),
            "tty=\"yes\": want true or false"
        );
        assert_eq!(
            query(&[("cmd", "sh"), ("cols", "70000")]).unwrap_err(),
            "cols=\"70000\": want a number in range"
        );
        assert_eq!(
            query(&[("cmd", "sh"), ("env", "=x")]).unwrap_err(),
            "env=\"=x\": want NAME=VALUE"
        );
        assert!(query(&[("cmd", "sh"), ("env", "NOVALUE")]).is_err());
    }

    #[test]
    fn channels() {
        // Kubernetes' numbers: a client written for one reads the other.
        use channel::*;
        assert_eq!(
            [STDIN, STDOUT, STDERR, EXIT, RESIZE, CLOSE],
            [0, 1, 2, 3, 4, 255]
        );
        let m = message(STDOUT, b"hi");
        assert_eq!(m, [1, b'h', b'i']);
        assert_eq!(parse(&m), Some((STDOUT, &b"hi"[..])));
        assert_eq!(parse(&[CLOSE, STDIN]), Some((CLOSE, &[STDIN][..])));
        assert_eq!(parse(&[EXIT]), Some((EXIT, &[][..])));
        assert_eq!(parse(&[]), None);
    }

    #[test]
    fn end_and_resize_on_the_wire() {
        let e = SessionEnd {
            exit_code: 3,
            ..Default::default()
        };
        assert_eq!(
            serde_json::to_value(&e).unwrap(),
            json!({"exit_code": 3, "timed_out": false})
        );
        let f = SessionEnd::failed("not_running", "the machine went down during the command");
        assert_eq!(
            serde_json::to_value(&f).unwrap(),
            json!({"exit_code": 0, "timed_out": false, "code": "not_running",
                   "error": "the machine went down during the command"})
        );
        let back: SessionEnd = serde_json::from_value(json!({"exit_code": 137})).unwrap();
        assert_eq!(back.exit_code, 137);
        let r: Resize = serde_json::from_value(json!({"cols": 100, "rows": 30})).unwrap();
        assert_eq!(
            r,
            Resize {
                cols: 100,
                rows: 30
            }
        );
        assert!(serde_json::from_value::<Resize>(json!({"cols": 100})).is_err());
    }
}
