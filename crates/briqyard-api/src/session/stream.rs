//! Version one of finite-input, non-terminal exec streaming.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const MAX_MESSAGE: usize = 1 << 20;
pub const MAX_STDIN: usize = 512 << 10;

/// First text message after upgrading `/v1/machines/{id}/exec/stream/v1`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Start {
    pub cmd: Vec<String>,
    #[serde(default, deserialize_with = "unique_env")]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub cwd: String,
    pub timeout_ms: u64,
    #[serde(default = "wake_default")]
    pub wake: bool,
    #[serde(default)]
    pub stdin: String,
    #[serde(default)]
    pub interactive: bool,
}
fn unique_env<'de, D: serde::Deserializer<'de>>(
    de: D,
) -> Result<BTreeMap<String, String>, D::Error> {
    struct Unique;
    impl<'de> serde::de::Visitor<'de> for Unique {
        type Value = BTreeMap<String, String>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("unique environment names")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut map: A,
        ) -> Result<Self::Value, A::Error> {
            let mut env = BTreeMap::new();
            while let Some((key, value)) = map.next_entry::<String, String>()? {
                if env.insert(key, value).is_some() {
                    return Err(serde::de::Error::custom("duplicate environment name"));
                }
                if env.len() > 256 {
                    return Err(serde::de::Error::custom("too many environment names"));
                }
            }
            Ok(env)
        }
    }
    de.deserialize_map(Unique)
}

fn wake_default() -> bool {
    true
}
impl Start {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.interactive {
            return Err("interactive must be false");
        }
        if self.timeout_ms == 0 || self.timeout_ms > 3_600_000 {
            return Err("timeout_ms must be positive and at most 3600000");
        }
        if self.cmd.is_empty()
            || self.cmd.len() > 256
            || self.cmd[0].is_empty()
            || self
                .cmd
                .iter()
                .any(|v| v.contains('\0') || v.len() > 32_768)
            || self.cmd.iter().map(String::len).sum::<usize>() > 131_072
        {
            return Err("invalid command bounds");
        }
        if self.cwd.len() > 4096
            || self.cwd.contains('\0')
            || (!self.cwd.is_empty() && !self.cwd.starts_with('/'))
        {
            return Err("invalid cwd");
        }
        if self.env.len() > 256
            || self.env.iter().any(|(k, v)| {
                k.is_empty()
                    || k.contains(['=', '\0'])
                    || v.contains('\0')
                    || k.len() > 4096
                    || v.len() > 32_768
            })
            || self
                .env
                .iter()
                .map(|(k, v)| k.len() + v.len())
                .sum::<usize>()
                > 131_072
        {
            return Err("invalid environment bounds");
        }
        if self.stdin.len() > MAX_STDIN {
            return Err("stdin exceeds finite input limit");
        }
        Ok(())
    }
    pub fn into_guest(self) -> crate::guest::Request {
        crate::guest::Request {
            op: "exec_stream_v1".into(),
            cmd: self.cmd,
            env: self.env,
            cwd: self.cwd,
            timeout_ms: self.timeout_ms,
            stdin: self.stdin.into_bytes(),
            ..Default::default()
        }
    }
}

/// The only client message accepted after Start. Repeated cancellation is harmless.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, tag = "action", rename_all = "snake_case")]
pub enum Control {
    Cancel,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn finite_request_bounds_and_defaults() {
        assert!(
            serde_json::from_str::<Start>(r#"{"cmd":["cat"],"cmd":["sh"],"timeout_ms":1}"#)
                .is_err()
        );
        assert!(serde_json::from_str::<Start>(
            r#"{"cmd":["cat"],"timeout_ms":1,"env":{"A":"1","A":"2"}}"#
        )
        .is_err());
        let mut s: Start = serde_json::from_str(r#"{"cmd":["cat"],"timeout_ms":1}"#).unwrap();
        assert!(s.validate().is_ok());
        assert!(s.stdin.is_empty());
        s.timeout_ms = 0;
        assert!(s.validate().is_err());
        s.timeout_ms = 3_600_001;
        assert!(s.validate().is_err());
        s.timeout_ms = 1;
        s.interactive = true;
        assert!(s.validate().is_err());
        s.interactive = false;
        s.stdin = "x".repeat(MAX_STDIN + 1);
        assert!(s.validate().is_err());
        assert!(
            serde_json::from_str::<Start>(r#"{"cmd":["cat"],"timeout_ms":1,"tty":true}"#).is_err()
        );
        assert!(serde_json::from_str::<Control>(r#"{"action":"data"}"#).is_err());
    }
}
