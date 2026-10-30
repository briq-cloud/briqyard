//! Pull-through mirrors (ADR 0036).

use anyhow::{anyhow, Result};

/// A registry's pull-through mirror (ADR 0036): the registry it stands in for (`docker.io`,
/// as a reference names it) and its address as a registry name (`10.0.0.2:7440`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mirror {
    pub registry: String,
    pub host: String,
    pub plain_http: bool,
}

impl Mirror {
    /// `registry_mirrors` entry: `docker.io: http://10.0.0.2:7440`. A mirror is a registry
    /// of its own at the root of its address, so the URL has no path.
    pub fn parse(registry: &str, url: &str) -> Result<Mirror> {
        if registry.is_empty() || registry.contains(['/', ' ']) {
            return Err(anyhow!(
                "{registry:?} is not a registry name (docker.io, ghcr.io)"
            ));
        }
        let (plain_http, rest) = match (url.strip_prefix("http://"), url.strip_prefix("https://")) {
            (Some(rest), _) => (true, rest),
            (_, Some(rest)) => (false, rest),
            _ => return Err(anyhow!("{url:?}: want http:// or https://")),
        };
        let host = rest.trim_end_matches('/');
        if host.is_empty() || host.contains(['/', '?', '#', '@']) {
            return Err(anyhow!(
                "{url:?}: a mirror is a host and a port, with no path"
            ));
        }
        Ok(Mirror {
            registry: registry.to_string(),
            host: host.to_string(),
            plain_http,
        })
    }
}
