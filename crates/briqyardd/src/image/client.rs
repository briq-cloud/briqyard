//! The registry client.

use oci_client::client::{ClientConfig, ClientProtocol};
use oci_client::manifest::{ImageIndexEntry, Platform};

/// How long a registry or a mirror may stay silent on a connection (each read, so a slow blob
/// is not cut). Above Zot's `syncTimeout` (10 minutes, `hack/mirror/zot.json`): a mirror's first
/// pull of an image copies it before answering. A mirror silent past it is left for the registry.
pub(super) const READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15 * 60);

/// The registry client: HTTPS except to the `plain` hosts; a connect that does not complete
/// within 10 s, or a connection silent for `read_timeout`, fails that source.
pub(super) fn client_config(plain: Vec<String>, read_timeout: std::time::Duration) -> ClientConfig {
    ClientConfig {
        platform_resolver: Some(Box::new(host_platform)),
        protocol: if plain.is_empty() {
            ClientProtocol::Https
        } else {
            ClientProtocol::HttpsExcept(plain)
        },
        connect_timeout: Some(std::time::Duration::from_secs(10)),
        read_timeout: Some(read_timeout),
        ..Default::default()
    }
}

pub(super) fn host_platform(entries: &[ImageIndexEntry]) -> Option<String> {
    let arch = match std::env::consts::ARCH {
        "aarch64" => "arm64",
        "x86_64" => "amd64",
        other => other,
    };
    entries
        .iter()
        .find(|e| matches!(&e.platform, Some(Platform { os, architecture, .. }) if os == "linux" && architecture == arch))
        .map(|e| e.digest.clone())
}
