//! Release-pin and checksum/asset validation over explicitly supplied bytes.
//!
//! Nothing here opens an installed pin, follows provenance, downloads a release, picks a
//! tag or treats a checksum entry as a delivery right. The caller separately establishes
//! that the pin file is the independently installed and reviewed one for the version it
//! selected; this module only checks that the bytes it was handed agree with each other.

use super::{Git, HexDigest, PosInt, Release, Version};
use crate::execution::sealed::canonical::{CodecError, MAX_MESSAGE_BYTES};
use serde::Deserialize;
use std::collections::BTreeMap;

const DAEMON_KEY: &str = "briqyardd-linux-x86_64";
const FLEET_KEY: &str = "briqyard-fleet-linux-x86_64";
const CLI_KEY: &str = "briqyard-linux-x86_64";
const SOURCE_PREFIX: &str = "https://github.com/briq-cloud/briqyard/releases/tag/v";

/// One selected release's three public x86_64 binaries, supplied by the caller.
pub struct ReleaseAssets<'a> {
    pub daemon: &'a [u8],
    pub fleet: &'a [u8],
    pub cli: &'a [u8],
}

/// The equality result of a pin file, its checksum list and its three assets. It is not an
/// approval, a delivery permit or evidence that the pin file itself is the reviewed one.
#[derive(Debug)]
pub struct VerifiedRelease {
    manifest: Release,
    daemon_asset_bytes: u64,
    fleet_asset_bytes: u64,
}

/// The closed five-field shape of `release-pins/<version>.json`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PinFile {
    release: Version,
    commit: Git,
    #[serde(rename = "releaseId")]
    release_id: PosInt,
    sha256: AssetPins,
    source: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AssetPins {
    #[serde(rename = "SHA256SUMS-x86_64")]
    sums: HexDigest,
    #[serde(rename = "briqyardd-linux-x86_64")]
    daemon: HexDigest,
    #[serde(rename = "briqyard-fleet-linux-x86_64")]
    fleet: HexDigest,
    #[serde(rename = "briqyard-linux-x86_64")]
    cli: HexDigest,
}

impl VerifiedRelease {
    /// Parse the five-field pin file (duplicate, unknown and missing keys refuse), require
    /// its source to be the tag URL of its own version, `sums` to be the digest of the supplied
    /// checksum list, exactly one list entry for each required binary equal to its pinned
    /// digest, and each supplied binary to hash to it. Other entries in the list are ignored
    /// and add no right.
    pub fn validate(
        pin_file: &[u8],
        checksum_list: &[u8],
        assets: ReleaseAssets<'_>,
    ) -> Result<Self, CodecError> {
        let manifest = parse_pin(pin_file)?;
        if HexDigest::of(checksum_list) != manifest.sums {
            return Err(CodecError::Value("checksum list digest"));
        }
        let entries = parse_checksum_list(checksum_list)?;
        for (name, digest, bytes) in [
            (DAEMON_KEY, &manifest.daemon, assets.daemon),
            (FLEET_KEY, &manifest.fleet, assets.fleet),
            (CLI_KEY, &manifest.cli, assets.cli),
        ] {
            if entries.get(name) != Some(digest) {
                return Err(CodecError::Value("checksum entry"));
            }
            if HexDigest::of(bytes) != *digest {
                return Err(CodecError::Value("release asset digest"));
            }
        }
        Ok(Self {
            manifest,
            daemon_asset_bytes: assets.daemon.len() as u64,
            fleet_asset_bytes: assets.fleet.len() as u64,
        })
    }

    pub fn release(&self) -> &Release {
        &self.manifest
    }

    pub(super) fn daemon_asset_bytes(&self) -> u64 {
        self.daemon_asset_bytes
    }

    pub(super) fn fleet_asset_bytes(&self) -> u64 {
        self.fleet_asset_bytes
    }
}

/// The pin file's shape and self-consistency only: `pin_file` is the digest of the raw bytes,
/// including any final line feed.
pub(super) fn parse_pin(pin_file: &[u8]) -> Result<Release, CodecError> {
    if pin_file.is_empty() || pin_file.len() > MAX_MESSAGE_BYTES {
        return Err(CodecError::TooLarge);
    }
    let pin: PinFile = serde_json::from_slice(pin_file).map_err(|_| CodecError::Schema)?;
    if pin.source != format!("{SOURCE_PREFIX}{}", pin.release) {
        return Err(CodecError::Value("release source"));
    }
    Ok(Release {
        version: pin.release,
        commit: pin.commit,
        release_id: pin.release_id,
        pin_file: HexDigest::of(pin_file),
        sums: pin.sha256.sums,
        daemon: pin.sha256.daemon,
        fleet: pin.sha256.fleet,
        cli: pin.sha256.cli,
    })
}

/// `<64 lowercase hex>␠␠<name>\n` rows, a final line feed, ASCII names without controls, no
/// duplicate name, and the three required names present.
fn parse_checksum_list(bytes: &[u8]) -> Result<BTreeMap<&str, HexDigest>, CodecError> {
    let text = std::str::from_utf8(bytes).map_err(|_| CodecError::Value("checksum list"))?;
    if !text.ends_with('\n') {
        return Err(CodecError::Value("checksum list"));
    }
    let mut entries = BTreeMap::new();
    for line in text.split_terminator('\n') {
        let (digest, name) = line
            .split_once("  ")
            .ok_or(CodecError::Value("checksum row"))?;
        let valid_name = !name.is_empty()
            && name.bytes().all(|b| b.is_ascii_graphic() || b == b' ')
            && !name.starts_with(' ');
        if !valid_name || entries.insert(name, HexDigest::new(digest)?).is_some() {
            return Err(CodecError::Value("checksum row"));
        }
    }
    for required in [DAEMON_KEY, FLEET_KEY, CLI_KEY] {
        if !entries.contains_key(required) {
            return Err(CodecError::Value("checksum entry"));
        }
    }
    Ok(entries)
}
