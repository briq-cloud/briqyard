//! The four commitments of an owner observation and an arm receipt: what each one hashes
//! (owner-layer erratum 2, ADR 0149).
//!
//! * `fragment`: SHA-256 of the raw installed unit file, nothing else.
//! * `argv`: `H(owner.argv/v1)`, the one primary command's whole ordered vector.
//! * `sandbox`: `H(owner.sandbox/v1)`, a closed projection of typed loaded properties.
//! * `fdstore`: `H(owner.fdstore/v1)`, the v3.6 listener object plus the store policy.
//!
//! These are pure preimage codecs. Nothing here reads a unit, asks a service manager or knows
//! what a host looks like: a value built here is a *claim about a preimage*, equal to another
//! only when both sides computed it from independent sources. Unknown, missing or duplicate
//! fields refuse, sets must be unique and in their pinned order, and a value that is not
//! positively proved is not representable (no default, no "unknown" variant).

use super::canonical::{h, CodecError, Wire};
use super::inputs::{Listeners, Path, Text};
use super::prim::{HexDigest, Ident, Uint};
use serde::{Deserialize, Serialize};

/// The raw unit file bound: the inherited 64 KiB message limit.
pub const MAX_FRAGMENT_BYTES: usize = 64 * 1024;
pub(super) const MAX_ENTRIES: usize = 64;

macro_rules! literal {
    ($(#[$meta:meta])* $name:ident, $text:literal) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
        pub enum $name {
            #[serde(rename = $text)]
            V1,
        }
    };
}

literal!(
    /// `owner.argv/v1`.
    ArgvFormat,
    "owner.argv/v1"
);
literal!(
    /// `owner.sandbox/v1`.
    SandboxFormat,
    "owner.sandbox/v1"
);
literal!(
    /// `owner.fdstore/v1`.
    FdStoreFormat,
    "owner.fdstore/v1"
);

fn bad<T>(what: &'static str) -> Result<T, CodecError> {
    Err(CodecError::Value(what))
}

/// `fragment`: `h(raw bytes)` of the installed unit file, first byte through EOF. No
/// normalization, parsing, drop-in merge or path is hashed; an empty or oversized file refuses.
pub fn fragment_digest(raw: &[u8]) -> Result<HexDigest, CodecError> {
    if raw.is_empty() || raw.len() > MAX_FRAGMENT_BYTES {
        return bad("unit fragment size");
    }
    Ok(HexDigest::of(raw))
}

/// `names = h(ASCII(join(names, ":")))`, empty bytes iff the vector is positively empty. The
/// names are in the order the manager delivers them, never sorted.
pub fn listener_names_digest(names: &[&str]) -> Result<HexDigest, CodecError> {
    let valid = names
        .iter()
        .all(|name| !name.is_empty() && name.bytes().all(|b| b.is_ascii_graphic() && b != b':'));
    if !valid || names.len() > MAX_ENTRIES {
        return bad("listener name");
    }
    let mut seen = std::collections::BTreeSet::new();
    if !names.iter().all(|name| seen.insert(*name)) {
        return bad("duplicate listener name");
    }
    Ok(HexDigest::of(names.join(":").as_bytes()))
}

/// `owner.argv/v1`: the primary command's executable and its entire argument vector, argv[0]
/// included, which in this profile is that executable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Argv {
    pub format: ArgvFormat,
    pub exec: Path,
    pub args: Vec<Text>,
}

impl Wire for Argv {
    fn validate(&self) -> Result<(), CodecError> {
        if self.args.is_empty() || self.args.len() > MAX_ENTRIES {
            return bad("argv length");
        }
        if self.args[0].as_str() != self.exec.as_str() {
            return bad("argv[0] is not the executable");
        }
        Ok(())
    }
}

impl Argv {
    pub fn new(exec: &str, args: &[&str]) -> Result<Self, CodecError> {
        let value = Self {
            format: ArgvFormat::V1,
            exec: Path::new(exec)?,
            args: args
                .iter()
                .map(|arg| Text::new(*arg))
                .collect::<Result<_, _>>()?,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn digest(&self) -> Result<HexDigest, CodecError> {
        self.validate()?;
        h(self)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtectSystem {
    #[serde(rename = "no")]
    No,
    #[serde(rename = "yes")]
    Yes,
    #[serde(rename = "full")]
    Full,
    #[serde(rename = "strict")]
    Strict,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtectHome {
    #[serde(rename = "no")]
    No,
    #[serde(rename = "yes")]
    Yes,
    #[serde(rename = "read-only")]
    ReadOnly,
    #[serde(rename = "tmpfs")]
    Tmpfs,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FamilyMode {
    #[serde(rename = "none")]
    None,
    #[serde(rename = "allow")]
    Allow,
    #[serde(rename = "deny")]
    Deny,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Families {
    pub mode: FamilyMode,
    pub names: Vec<Ident>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindReadOnly {
    pub source: Path,
    pub dest: Path,
    pub recursive: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvAssignment {
    pub name: Ident,
    pub value: Text,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvFile {
    pub path: Path,
    pub optional: bool,
}

/// `owner.sandbox/v1`: the closed loaded-property projection for this profile only. Order
/// rules: GIDs numeric, every other set by the bytes of its decoded literal, `bind_read_only`
/// and `env_files` in the manager's order, `public_env` by ASCII name.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sandbox {
    pub format: SandboxFormat,
    pub uid: Uint,
    pub gid: Uint,
    pub supplementary_gids: Vec<Uint>,
    pub umask: Uint,
    pub dynamic_user: bool,
    pub no_new_privileges: bool,
    pub protect_system: ProtectSystem,
    pub protect_home: ProtectHome,
    pub private_tmp: bool,
    pub private_devices: bool,
    pub families: Families,
    pub state_dirs: Vec<Ident>,
    pub state_dir_mode: Uint,
    pub read_write: Vec<Path>,
    pub read_only: Vec<Path>,
    pub inaccessible: Vec<Path>,
    pub bind_read_only: Vec<BindReadOnly>,
    pub public_env: Vec<EnvAssignment>,
    pub env_files: Vec<EnvFile>,
}

fn strictly_ascending<T, K: Ord>(items: &[T], key: impl Fn(&T) -> K) -> bool {
    items.windows(2).all(|pair| key(&pair[0]) < key(&pair[1]))
}

fn env_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    matches!(bytes.next(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'_'))
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn address_family(name: &str) -> bool {
    name.strip_prefix("AF_").is_some_and(|rest| {
        !rest.is_empty()
            && rest
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
    })
}

impl Wire for Sandbox {
    fn validate(&self) -> Result<(), CodecError> {
        let sizes = [
            self.supplementary_gids.len(),
            self.families.names.len(),
            self.state_dirs.len(),
            self.read_write.len(),
            self.read_only.len(),
            self.inaccessible.len(),
            self.bind_read_only.len(),
            self.public_env.len(),
            self.env_files.len(),
        ];
        if sizes.iter().any(|&n| n > MAX_ENTRIES) {
            return bad("sandbox set too large");
        }
        if self.umask.get() > 0o7777 || self.state_dir_mode.get() > 0o7777 {
            return bad("permission bits");
        }
        if !strictly_ascending(&self.supplementary_gids, |gid| gid.get()) {
            return bad("supplementary groups order");
        }
        let names = &self.families.names;
        let family_ok = match self.families.mode {
            FamilyMode::None => names.is_empty(),
            FamilyMode::Allow | FamilyMode::Deny => {
                !names.is_empty()
                    && strictly_ascending(names, |n| n.as_str().as_bytes().to_vec())
                    && names.iter().all(|n| address_family(n.as_str()))
            }
        };
        if !family_ok {
            return bad("address families");
        }
        let state_ok = strictly_ascending(&self.state_dirs, |n| n.as_str().as_bytes().to_vec())
            && self
                .state_dirs
                .iter()
                .all(|n| !n.as_str().contains('/') && n.as_str() != "." && n.as_str() != "..");
        if !state_ok {
            return bad("state directories");
        }
        for paths in [&self.read_write, &self.read_only, &self.inaccessible] {
            if !strictly_ascending(paths, |p| p.as_str().as_bytes().to_vec()) {
                return bad("path set order");
            }
        }
        let mut dests = std::collections::BTreeSet::new();
        if !self
            .bind_read_only
            .iter()
            .all(|b| dests.insert(b.dest.as_str()))
        {
            return bad("duplicate bind destination");
        }
        let env_ok = strictly_ascending(&self.public_env, |e| e.name.as_str().as_bytes().to_vec())
            && self.public_env.iter().all(|e| env_name(e.name.as_str()));
        if !env_ok {
            return bad("public environment");
        }
        let mut files = std::collections::BTreeSet::new();
        if !self.env_files.iter().all(|f| files.insert(f.path.as_str())) {
            return bad("duplicate environment file");
        }
        Ok(())
    }
}

impl Sandbox {
    pub fn digest(&self) -> Result<HexDigest, CodecError> {
        self.validate()?;
        h(self)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Preserve {
    #[serde(rename = "no")]
    No,
    #[serde(rename = "restart")]
    Restart,
    #[serde(rename = "yes")]
    Yes,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NotifyAccess {
    #[serde(rename = "none")]
    None,
    #[serde(rename = "main")]
    Main,
}

/// `owner.fdstore/v1`: the v3.6 `Listeners` object of the retained ordinary vector and the
/// store policy. A descriptor number is never part of it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FdStore {
    pub format: FdStoreFormat,
    pub listeners: Listeners,
    pub preserve: Preserve,
    pub notify_access: NotifyAccess,
}

impl Wire for FdStore {
    fn validate(&self) -> Result<(), CodecError> {
        let empty = HexDigest::of(b"");
        if (self.listeners.count.get() == 0) != (self.listeners.names == empty) {
            return bad("listener count and names disagree about emptiness");
        }
        Ok(())
    }
}

impl FdStore {
    /// The inner v3.6 object as an approval or a measurement states it.
    pub fn from_parts(
        listeners: Listeners,
        preserve: Preserve,
        notify_access: NotifyAccess,
    ) -> Self {
        Self {
            format: FdStoreFormat::V1,
            listeners,
            preserve,
            notify_access,
        }
    }

    /// `names` are the retained ordinary vector in qualified delivery order.
    pub fn new(
        names: &[&str],
        store_max: u64,
        preserve: Preserve,
        notify_access: NotifyAccess,
    ) -> Result<Self, CodecError> {
        let value = Self {
            format: FdStoreFormat::V1,
            listeners: Listeners {
                count: Uint::new(names.len() as u64)?,
                names: listener_names_digest(names)?,
                store_max: Uint::new(store_max)?,
            },
            preserve,
            notify_access,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn digest(&self) -> Result<HexDigest, CodecError> {
        self.validate()?;
        h(self)
    }
}
