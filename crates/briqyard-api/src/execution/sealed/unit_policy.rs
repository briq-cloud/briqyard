//! The typed preimages an owner expects of a unit, and what each phase of the campaign shows
//! (erratum 2 §1, ADR 0149).
//!
//! A [`UnitPolicy`] is the closed preimage of a role's legacy and guarded effective unit as an
//! independent approval holds it: the raw fragment bytes, the command with its two typed
//! placeholders (`op` and `serial` of the approved transition), the sandbox projection and the
//! store policy. Sets arrive in any order and are sorted into their pinned canonical order;
//! duplicates, unknown fields and anything outside the closed forms refuse. Nothing here reads
//! a host: a measured answer is compared with these expectations, never turned into them.

use super::canonical::CodecError;
use super::inputs::{Listeners, Path, Program, Text};
use super::preimage::{
    fragment_digest, Argv, BindReadOnly, EnvAssignment, EnvFile, Families, FamilyMode, FdStore,
    NotifyAccess, Preserve, ProtectHome, ProtectSystem, Sandbox, SandboxFormat, MAX_ENTRIES,
    MAX_FRAGMENT_BYTES,
};
use super::prim::{Build, HexDigest, Ident, PosInt, Uint};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::Deserialize;

fn bad<T>(what: &'static str) -> Result<T, CodecError> {
    Err(CodecError::Value(what))
}

/// The approved transition's two fields a guarded command may carry.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transition {
    pub op: HexDigest,
    pub serial: PosInt,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
pub enum Field {
    #[serde(rename = "op")]
    Op,
    #[serde(rename = "serial")]
    Serial,
}

/// One argument of the primary command: a literal, or a typed field of the transition.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum Token {
    Literal(String),
    Placeholder {
        #[serde(rename = "x")]
        field: Field,
    },
}

/// `fragment`: the strict unpadded base64url of the raw file, then its SHA-256.
pub fn fragment_from_base64url(text: &str) -> Result<HexDigest, CodecError> {
    let raw = URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|_| CodecError::Value("base64url"))?;
    if URL_SAFE_NO_PAD.encode(&raw) != text || raw.len() > MAX_FRAGMENT_BYTES {
        return bad("fragment bytes");
    }
    fragment_digest(&raw)
}

/// The expanded command. A placeholder without a transition refuses.
pub fn argv_digest(
    exec: &str,
    template: &[Token],
    transition: Option<&Transition>,
) -> Result<HexDigest, CodecError> {
    let mut args = Vec::with_capacity(template.len());
    for token in template {
        args.push(match (token, transition) {
            (Token::Literal(text), _) => text.clone(),
            (Token::Placeholder { .. }, None) => return bad("placeholder outside a guarded unit"),
            (Token::Placeholder { field: Field::Op }, Some(x)) => x.op.as_str().to_owned(),
            (
                Token::Placeholder {
                    field: Field::Serial,
                },
                Some(x),
            ) => x.serial.get().to_string(),
        });
    }
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    Argv::new(exec, &refs)?.digest()
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FamiliesInput {
    pub mode: FamilyMode,
    pub names: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindInput {
    pub source: String,
    pub dest: String,
    pub recursive: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvInput {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvFileInput {
    pub path: String,
    pub optional: bool,
}

/// The sandbox projection as an approval states it: literal text, sets in any order.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxInput {
    pub uid: u64,
    pub gid: u64,
    pub supplementary_gids: Vec<u64>,
    pub umask: u64,
    pub dynamic_user: bool,
    pub no_new_privileges: bool,
    pub protect_system: ProtectSystem,
    pub protect_home: ProtectHome,
    pub private_tmp: bool,
    pub private_devices: bool,
    pub families: FamiliesInput,
    pub state_dirs: Vec<String>,
    pub state_dir_mode: u64,
    pub read_write: Vec<String>,
    pub read_only: Vec<String>,
    pub inaccessible: Vec<String>,
    pub bind_read_only: Vec<BindInput>,
    pub public_env: Vec<EnvInput>,
    pub env_files: Vec<EnvFileInput>,
}

fn sorted_set<T: Clone, K: Ord>(items: &[T], key: impl Fn(&T) -> K) -> Result<Vec<T>, CodecError> {
    if items.len() > MAX_ENTRIES {
        return bad("sandbox set too large");
    }
    let mut sorted = items.to_vec();
    sorted.sort_by_key(&key);
    if sorted.windows(2).any(|pair| key(&pair[0]) == key(&pair[1])) {
        return bad("duplicate set member");
    }
    Ok(sorted)
}

fn sorted_texts<T: Clone>(
    items: &[String],
    build: impl Fn(&str) -> Result<T, CodecError>,
) -> Result<Vec<T>, CodecError> {
    sorted_set(items, |text| text.as_bytes().to_vec())?
        .iter()
        .map(|text| build(text))
        .collect()
}

impl SandboxInput {
    /// The canonical projection: sets sorted (GIDs numerically, the rest by the bytes of their
    /// literals), binds and environment files in the manager's order, every closed rule applied.
    pub fn canonical(&self) -> Result<Sandbox, CodecError> {
        use super::canonical::Wire;
        let gids = sorted_set(&self.supplementary_gids, |gid| *gid)?
            .into_iter()
            .map(Uint::new)
            .collect::<Result<_, _>>()?;
        let sandbox = Sandbox {
            format: SandboxFormat::V1,
            uid: Uint::new(self.uid)?,
            gid: Uint::new(self.gid)?,
            supplementary_gids: gids,
            umask: Uint::new(self.umask)?,
            dynamic_user: self.dynamic_user,
            no_new_privileges: self.no_new_privileges,
            protect_system: self.protect_system,
            protect_home: self.protect_home,
            private_tmp: self.private_tmp,
            private_devices: self.private_devices,
            families: Families {
                mode: self.families.mode,
                names: sorted_texts(&self.families.names, |text| Ident::new(text))?,
            },
            state_dirs: sorted_texts(&self.state_dirs, |text| Ident::new(text))?,
            state_dir_mode: Uint::new(self.state_dir_mode)?,
            read_write: sorted_texts(&self.read_write, |text| Path::new(text))?,
            read_only: sorted_texts(&self.read_only, |text| Path::new(text))?,
            inaccessible: sorted_texts(&self.inaccessible, |text| Path::new(text))?,
            bind_read_only: self
                .bind_read_only
                .iter()
                .map(|bind| {
                    Ok(BindReadOnly {
                        source: Path::new(&bind.source)?,
                        dest: Path::new(&bind.dest)?,
                        recursive: bind.recursive,
                    })
                })
                .collect::<Result<_, CodecError>>()?,
            public_env: sorted_set(&self.public_env, |env| env.name.as_bytes().to_vec())?
                .iter()
                .map(|env| {
                    Ok(EnvAssignment {
                        name: Ident::new(&env.name)?,
                        value: Text::new(&env.value)?,
                    })
                })
                .collect::<Result<_, CodecError>>()?,
            env_files: self
                .env_files
                .iter()
                .map(|file| {
                    Ok(EnvFile {
                        path: Path::new(&file.path)?,
                        optional: file.optional,
                    })
                })
                .collect::<Result<_, CodecError>>()?,
        };
        sandbox.validate()?;
        Ok(sandbox)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreInput {
    pub preserve: Preserve,
    pub notify_access: NotifyAccess,
}

/// `fdstore`: the inner v3.6 listeners object and the store policy.
pub fn fdstore_digest(listeners: &Listeners, store: StoreInput) -> Result<HexDigest, CodecError> {
    FdStore::from_parts(listeners.clone(), store.preserve, store.notify_access).digest()
}

/// One effective unit's typed preimages.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnitSpec {
    pub fragment: String,
    pub exec: String,
    pub args: Vec<Token>,
    pub sandbox: SandboxInput,
    pub store: StoreInput,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnitPolicy {
    pub legacy: UnitSpec,
    pub guarded: UnitSpec,
}

/// The four commitments of one effective unit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnitDigests {
    pub fragment: HexDigest,
    pub argv: HexDigest,
    pub sandbox: HexDigest,
    pub fdstore: HexDigest,
}

impl UnitSpec {
    pub fn digests(
        &self,
        transition: Option<&Transition>,
        listeners: &Listeners,
    ) -> Result<UnitDigests, CodecError> {
        Ok(UnitDigests {
            fragment: fragment_from_base64url(&self.fragment)?,
            argv: argv_digest(&self.exec, &self.args, transition)?,
            sandbox: self.sandbox.canonical()?.digest()?,
            fdstore: fdstore_digest(listeners, self.store)?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
pub enum Phase {
    #[serde(rename = "prearm")]
    Prearm,
    #[serde(rename = "armed")]
    Armed,
    #[serde(rename = "launch")]
    Launch,
    #[serde(rename = "seal")]
    Seal,
    #[serde(rename = "launch_a")]
    LaunchA,
}

impl UnitPolicy {
    /// What the unit shows at `phase`: the installed file's bytes and the loaded command,
    /// sandbox and store. A guarded file may sit beside a still-legacy loaded unit until the
    /// common reload; the guarded loaded unit is expected from the launch on. The legacy unit
    /// carries no transition fields; the guarded one is expanded with the approved one.
    pub fn expected(
        &self,
        phase: Phase,
        transition: &Transition,
        listeners: &Listeners,
    ) -> Result<UnitDigests, CodecError> {
        let before = phase == Phase::Prearm;
        let installed = if before { &self.legacy } else { &self.guarded };
        let loaded_legacy = matches!(phase, Phase::Prearm | Phase::Armed);
        let loaded = if loaded_legacy {
            &self.legacy
        } else {
            &self.guarded
        };
        let x = |legacy: bool| if legacy { None } else { Some(transition) };
        let installed = installed.digests(x(before), listeners)?;
        let loaded = loaded.digests(x(loaded_legacy), listeners)?;
        Ok(UnitDigests {
            fragment: installed.fragment,
            ..loaded
        })
    }
}

/// Erratum 2 §3 for one role: the bootstrap guard and the staged candidate are the target
/// asset, the same bytes (digest and length) and the same approved build, at distinct paths.
pub fn same_target_asset(
    guard: &Program,
    candidate: &Program,
    target: &HexDigest,
    build: &Build,
) -> Result<(), CodecError> {
    let alike = guard.file.sha256 == *target
        && candidate.file.sha256 == *target
        && guard.file.bytes == candidate.file.bytes
        && guard.build == *build
        && candidate.build == *build;
    if !alike {
        return bad("program is not the target release asset");
    }
    if guard.file.path == candidate.file.path {
        return bad("guard and candidate share a path");
    }
    Ok(())
}
