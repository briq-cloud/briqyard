//! Immutable startup evidence, not a startup authorization. The caller must independently
//! establish the durable grant consumption, peer and kernel custody, process profile, and
//! manifest policy before acting. Record fields alone do not prove a live process or readiness.

use super::artifacts::{BoundAssets, Class, Descriptor, FrozenArtifact, Member as AssetMember};
use super::{CustodyError, StageDeadline};
use briqyard_api::execution::sealed::{
    custody::{Capture, LoadBody, Resource},
    decode, h,
    objects::Plan,
    prim::{HexDigest, PosInt},
    sig::{PinnedKey, Role, Sig, Tag},
    transition::{LGrant, LKind, Launch, LaunchStage, Member, Secrets},
    CodecError, Wire,
};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CaptureLoad {
    capture: Capture,
    load: Sig<LoadBody>,
}

impl Wire for CaptureLoad {
    fn validate(&self) -> Result<(), CodecError> {
        self.capture.validate()?;
        self.load.validate()
    }
}

/// The lexical selector only. Filesystem traversal and ownership still need a pinned dirfd.
pub struct OperationDirectory {
    resource: Resource,
    op: HexDigest,
    serial: PosInt,
}

impl OperationDirectory {
    pub fn parse(resource: Resource, path: &Path) -> Result<Self, CustodyError> {
        let (prefix, leaf) = match resource {
            Resource::Daemon => ("/var/lib/briqyard/sealed-ops/", "/daemon"),
            Resource::Authority => (
                "/var/lib/briq-execution-authority/sealed-ops/",
                "/authority",
            ),
        };
        let invalid = || CustodyError::Protocol("invalid sealed operation directory");
        let (op, serial) = path
            .to_str()
            .and_then(|path| path.strip_prefix(prefix)?.strip_suffix(leaf))
            .and_then(|scope| scope.split_once('/'))
            .ok_or_else(invalid)?;
        let op = HexDigest::new(op).map_err(|_| invalid())?;
        let parsed = PosInt::new(serial.parse().map_err(|_| invalid())?).map_err(|_| invalid())?;
        if parsed.get().to_string() != serial {
            return Err(invalid());
        }
        Ok(Self {
            resource,
            op,
            serial: parsed,
        })
    }
}

/// Exact byte digests from a separately parsed, validated manifest. These do not attest
/// the source, ownership, TLS endpoint identity, or possession of the signing key.
pub struct ConfigTlsPins {
    pub config: HexDigest,
    pub cert: HexDigest,
    pub key: HexDigest,
}

pub struct SealedInput {
    assets: BoundAssets,
    plan: Plan,
    launch: Launch,
    grant: LGrant,
    custody: CaptureLoad,
    inputs: Vec<u8>,
}

impl SealedInput {
    /// The expected plan hash must come from the caller's independent operation record, not
    /// the offer, Launch, or argv. This consumes the original FD/offer binding and preserves it.
    pub fn decode(
        assets: BoundAssets,
        directory: &OperationDirectory,
        expected_plan_hash: &HexDigest,
        deadline: StageDeadline,
    ) -> Result<Self, CustodyError> {
        let read = |class| {
            assets
                .artifact(class)
                .ok_or(CustodyError::Protocol("missing startup artifact"))?
                .read_small(deadline)
        };
        let plan_bytes = read(Class::Plan)?;
        let plan: Plan = decode(&plan_bytes)
            .map_err(|_| CustodyError::Protocol("invalid startup plan record"))?;
        let plan_hash = HexDigest::of(&plan_bytes);
        if plan_hash != *expected_plan_hash {
            return Err(CustodyError::Protocol("startup plan commitment"));
        }
        if directory.op != plan.x.op || directory.serial != plan.x.serial {
            return Err(CustodyError::Protocol("startup operation directory scope"));
        }
        let resource = directory.resource;
        assets
            .offer()
            .check_plan_pins(resource, &plan)
            .map_err(|_| CustodyError::Protocol("startup asset plan pins"))?;
        let launch: Launch = decode(&read(Class::Launch)?)
            .map_err(|_| CustodyError::Protocol("invalid startup launch record"))?;
        let (action, old) = match resource {
            Resource::Daemon => (LKind::LaunchD, &plan.pre_d),
            Resource::Authority => (LKind::LaunchA, &plan.pre_a),
        };
        if launch.x != plan.x
            || launch.plan != plan_hash
            || launch.resource != resource
            || launch.stage != LaunchStage::Consumed
            || launch.old != *old
        {
            return Err(CustodyError::Protocol("startup launch scope or stage"));
        }

        let rk = PinnedKey::new(Role::Rk, *plan.rk.as_array())
            .map_err(|_| CustodyError::Protocol("invalid startup receiver key"))?;
        let bk = PinnedKey::new(Role::Bk, *plan.bk.as_array())
            .map_err(|_| CustodyError::Protocol("invalid startup API key"))?;
        let grant: LGrant = decode(&read(Class::Grant)?)
            .map_err(|_| CustodyError::Protocol("invalid startup grant record"))?;
        let decision = grant
            .verify(&rk, &bk)
            .map_err(|_| CustodyError::Protocol("startup grant signatures"))?;
        if decision.action != action {
            return Err(CustodyError::Protocol("startup grant action"));
        }
        decision
            .check_launch(&launch)
            .map_err(|_| CustodyError::Protocol("startup grant launch scope"))?;
        if decision.nonce == launch.nonce {
            return Err(CustodyError::Protocol("startup grant reuses capture nonce"));
        }

        let custody: CaptureLoad = decode(&read(Class::CaptureLoad)?)
            .map_err(|_| CustodyError::Protocol("invalid startup capture/load record"))?;
        let capture = custody
            .capture
            .verify(Tag::CustodyCapture, &rk)
            .map_err(|_| CustodyError::Protocol("startup capture signature"))?;
        launch
            .check_capture(&capture.wire)
            .map_err(|_| CustodyError::Protocol("startup capture launch scope"))?;
        let load = custody
            .load
            .verify(Tag::CustodyLoad, &rk)
            .map_err(|_| CustodyError::Protocol("startup load signature"))?;
        let launch_hash = launch
            .hash()
            .map_err(|_| CustodyError::Protocol("startup launch hash"))?;
        let capture_hash =
            h(&custody.capture).map_err(|_| CustodyError::Protocol("startup capture hash"))?;
        if load.x != launch.x
            || load.plan != launch.plan
            || load.resource != resource
            || load.owner != launch.owner
            || load.launch != launch_hash
            || load.capture != capture_hash
        {
            return Err(CustodyError::Protocol(
                "startup load launch or capture scope",
            ));
        }

        for descriptor in assets.offer().descriptors() {
            let Class::Member(class) = descriptor.class() else {
                continue;
            };
            let expected = match class {
                AssetMember::Hi => Member::Hi,
                AssetMember::He => Member::He,
                AssetMember::Ni => Member::Ni,
                AssetMember::Ng => Member::Ng,
                AssetMember::Tr => Member::Tr,
            };
            let secret: Secrets = decode(&read(Class::Member(class))?)
                .map_err(|_| CustodyError::Protocol("invalid startup member envelope"))?;
            if secret.member != expected {
                return Err(CustodyError::Protocol("startup member role"));
            }
            secret
                .check_plan(&plan_hash, &plan)
                .and_then(|()| secret.check_members(&plan.new))
                .map_err(|_| CustodyError::Protocol("startup member scope or digest"))?;
        }

        let inputs = read(Class::Inputs)?;
        deadline.check()?;
        Ok(Self {
            assets,
            plan,
            launch,
            grant,
            custody,
            inputs,
        })
    }

    pub fn plan(&self) -> &Plan {
        &self.plan
    }

    pub fn launch(&self) -> &Launch {
        &self.launch
    }

    pub fn grant(&self) -> &LGrant {
        &self.grant
    }

    pub fn capture(&self) -> &Capture {
        &self.custody.capture
    }

    pub fn load(&self) -> &Sig<LoadBody> {
        &self.custody.load
    }

    /// Only the bytes are pinned; their schema and live facts are not interpreted here.
    pub fn inputs_bytes(&self) -> &[u8] {
        &self.inputs
    }

    pub fn artifact(&self, class: Class) -> Option<&FrozenArtifact> {
        self.assets.artifact(class)
    }

    /// Binding already hashed the exact immutable bytes of each original descriptor.
    /// Compare those bound digests, not another file opened by path or an offer supplied later.
    pub fn check_config_tls_pins(&self, pins: &ConfigTlsPins) -> Result<(), CustodyError> {
        for descriptor in self.assets.offer().descriptors() {
            let (actual, expected) = match descriptor {
                Descriptor::Config { digest, .. } => (digest, &pins.config),
                Descriptor::TlsCert { digest, .. } => (digest, &pins.cert),
                Descriptor::TlsKey { digest, .. } => (digest, &pins.key),
                _ => continue,
            };
            if actual != expected {
                return Err(CustodyError::Protocol("startup config or TLS pin"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
