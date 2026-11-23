use super::{Class, Member, Signer};
use briqyard_api::execution::sealed::custody::Resource;

/// The most rights one packet may carry: the authority's 22 (16 prefix rights, then the six
/// suffix rights), also the daemon's maximum (18 + admin TLS pair + S3 + file key). The socket
/// owner sizes its ancillary buffer from this and rejects anything longer.
pub const MAX_ASSET_RIGHTS: usize = 22;

/// What the frozen startup profile requires beyond the fixed prefix. The caller derives it
/// from the validated closure and effective frozen configuration; a missing file or credential
/// is never evidence that a feature is disabled. The authority has no optional suffix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Requirements {
    Daemon {
        admin_tls: bool,
        backup_s3: bool,
        file_key: bool,
    },
    Authority,
}

impl Requirements {
    pub fn resource(self) -> Resource {
        match self {
            Self::Daemon { .. } => Resource::Daemon,
            Self::Authority => Resource::Authority,
        }
    }

    /// Prefix indices 0..=12 (daemon) or 0..=14 and the ordinary key at 15 (authority) never
    /// move; the v3.3 suffix follows them in its fixed order.
    pub fn classes(self) -> Vec<Class> {
        let mut classes = vec![
            Class::Plan,
            Class::Launch,
            Class::Grant,
            Class::Inputs,
            Class::Candidate,
            Class::Config,
            Class::CaptureLoad,
            Class::Member(Member::Hi),
            Class::Member(Member::He),
        ];
        let signer = match self {
            Self::Daemon { .. } => Signer::Hk,
            Self::Authority => {
                classes.extend([Class::Member(Member::Ni), Class::Member(Member::Ng)]);
                Signer::Ak
            }
        };
        classes.extend([
            Class::Member(Member::Tr),
            Class::Signer(signer),
            Class::TlsCert,
            Class::TlsKey,
        ]);
        if self == Self::Authority {
            classes.push(Class::OrdinaryAuthorityKey);
        }
        classes.extend([
            Class::VerificationRegistry,
            Class::TransitionServerCert,
            Class::TransitionServerKey,
            Class::TransitionClientCert,
            Class::TransitionClientKey,
        ]);
        match self {
            Self::Authority => classes.push(Class::ContinuationBearer),
            Self::Daemon {
                admin_tls,
                backup_s3,
                file_key,
            } => {
                if admin_tls {
                    classes.extend([Class::DaemonApiCert, Class::DaemonApiKey]);
                }
                if backup_s3 {
                    classes.push(Class::BackupS3Pair);
                }
                if file_key {
                    classes.push(Class::LocalPoolKey);
                }
            }
        }
        classes
    }
}
