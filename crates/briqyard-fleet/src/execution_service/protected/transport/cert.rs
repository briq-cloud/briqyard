//! The private identity certificate profile lives in `briqyard_api::execution::private_cert`,
//! shared with the host's sealed-asset checks so there is one validator.

pub(crate) use briqyard_api::execution::private_cert::{
    key_spki_digest, parse, verify, CertError, Leaf, Usage,
};
