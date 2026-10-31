//! One served OpenAPI document, assembled in order from coherent source fragments.
pub const OPENAPI: &str = concat!(
    include_str!("../../../api/openapi/00-routes.fragment.yaml"),
    include_str!("../../../api/openapi/10-machines.fragment.yaml"),
    include_str!("../../../api/openapi/20-hosts.fragment.yaml"),
);
