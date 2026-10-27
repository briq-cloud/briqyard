//! A public client's request head at the HTTP ingress: a host, more to read, or a refusal.
#![no_main]

use briqyardd::ingress::{parse_head, Head};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Head::Host(host) = parse_head(data) {
        assert!(!host.is_empty(), "routed by an empty host");
        assert_eq!(host, host.to_ascii_lowercase());
    }
});
