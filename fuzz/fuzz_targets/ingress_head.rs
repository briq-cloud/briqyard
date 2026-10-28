//! A public client's request head at the HTTP ingress: a host, more to read, or a refusal.
#![no_main]

use briqyardd::ingress::{parse_head, Head, MAX_HEAD};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Head::Host(host) = parse_head(data) {
        assert!(!host.is_empty(), "routed by an empty host");
        assert_eq!(host, host.to_ascii_lowercase());
    }
    // Inputs stay far under MAX_HEAD: the input repeated past it is never a head still arriving.
    if !data.is_empty() {
        let long: Vec<u8> = data.iter().copied().cycle().take(MAX_HEAD + 1).collect();
        assert!(
            !matches!(parse_head(&long), Head::Partial),
            "read on past MAX_HEAD"
        );
    }
});
