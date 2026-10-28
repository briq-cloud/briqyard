//! A guest's DNS query on its gateway: dropped or answered, and every answer parses back.
#![no_main]

use briqyardd::netw::dns;
use hickory_proto::op::Message;
use libfuzzer_sys::fuzz_target;
use std::net::Ipv4Addr;

fuzz_target!(|data: &[u8]| {
    let Some(query) = dns::parse_query(data) else {
        return;
    };
    let _ = dns::query_name(&query);
    for ip in [Some(Ipv4Addr::LOCALHOST), None] {
        if let Some(answer) = dns::build_answer(&query, ip) {
            assert!(
                Message::from_vec(&answer).is_ok(),
                "our answer does not parse"
            );
        }
    }
});
