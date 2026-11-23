//! What root custody reads back from the plan reader socket: one untrusted reply, decoded
//! strictly. None of it may panic, and nothing that decodes may fail to re-encode identically.
#![no_main]

use briqyard_api::execution::sealed::{
    decode, encode,
    plan_pin::{Read, ReadPair, TrustRecord},
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(pair) = decode::<ReadPair>(data) {
        assert_eq!(encode(&pair).unwrap(), data);
    }
    if let Ok(read) = decode::<Read>(data) {
        assert_eq!(encode(&read).unwrap(), data);
    }
    if let Ok(record) = decode::<TrustRecord>(data) {
        assert_eq!(encode(&record).unwrap(), data);
        let _ = record.pinned();
    }
});
