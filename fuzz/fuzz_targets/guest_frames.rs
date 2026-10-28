//! What the daemon reads from a guest's init over vsock: exec output to its exit, the exit
//! report, any answer frame. A guest is untrusted: none of it may panic the daemon.
#![no_main]

use briqyard_api::guest::{self, ExitReport, Response};
use briqyardd::guestc;
use futures::executor::block_on;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = block_on(guestc::collect(&mut &data[..]));
    let _ = block_on(guestc::read_frame::<_, ExitReport>(&mut &data[..]));
    let _ = guest::read_frame::<_, Response>(&mut &data[..]);
    let _ = guest::decode_frame::<Response>(data);
});
