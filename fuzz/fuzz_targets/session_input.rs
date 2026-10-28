//! What an exec session's client sends: the query that opens it and its messages.
#![no_main]

use briqyard_api::session::ExecSession;
use briqyardd::session;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = session::input(data);
    let _ = ExecSession::from_query(url::form_urlencoded::parse(data));
});
