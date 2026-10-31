//! Host helpers reset supervisor OOM protection before exec.
pub(crate) fn command(program: impl AsRef<std::ffi::OsStr>) -> tokio::process::Command {
    briqyard_api::host_process::command(program).into()
}
