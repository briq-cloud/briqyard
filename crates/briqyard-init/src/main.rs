//! briqyard-init is PID 1 inside every machine. It prepares the guest from the config drive,
//! runs the image's command, serves the host over vsock, and halts when the command ends.
//! Linux only; the real source is in init/.

#[cfg(target_os = "linux")]
mod init;

fn main() {
    #[cfg(target_os = "linux")]
    init::main();
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("briqyard-init only runs on Linux");
        std::process::exit(2);
    }
}

/// A test binary ends with its parent, and in bounded time (briqyard-testing).
#[cfg(test)]
#[ctor::ctor(unsafe)]
fn exit_with_parent() {
    briqyard_testing::exit_with_parent();
}
