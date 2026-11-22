use clap::{Args, ValueEnum};
use std::path::PathBuf;

#[derive(Clone, Copy, ValueEnum)]
enum ResourceChoice {
    Daemon,
    Authority,
}

#[derive(Args)]
pub(super) struct Options {
    #[arg(long, value_enum)]
    resource: ResourceChoice,
    #[arg(long)]
    operation_dir: PathBuf,
}

#[derive(Clone, Copy)]
pub(super) enum Mode {
    Guard,
    Custodian,
}

impl Options {
    #[cfg(target_os = "linux")]
    fn refusal(&self, mode: Mode) -> &'static str {
        use briqyard_api::execution::sealed::custody::Resource;
        use briqyardd::execution_custody::sealed_input::OperationDirectory;

        let resource = match (mode, self.resource) {
            (_, ResourceChoice::Daemon) => Resource::Daemon,
            (Mode::Custodian, ResourceChoice::Authority) => Resource::Authority,
            (Mode::Guard, ResourceChoice::Authority) => return "resource_not_supported_by_guard",
        };
        if OperationDirectory::parse(resource, &self.operation_dir).is_err() {
            return "invalid_operation_directory";
        }
        "protected_startup_inputs_unavailable"
    }

    pub(super) fn refuse(&self, mode: Mode) -> ! {
        #[cfg(target_os = "linux")]
        let reason = self.refusal(mode);
        #[cfg(not(target_os = "linux"))]
        let reason = match (mode, self.resource, &self.operation_dir) {
            _ => "sealed_start_requires_linux",
        };
        eprintln!(r#"{{"event":"sealed_start_refused","reason":"{reason}"}}"#);
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests;
