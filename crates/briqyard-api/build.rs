//! The commit this build is made from, for `VERSION` (ADR 0027): `BRIQYARD_COMMIT` when the
//! build sets it (a release built outside a checkout), else git's, else `unknown`.

use std::path::Path;
use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (out.status.success() && !s.is_empty()).then_some(s)
}

fn main() {
    println!("cargo:rerun-if-env-changed=BRIQYARD_COMMIT");
    let commit = std::env::var("BRIQYARD_COMMIT")
        .ok()
        .filter(|c| !c.is_empty())
        .or_else(|| git(&["rev-parse", "--short=12", "HEAD"]))
        .unwrap_or_else(|| "unknown".into());
    // A commit moves HEAD or the branch it names: a loose ref, else the packed ones.
    if let Some(head) = git(&["rev-parse", "--git-path", "HEAD"]) {
        println!("cargo:rerun-if-changed={head}");
    }
    if let Some(branch) = git(&["symbolic-ref", "-q", "HEAD"]) {
        let loose = git(&["rev-parse", "--git-path", &branch]).filter(|p| Path::new(p).exists());
        if let Some(p) = loose.or_else(|| git(&["rev-parse", "--git-path", "packed-refs"])) {
            println!("cargo:rerun-if-changed={p}");
        }
    }
    println!("cargo:rustc-env=BRIQYARD_COMMIT={commit}");
}
