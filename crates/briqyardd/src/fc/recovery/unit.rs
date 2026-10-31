//! A narrow effective-unit contract, with no environment-variable authority.
use super::fs::invalid;
#[cfg(target_os = "linux")]
use super::fs::{Dir, Owner};
#[cfg(target_os = "linux")]
use std::path::Path;
use std::{collections::BTreeMap, io};

pub(super) const PROPERTIES: &str = "Id,LoadState,ActiveState,SubState,MainPID,ControlPID,ControlGroup,InvocationID,KillMode,Delegate,ExecStart,Type,User,Group,RootDirectory,RootImage,PIDFile,RemainAfterExit,NeedDaemonReload,Slice,FragmentPath,DropInPaths";
pub(super) const GROUP: &str = "/system.slice/briqyardd.service";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Identity {
    pub(super) pid: u32,
    pub(super) invocation: String,
}

pub(super) fn validate(text: &str, pid: u32, hooks: &Hooks) -> io::Result<Identity> {
    if hooks.0 != [true; 6] {
        return Err(invalid());
    }
    let mut properties = BTreeMap::new();
    for line in text.lines() {
        let (key, value) = line.split_once('=').ok_or_else(invalid)?;
        if !PROPERTIES.split(',').any(|allowed| key == allowed)
            || properties.insert(key, value).is_some()
        {
            return Err(invalid());
        }
    }
    if properties.len() != PROPERTIES.split(',').count() {
        return Err(invalid());
    }
    for (key, value) in [
        ("Id", "briqyardd.service"),
        ("LoadState", "loaded"),
        ("ActiveState", "active"),
        ("SubState", "running"),
        ("ControlPID", "0"),
        ("ControlGroup", GROUP),
        ("KillMode", "process"),
        ("Delegate", "no"),
        ("Type", "simple"),
        ("RemainAfterExit", "no"),
        ("NeedDaemonReload", "no"),
        ("Slice", "system.slice"),
        ("FragmentPath", "/etc/systemd/system/briqyardd.service"),
    ] {
        if properties[key] != value {
            return Err(invalid());
        }
    }
    for key in ["RootDirectory", "RootImage", "PIDFile", "DropInPaths"] {
        if !properties[key].is_empty() {
            return Err(invalid());
        }
    }
    for key in ["User", "Group"] {
        if !matches!(properties[key], "" | "root") {
            return Err(invalid());
        }
    }
    if properties["MainPID"].parse::<u32>().ok() != Some(pid) {
        return Err(invalid());
    }
    let invocation = properties["InvocationID"];
    if invocation.len() != 32
        || !invocation
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        || invocation.bytes().all(|b| b == b'0')
    {
        return Err(invalid());
    }
    let command = properties["ExecStart"]
        .strip_prefix("{ ")
        .and_then(|s| s.strip_suffix(" }"))
        .ok_or_else(invalid)?;
    let mut fields = BTreeMap::new();
    for field in command.split(" ; ") {
        let (key, value) = field.split_once('=').ok_or_else(invalid)?;
        if fields.insert(key, value).is_some()
            || ![
                "path",
                "argv[]",
                "ignore_errors",
                "start_time",
                "stop_time",
                "pid",
                "code",
                "status",
            ]
            .contains(&key)
        {
            return Err(invalid());
        }
    }
    if fields.get("path") != Some(&"/usr/local/bin/briqyardd")
        || fields.get("argv[]")
            != Some(&"/usr/local/bin/briqyardd --config /etc/briqyard/config.yaml")
        || fields.get("ignore_errors") != Some(&"no")
    {
        return Err(invalid());
    }
    Ok(Identity {
        pid,
        invocation: invocation.into(),
    })
}

pub(super) fn self_start(stat: &str) -> io::Result<u64> {
    stat.rsplit_once(')')
        .and_then(|(_, tail)| tail.split_whitespace().nth(19))
        .and_then(|s| s.parse().ok())
        .ok_or_else(invalid)
}
#[cfg(target_os = "linux")]
pub(super) fn self_membership(proc: &Dir, start: u64) -> io::Result<()> {
    if self_start(&proc.text(c"stat", 4096)?)? != start
        || proc.text(c"cgroup", 4096)? != format!("0::{GROUP}\n")
    {
        return Err(invalid());
    }
    let cmd = proc.bytes(c"cmdline", 4096)?;
    if cmd != b"/usr/local/bin/briqyardd\0--config\0/etc/briqyard/config.yaml\0" {
        return Err(invalid());
    }
    Ok(())
}

pub(super) const HOOKS: [&str; 6] = [
    "ExecCondition",
    "ExecStartPre",
    "ExecStartPost",
    "ExecReload",
    "ExecStop",
    "ExecStopPost",
];
pub(super) struct Hooks([bool; 6]);
impl Hooks {
    pub(super) fn empty() -> Self {
        Self([false; 6])
    }
    pub(super) fn observe(&mut self, name: &str, text: &str) -> io::Result<()> {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Array {
            #[serde(rename = "type")]
            signature: String,
            data: Vec<()>,
        }
        let index = HOOKS
            .iter()
            .position(|hook| *hook == name)
            .ok_or_else(invalid)?;
        if self.0[index] || text.len() > 4096 {
            return Err(invalid());
        }
        let array: Array = serde_json::from_str(text).map_err(|_| invalid())?;
        if array.signature != "a(sasbttttuii)" || !array.data.is_empty() {
            return Err(invalid());
        }
        self.0[index] = true;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub(super) async fn query() -> anyhow::Result<(String, Hooks)> {
    let mut hooks = Hooks::empty();
    for name in HOOKS {
        let args = [
            "--system",
            "--no-pager",
            "--json=short",
            "get-property",
            "org.freedesktop.systemd1",
            "/org/freedesktop/systemd1/unit/briqyardd_2eservice",
            "org.freedesktop.systemd1.Service",
            name,
        ];
        hooks.observe(
            name,
            &output(std::ffi::OsStr::new("/usr/bin/busctl"), &args, 4096).await?,
        )?;
    }
    let args = [
        "--system",
        "--all",
        "--no-pager",
        "--no-ask-password",
        "--full",
        "show",
        "--property",
        PROPERTIES,
        "--",
        "briqyardd.service",
    ];
    Ok((
        output(std::ffi::OsStr::new("/usr/bin/systemctl"), &args, 16384).await?,
        hooks,
    ))
}

#[cfg(target_os = "linux")]
pub(super) async fn output(
    program: &std::ffi::OsStr,
    args: &[&str],
    cap: u64,
) -> anyhow::Result<String> {
    use std::{process::Stdio, time::Duration};
    use tokio::io::AsyncReadExt;
    let mut command = crate::host_process::command(program);
    command
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let mut child = command.spawn()?;
    let mut stdout = child.stdout.take().ok_or_else(invalid)?;
    let checked = tokio::time::timeout(Duration::from_secs(3), async {
        let mut bytes = Vec::new();
        (&mut stdout).take(cap + 1).read_to_end(&mut bytes).await?;
        if bytes.len() as u64 > cap || !child.wait().await?.success() {
            return Err(invalid());
        }
        String::from_utf8(bytes).map_err(|_| invalid())
    })
    .await;
    match checked {
        Ok(Ok(text)) => Ok(text),
        _ => {
            let _ = child.start_kill();
            tokio::time::timeout(Duration::from_secs(3), child.wait())
                .await
                .map_err(|_| invalid())??;
            Err(anyhow::anyhow!("bounded supervision helper failed"))
        }
    }
}

#[cfg(target_os = "linux")]
pub(super) fn actual_group(root: &Dir) -> io::Result<Dir> {
    let slice = root.child(c"system.slice")?;
    slice.owned(Owner::ROOT, false)?;
    let group = slice.child(c"briqyardd.service")?;
    group.owned(Owner::ROOT, false)?;
    Ok(group)
}

#[cfg(target_os = "linux")]
pub(super) fn root_cgroup() -> io::Result<Dir> {
    let root = Dir::absolute(Path::new("/sys/fs/cgroup"))?;
    root.owned(Owner::ROOT, false)?;
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
        if unsafe { libc::fstatfs(root.0.as_raw_fd(), stat.as_mut_ptr()) } != 0
            || unsafe { stat.assume_init() }.f_type != libc::CGROUP2_SUPER_MAGIC
        {
            return Err(invalid());
        }
    }
    Ok(root)
}

pub(super) fn jailer_version(jailer: &str, vmm: &str) -> io::Result<()> {
    if jailer.trim() != "Jailer v1.17.0" || !vmm.starts_with("v1.17.0/") {
        return Err(invalid());
    }
    Ok(())
}

pub(super) fn final_service_pids(members: &[u32], pid: u32, has_children: bool) -> io::Result<()> {
    if has_children || members != [pid] {
        return Err(invalid());
    }
    Ok(())
}
#[cfg(test)]
pub(super) fn final_service_members(text: &str, pid: u32, has_children: bool) -> io::Result<()> {
    final_service_pids(&super::fs::pids(text)?, pid, has_children)
}
