use super::*;

pub(super) fn build_env(env: &BTreeMap<String, String>) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = env.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    if !env.contains_key("PATH") {
        out.push((
            "PATH".into(),
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into(),
        ));
    }
    if !env.contains_key("HOME") {
        out.push(("HOME".into(), "/root".into()));
    }
    out
}

pub(super) fn main_command(st: &State) -> Result<Command> {
    let cfg = &st.cfg;
    let mut argv: Vec<String> = cfg.entrypoint.clone();
    argv.extend(cfg.cmd.iter().cloned());
    if argv.is_empty() {
        return Err(anyhow!("the image has no entrypoint or command"));
    }
    let path = look_path(&argv[0], &st.env)?;
    let mut cmd = Command::new(path);
    cmd.args(&argv[1..]);
    cmd.env_clear();
    cmd.envs(st.env.iter().map(|(k, v)| (k, v)));
    cmd.current_dir(if cfg.workdir.is_empty() {
        "/"
    } else {
        &cfg.workdir
    });
    cmd.stdin(Stdio::null());
    let console = fs::OpenOptions::new()
        .write(true)
        .open("/dev/console")
        .context("/dev/console")?;
    cmd.stdout(Stdio::from(console.try_clone()?));
    cmd.stderr(Stdio::from(console));
    cmd.process_group(0);
    if !cfg.user.is_empty() {
        let (uid, gid, home) = lookup_user(&cfg.user)?;
        run_as(cmd.as_std_mut(), uid, gid, supplementary_groups(uid));
        if let Some(h) = home {
            cmd.env("HOME", h);
        }
    }
    cmd.kill_on_drop(false);
    Ok(cmd)
}

/// Runs the command as `uid`, `gid` and `groups` (none clears root's own). The child drops
/// root itself, in the only order that works: `setgroups` and `setgid` while still root,
/// `setuid` last. Not std's `Command::uid` and `gid`: std switches to the user before any
/// `pre_exec`, where a `setgroups` then fails with EPERM; std's own `groups` is unstable (#90747).
pub(super) fn run_as(cmd: &mut std::process::Command, uid: u32, gid: u32, groups: Vec<u32>) {
    use std::os::unix::process::CommandExt;
    // SAFETY: only async-signal-safe calls between fork and exec; `groups` is built before.
    unsafe {
        cmd.pre_exec(move || {
            if libc::setgroups(groups.len(), groups.as_ptr()) < 0
                || libc::setgid(gid) < 0
                || libc::setuid(uid) < 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

pub(super) fn look_path(name: &str, env: &[(String, String)]) -> Result<String> {
    if name.contains('/') {
        return Ok(name.to_string());
    }
    let path = env
        .iter()
        .find(|(k, _)| k == "PATH")
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    for dir in path.split(':') {
        let p = Path::new(dir).join(name);
        if let Ok(m) = fs::metadata(&p) {
            if !m.is_dir() {
                return Ok(p.to_string_lossy().into_owned());
            }
        }
    }
    Err(anyhow!("{name}: not found in PATH"))
}

pub(super) fn read_table(path: &str) -> Vec<Vec<String>> {
    parse_table(&fs::read_to_string(path).unwrap_or_default())
}

/// A passwd or group file: one row per line, colon-separated; comments and blank lines skipped.
pub(super) fn parse_table(text: &str) -> Vec<Vec<String>> {
    text.lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.split(':').map(String::from).collect())
        .collect()
}

/// Resolves "name", "uid", "name:group" or "uid:gid" through /etc/passwd and /etc/group.
pub(super) fn lookup_user(spec: &str) -> Result<(u32, u32, Option<String>)> {
    lookup_user_in(spec, &read_table("/etc/passwd"), &read_table("/etc/group"))
}

/// `lookup_user` against the given passwd and group rows. Returns uid, gid and the home
/// directory when the user has a passwd entry.
pub(super) fn lookup_user_in(
    spec: &str,
    passwd: &[Vec<String>],
    groups: &[Vec<String>],
) -> Result<(u32, u32, Option<String>)> {
    let (user, group) = match spec.split_once(':') {
        Some((u, g)) => (u, Some(g)),
        None => (spec, None),
    };
    let mut found = None;
    for row in passwd {
        if row.len() >= 7 && (row[0] == user || row[2] == user) {
            let uid: u32 = row[2].parse().unwrap_or(0);
            let gid: u32 = row[3].parse().unwrap_or(0);
            found = Some((uid, gid, Some(row[5].clone())));
            break;
        }
    }
    let (uid, mut gid, home) = match found {
        Some(f) => f,
        None => {
            let n: u32 = user
                .parse()
                .map_err(|_| anyhow!("user {user:?} not found"))?;
            (n, n, None)
        }
    };
    if let Some(g) = group {
        gid = match groups
            .iter()
            .find(|r| r.len() >= 3 && (r[0] == g || r[2] == g))
        {
            Some(r) => r[2].parse().unwrap_or(gid),
            None => g.parse().map_err(|_| anyhow!("group {g:?} not found"))?,
        };
    }
    Ok((uid, gid, home))
}

pub(super) fn supplementary_groups(uid: u32) -> Vec<u32> {
    supplementary_groups_in(uid, &read_table("/etc/passwd"), &read_table("/etc/group"))
}

/// The groups that list the user with this uid as a member.
pub(super) fn supplementary_groups_in(
    uid: u32,
    passwd: &[Vec<String>],
    groups: &[Vec<String>],
) -> Vec<u32> {
    let name = match passwd
        .iter()
        .find(|r| r.len() >= 3 && r[2] == uid.to_string())
    {
        Some(r) => r[0].clone(),
        None => return vec![],
    };
    groups
        .iter()
        .filter(|r| r.len() >= 4 && r[3].split(',').any(|m| m == name))
        .filter_map(|r| r[2].parse().ok())
        .collect()
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::init::testutil::*;

    // --- users and groups ---

    const PASSWD: &str = "root:x:0:0:root:/root:/bin/sh\n\
        # a comment\n\
        \n\
        postgres:x:999:999::/var/lib/postgresql:/bin/sh\n\
        short:x:7\n\
        nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n";
    const GROUP: &str = "root:x:0:\n\
        postgres:x:999:\n\
        docker:x:120:postgres,alice\n\
        staff:x:50:alice\n";

    fn lookup(spec: &str) -> Result<(u32, u32, Option<String>)> {
        lookup_user_in(spec, &parse_table(PASSWD), &parse_table(GROUP))
    }

    #[test]
    fn tables() {
        let t = parse_table(PASSWD);
        assert_eq!(t.len(), 4, "comments and blank lines are skipped");
        assert_eq!(t[0][0], "root");
        assert_eq!(t[2], vec!["short", "x", "7"]);
        assert!(parse_table("").is_empty());
    }

    #[test]
    fn user_lookup() {
        assert_eq!(lookup("root").unwrap(), (0, 0, Some("/root".into())));
        assert_eq!(
            lookup("postgres").unwrap(),
            (999, 999, Some("/var/lib/postgresql".into()))
        );
        // A uid finds its passwd row too, home included.
        assert_eq!(lookup("999").unwrap(), lookup("postgres").unwrap());
        assert_eq!(lookup("0").unwrap(), lookup("root").unwrap());
        // A numeric user with no row: uid and gid alike, no home.
        assert_eq!(lookup("1000").unwrap(), (1000, 1000, None));
        assert_eq!(lookup("1000:1001").unwrap(), (1000, 1001, None));
        // A short passwd row is ignored rather than read out of bounds: its name is unknown
        // and its uid falls back to the numeric rule.
        assert!(lookup("short").is_err());
        assert_eq!(lookup("7").unwrap(), (7, 7, None));
    }

    #[test]
    fn user_lookup_with_group() {
        let home = Some("/var/lib/postgresql".to_string());
        assert_eq!(lookup("postgres:docker").unwrap(), (999, 120, home.clone()));
        assert_eq!(lookup("postgres:0").unwrap(), (999, 0, home.clone()));
        assert_eq!(lookup("999:root").unwrap(), (999, 0, home.clone()));
        // A numeric group with no row is taken as is.
        assert_eq!(lookup("postgres:5000").unwrap(), (999, 5000, home));
    }

    #[test]
    fn user_lookup_errors() {
        for (spec, what) in [
            ("alice", "user \"alice\" not found"),
            ("", "user \"\" not found"),
            ("alice:root", "user \"alice\" not found"),
            ("postgres:nogroup", "group \"nogroup\" not found"),
            ("postgres:", "group \"\" not found"),
        ] {
            let e = lookup(spec).unwrap_err().to_string();
            assert_eq!(e, what, "{spec}");
        }
    }

    #[test]
    fn supplementary_groups_of_a_user() {
        let passwd = parse_table(PASSWD);
        let groups = parse_table(GROUP);
        assert_eq!(supplementary_groups_in(999, &passwd, &groups), vec![120]);
        assert!(supplementary_groups_in(65534, &passwd, &groups).is_empty());
        assert!(
            supplementary_groups_in(1000, &passwd, &groups).is_empty(),
            "no passwd row"
        );
        // Membership is by name, exact: "alice" is not "alic".
        let mut p = passwd.clone();
        p.push(
            "alic:x:2000:2000::/home/alic:/bin/sh"
                .split(':')
                .map(String::from)
                .collect(),
        );
        assert!(supplementary_groups_in(2000, &p, &groups).is_empty());
    }

    /// The user, group and groups a process started by `run_as` has, from its
    /// `/proc/self/status`.
    fn ids_run_as(uid: u32, gid: u32, groups: Vec<u32>) -> [String; 3] {
        let mut cmd = std::process::Command::new("cat");
        cmd.arg("/proc/self/status").stdout(Stdio::piped());
        run_as(&mut cmd, uid, gid, groups);
        let child = spawn_tracked(&mut cmd);
        let pid = child.id() as i32;
        let out = child.wait_with_output();
        untrack(pid);
        let status = String::from_utf8(out.expect("started").stdout).unwrap();
        ["Uid:", "Gid:", "Groups:"].map(|k| {
            let line = status.lines().find(|l| l.starts_with(k)).unwrap();
            line[k.len()..]
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        })
    }

    /// v0.1.1 could not start a user with supplementary groups (grafana, n8n): the groups
    /// were set after the user, as the user. Changing users needs root:
    /// `sudo <test binary> --ignored run_as` (CI runs it).
    #[test]
    #[ignore = "needs root"]
    fn run_as_sets_the_groups_before_the_user() {
        assert_eq!(
            ids_run_as(65534, 65534, vec![100, 65534]),
            [
                "65534 65534 65534 65534",
                "65534 65534 65534 65534",
                "100 65534"
            ]
        );
        // No supplementary group: root's own are dropped.
        assert_eq!(ids_run_as(65534, 100, vec![])[1..], ["100 100 100 100", ""]);
    }

    // --- the environment and the command ---

    #[test]
    fn environment_defaults() {
        let env = build_env(&BTreeMap::new());
        assert_eq!(
            env,
            vec![
                (
                    "PATH".to_string(),
                    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string()
                ),
                ("HOME".to_string(), "/root".to_string()),
            ]
        );
        // The image's values win and come first.
        let mut image = BTreeMap::new();
        image.insert("PATH".to_string(), "/app/bin".to_string());
        image.insert("HOME".to_string(), "/app".to_string());
        image.insert("A".to_string(), "1".to_string());
        let env = build_env(&image);
        assert_eq!(env.len(), 3);
        assert!(env.contains(&("PATH".to_string(), "/app/bin".to_string())));
        assert!(env.contains(&("HOME".to_string(), "/app".to_string())));
        assert!(env.contains(&("A".to_string(), "1".to_string())));
    }

    #[test]
    fn path_lookup() {
        let root = tempfile::tempdir().unwrap();
        let bin = root.path().join("bin");
        let sbin = root.path().join("sbin");
        fs::create_dir_all(&bin).unwrap();
        fs::create_dir_all(&sbin).unwrap();
        write(&bin.join("tool"), b"", 0o755);
        write(&sbin.join("tool"), b"", 0o755);
        fs::create_dir(bin.join("adir")).unwrap();
        write(&sbin.join("adir"), b"", 0o755);
        let env = vec![(
            "PATH".to_string(),
            format!("{}:{}", bin.display(), sbin.display()),
        )];
        // First directory wins; a directory of that name is not a command.
        assert_eq!(
            look_path("tool", &env).unwrap(),
            bin.join("tool").to_string_lossy()
        );
        assert_eq!(
            look_path("adir", &env).unwrap(),
            sbin.join("adir").to_string_lossy()
        );
        // A path is taken as given, found or not.
        assert_eq!(look_path("/x/y", &env).unwrap(), "/x/y");
        assert_eq!(look_path("./y", &env).unwrap(), "./y");
        let e = look_path("missing", &env).unwrap_err().to_string();
        assert_eq!(e, "missing: not found in PATH");
        assert!(look_path("tool", &[]).is_err(), "no PATH, nothing found");
    }
}
