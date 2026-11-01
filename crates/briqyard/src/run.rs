//! `run`: one command, one call.

use super::*;

pub(super) const NONE: Option<&()> = None;

pub(super) async fn run(c: &Client, cmd: Cmd) -> Result<()> {
    use reqwest::Method;
    const GET: Method = Method::GET;
    const POST: Method = Method::POST;
    const PUT: Method = Method::PUT;
    const DELETE: Method = Method::DELETE;
    match cmd {
        Cmd::WarmPool(command) => warm::run(c, command).await?,
        Cmd::Status => print_json(&c.call::<api::Status>(GET, "/v1/status", NONE).await?),
        Cmd::Openapi => print!("{}", c.raw(GET, "/v1/openapi.yaml", NONE).await?),
        Cmd::Machine(m) => match *m {
            MachineCmd::Ls { namespace, labels } => {
                let path = machines_path(namespace.as_deref(), &labels);
                let ms: Vec<api::Machine> = c.call(GET, &path, NONE).await?;
                print!("{}", machine_table(&ms));
            }
            MachineCmd::Run(a) => {
                let name = a.name.clone().unwrap_or_else(|| {
                    let base = a.image.rsplit('/').next().unwrap_or(&a.image);
                    let base = base.split([':', '@']).next().unwrap_or(base);
                    format!("{base}-{}", suffix())
                });
                let env = env_args(&a.envs)?;
                let files = file_args(&a.files)?;
                let volume = match &a.volume {
                    Some(v) => {
                        let (size, mount) = v.split_once(':').ok_or_else(|| {
                            anyhow!("--volume {v:?}: want SIZE:MOUNT, like 10G:/data")
                        })?;
                        let gb: u32 = size
                            .trim_end_matches("GB")
                            .trim_end_matches('G')
                            .parse()
                            .map_err(|_| anyhow!("--volume {v:?}: bad size"))?;
                        Some(api::VolumeSpec {
                            size_gb: gb,
                            mount: mount.to_string(),
                        })
                    }
                    None => None,
                };
                let req = api::CreateMachineRequest {
                    namespace: a.namespace.clone(),
                    name,
                    image: a.image.clone(),
                    entrypoint: if a.entrypoint.is_empty() {
                        None
                    } else {
                        Some(a.entrypoint.clone())
                    },
                    cmd: if a.cmd.is_empty() {
                        None
                    } else {
                        Some(a.cmd.clone())
                    },
                    env,
                    files,
                    size: api::Size {
                        vcpus: a.vcpus,
                        memory_mb: a.memory,
                        cpu_millis: a.cpu_millis,
                    },
                    volume,
                    ports: a.ports.clone(),
                    sleep: a.sleep.clone(),
                    restart: None,
                    metadata: label_args(&a.labels)?,
                    region: a.region.clone(),
                    egress: a.egress.clone(),
                    limits: a.limits.request()?,
                    disk_limits: a.disk.request()?,
                    backup: a.backup.request()?,
                    probes: Some(api::Probes {
                        startup: a.startup.clone(),
                        readiness: a.readiness.clone(),
                        liveness: a.liveness.clone(),
                    })
                    .filter(|p| !p.is_empty()),
                    start: if a.no_start { Some(false) } else { None },
                    fork: None,
                    restore: None,
                    template_build: a.template_build.clone(),
                };
                let m: api::Machine = c.call(POST, "/v1/machines", Some(&req)).await?;
                let m = match a.detach || a.no_start {
                    true => m,
                    false => c.running(m).await?,
                };
                print_json(&m);
                if m.state == api::state::ERROR {
                    bail!("{}", m.error);
                }
            }
            MachineCmd::Get { id } => print_json(
                &c.call::<api::Machine>(GET, &format!("/v1/machines/{id}"), NONE)
                    .await?,
            ),
            MachineCmd::Describe { id } => {
                let m: api::Machine = c.call(GET, &format!("/v1/machines/{id}"), NONE).await?;
                // By its namespace: through a fleet, that is the machine's host.
                let path = events_path(Some(&m.namespace), Some(&m.id), false);
                let (mut evs, _) = c.events(&path, None).await?;
                let keep = evs.len().saturating_sub(20);
                print!("{}", describe(&m, &evs.split_off(keep)));
            }
            MachineCmd::Start { id } => print_json(
                &c.call::<api::Machine>(POST, &format!("/v1/machines/{id}/start"), NONE)
                    .await?,
            ),
            MachineCmd::Stop { suspend, id } => {
                let req = api::StopRequest {
                    suspend,
                    timeout_sec: 0,
                };
                print_json(
                    &c.call::<api::Machine>(POST, &format!("/v1/machines/{id}/stop"), Some(&req))
                        .await?,
                )
            }
            MachineCmd::Restart { id } => print_json(
                &c.call::<api::Machine>(POST, &format!("/v1/machines/{id}/restart"), NONE)
                    .await?,
            ),
            MachineCmd::Wake { id } => print_json(
                &c.call::<api::Machine>(POST, &format!("/v1/machines/{id}/wake"), NONE)
                    .await?,
            ),
            MachineCmd::Touch { id } => {
                c.raw(POST, &format!("/v1/machines/{id}/touch"), NONE)
                    .await?;
            }
            MachineCmd::Wait { until, id } => print_json(
                &c.call::<api::Machine>(
                    POST,
                    &format!("/v1/machines/{id}/wait?timeout=120&for={until}"),
                    NONE,
                )
                .await?,
            ),
            MachineCmd::Rm { id } => {
                c.raw(DELETE, &format!("/v1/machines/{id}"), NONE).await?;
            }
            MachineCmd::Exec {
                no_wake,
                timeout,
                interactive,
                tty,
                id,
                cmd,
            } => {
                // 0 is the daemon's default: 5 minutes for a command, none for a session.
                let timeout_ms = timeout.map_or(0, |t| t.as_millis() as u64);
                if interactive || tty {
                    let req = api::session::ExecSession {
                        cmd,
                        wake: !no_wake,
                        timeout_ms,
                        tty,
                        ..Default::default()
                    };
                    let code = session::run(c, &id, req, interactive).await?;
                    if code != 0 {
                        std::process::exit(code);
                    }
                    return Ok(());
                }
                let req = api::ExecRequest {
                    cmd,
                    wake: !no_wake,
                    timeout_ms,
                    ..Default::default()
                };
                let res: api::ExecResult = c
                    .call(POST, &format!("/v1/machines/{id}/exec"), Some(&req))
                    .await?;
                print!("{}", res.stdout);
                eprint!("{}", res.stderr);
                std::io::stdout().flush()?;
                if res.timed_out {
                    eprintln!("(timed out)");
                }
                if res.exit_code != 0 {
                    std::process::exit(res.exit_code);
                }
            }
            MachineCmd::Logs {
                since,
                limit,
                follow,
                id,
            } => {
                let since = since.unwrap_or_default();
                let print =
                    |l: &api::LogLine| println!("{} {}", l.ts.format("%H:%M:%S%.3f"), l.line);
                if follow {
                    let path = format!("/v1/machines/{id}/logs?since={since}&follow=true");
                    c.stream(&path, |line| match follow_line(line)? {
                        ControlFlow::Continue(l) => {
                            l.iter().for_each(print);
                            Ok(ControlFlow::Continue(()))
                        }
                        ControlFlow::Break(why) => {
                            eprintln!("({why})");
                            Ok(ControlFlow::Break(()))
                        }
                    })
                    .await?;
                } else {
                    let res: api::LogsResponse = c
                        .call(
                            GET,
                            &format!("/v1/machines/{id}/logs?since={since}&limit={limit}"),
                            NONE,
                        )
                        .await?;
                    res.lines.iter().for_each(print);
                    if !res.next.is_empty() {
                        eprintln!("(next: --since {})", res.next);
                    }
                }
            }
            MachineCmd::Move { namespace, id } => {
                let req = api::MoveRequest { namespace };
                print_json(
                    &c.call::<api::MoveResult>(
                        POST,
                        &format!("/v1/machines/{id}/move"),
                        Some(&req),
                    )
                    .await?,
                )
            }
            MachineCmd::Fork {
                name,
                namespace,
                snapshot,
                id,
            } => {
                let src: api::Machine = c.call(GET, &format!("/v1/machines/{id}"), NONE).await?;
                let named = snapshot.is_some();
                let mut req = api::CreateMachineRequest {
                    namespace: namespace.unwrap_or_else(|| src.namespace.clone()),
                    name: name.unwrap_or_else(|| format!("{}-fork", src.name)),
                    size: src.size,
                    ports: src.ports.clone(),
                    sleep: src.sleep.clone(),
                    metadata: src.metadata.clone(),
                    egress: Some(src.egress.clone()),
                    limits: Some(src.limits.clone()),
                    disk_limits: Some(src.disk_limits.clone()),
                    fork: Some(api::ForkSpec {
                        snapshot,
                        machine_id: id,
                        copy: String::new(),
                    }),
                    ..Default::default()
                };
                if named {
                    req.size = api::Size::default();
                    req.ports.clear();
                    req.sleep = "never".into();
                    req.egress = None;
                    req.limits = None;
                    req.disk_limits = None;
                }
                print_json(
                    &c.call::<api::Machine>(POST, "/v1/machines", Some(&req))
                        .await?,
                );
            }
            MachineCmd::Put {
                id,
                local,
                guest_path,
            } => {
                c.put_file(&id, &local, &guest_path).await?;
            }
            MachineCmd::GetFile { id, guest_path } => {
                c.get_file(&id, &guest_path).await?;
            }
            MachineCmd::Set(a) => {
                let changing_size =
                    a.vcpus.is_some() || a.memory.is_some() || a.cpu_millis.is_some();
                let half = changing_size
                    && (a.vcpus.is_none() || a.memory.is_none() || a.cpu_millis.is_none());
                let size_now = match half {
                    true => {
                        let m: api::Machine =
                            c.call(GET, &format!("/v1/machines/{}", a.id), NONE).await?;
                        Some(m.pending.and_then(|p| p.size).unwrap_or(m.size))
                    }
                    false => None,
                };
                let req = a.request(size_now)?;
                print_json(
                    &c.call::<api::Machine>(
                        reqwest::Method::PATCH,
                        &format!("/v1/machines/{}", a.id),
                        Some(&req),
                    )
                    .await?,
                )
            }
            MachineCmd::SetSleep { id, sleep } => {
                let req = api::UpdateMachineRequest {
                    sleep: Some(sleep),
                    ..Default::default()
                };
                print_json(
                    &c.call::<api::Machine>(
                        reqwest::Method::PATCH,
                        &format!("/v1/machines/{id}"),
                        Some(&req),
                    )
                    .await?,
                )
            }
            MachineCmd::SetBackup {
                id,
                every,
                keep,
                off,
            } => {
                let req = api::UpdateMachineRequest {
                    backup: match off {
                        true => Some(None),
                        false => policy(every.as_deref(), keep)?,
                    },
                    ..Default::default()
                };
                print_json(
                    &c.call::<api::Machine>(
                        reqwest::Method::PATCH,
                        &format!("/v1/machines/{id}"),
                        Some(&req),
                    )
                    .await?,
                )
            }
            MachineCmd::SetEgress { id, egress } => {
                let req = api::UpdateMachineRequest {
                    egress: Some(egress),
                    ..Default::default()
                };
                print_json(
                    &c.call::<api::Machine>(
                        reqwest::Method::PATCH,
                        &format!("/v1/machines/{id}"),
                        Some(&req),
                    )
                    .await?,
                )
            }
            MachineCmd::SetDiskLimits { id, limits } => {
                let Some(limits) = limits.request()? else {
                    bail!("name a limit: --disk-bw, --disk-iops or --disk-burst");
                };
                let req = api::UpdateMachineRequest {
                    disk_limits: Some(limits),
                    ..Default::default()
                };
                print_json(
                    &c.call::<api::Machine>(
                        reqwest::Method::PATCH,
                        &format!("/v1/machines/{id}"),
                        Some(&req),
                    )
                    .await?,
                )
            }
            MachineCmd::SetLimits { id, limits } => {
                let Some(limits) = limits.request()? else {
                    bail!("name a limit: --block-port, --conn-per-min or --bandwidth");
                };
                let req = api::UpdateMachineRequest {
                    limits: Some(limits),
                    ..Default::default()
                };
                print_json(
                    &c.call::<api::Machine>(
                        reqwest::Method::PATCH,
                        &format!("/v1/machines/{id}"),
                        Some(&req),
                    )
                    .await?,
                )
            }
            MachineCmd::Backup { id } => print_json(
                &c.call::<api::Backup>(POST, &format!("/v1/machines/{id}/backups"), NONE)
                    .await?,
            ),
            MachineCmd::Backups { id } => print_json(
                &c.call::<Vec<api::Backup>>(GET, &format!("/v1/machines/{id}/backups"), NONE)
                    .await?,
            ),
            MachineCmd::Restore {
                from,
                backup,
                namespace,
                name,
                sleep,
            } => {
                let req = api::CreateMachineRequest {
                    namespace,
                    name,
                    sleep,
                    restore: Some(api::RestoreSpec {
                        machine_id: from,
                        backup,
                    }),
                    ..Default::default()
                };
                print_json(
                    &c.call::<api::Machine>(POST, "/v1/machines", Some(&req))
                        .await?,
                )
            }
            MachineCmd::Stats { id } => print_json(
                &c.call::<api::MachineStats>(GET, &format!("/v1/machines/{id}/stats"), NONE)
                    .await?,
            ),
            MachineCmd::Snapshot(s) => match s {
                SnapshotCmd::Create {
                    name,
                    memory,
                    template,
                    id,
                } => {
                    let req = api::SnapshotRequest {
                        name,
                        memory,
                        template,
                    };
                    print_json(
                        &c.call::<api::Snapshot>(
                            POST,
                            &format!("/v1/machines/{id}/snapshots"),
                            Some(&req),
                        )
                        .await?,
                    )
                }
                SnapshotCmd::Ls { id } => {
                    let path = format!("/v1/machines/{id}/snapshots");
                    let ss: Vec<api::Snapshot> = c.call(GET, &path, NONE).await?;
                    print!("{}", snapshot_table(&ss));
                }
                SnapshotCmd::Restore { id, snap } => print_json(
                    &c.call::<api::Machine>(
                        POST,
                        &format!("/v1/machines/{id}/snapshots/{snap}/restore"),
                        NONE,
                    )
                    .await?,
                ),
                SnapshotCmd::Rm { id, snap } => {
                    c.raw(DELETE, &format!("/v1/machines/{id}/snapshots/{snap}"), NONE)
                        .await?;
                }
            },
        },
        Cmd::Endpoint(e) => match e {
            EndpointCmd::Add {
                http,
                host,
                id,
                port,
            } => {
                let req = api::CreateEndpointRequest {
                    port,
                    protocol: if http { "http".into() } else { String::new() },
                    host: host.unwrap_or_default(),
                };
                print_json(
                    &c.call::<api::Endpoint>(
                        POST,
                        &format!("/v1/machines/{id}/endpoints"),
                        Some(&req),
                    )
                    .await?,
                );
            }
            EndpointCmd::Ls => {
                let eps: Vec<api::Endpoint> = c.call(GET, "/v1/endpoints", NONE).await?;
                print!("{}", endpoint_table(&eps));
            }
            EndpointCmd::Rm { id } => {
                c.raw(DELETE, &format!("/v1/endpoints/{id}"), NONE).await?;
            }
        },
        Cmd::Namespace(t) => match t {
            NamespaceCmd::Ls => print_json(
                &c.call::<Vec<api::Namespace>>(GET, "/v1/namespaces", NONE)
                    .await?,
            ),
            NamespaceCmd::Get { id } => print_json(
                &c.call::<api::Namespace>(GET, &format!("/v1/namespaces/{id}"), NONE)
                    .await?,
            ),
            NamespaceCmd::Rm { id } => {
                c.raw(DELETE, &format!("/v1/namespaces/{id}"), NONE).await?;
            }
            NamespaceCmd::Gateway(GatewayCmd::Set(a)) => {
                let GatewaySetArgs {
                    namespace,
                    vcpus,
                    memory,
                    cpu_millis,
                    region,
                    start,
                    image,
                    port,
                    readiness,
                    envs,
                    files,
                    cmd,
                } = *a;
                let spec = api::GatewaySpec {
                    size: if vcpus.is_some() || memory.is_some() || cpu_millis.is_some() {
                        Some(api::Size {
                            vcpus: vcpus.unwrap_or(1),
                            memory_mb: memory.unwrap_or(256),
                            cpu_millis,
                        })
                    } else {
                        None
                    },
                    image,
                    cmd: if cmd.is_empty() { None } else { Some(cmd) },
                    env: env_args(&envs)?,
                    files: file_args(&files)?,
                    port,
                    probes: api::Probes {
                        readiness,
                        ..Default::default()
                    },
                    start,
                    ..Default::default()
                };
                print_json(
                    &c.call::<api::Namespace>(
                        PUT,
                        &namespace_put_path(&namespace, "gateway", region.as_deref()),
                        Some(&spec),
                    )
                    .await?,
                )
            }
            NamespaceCmd::Gateway(GatewayCmd::Rm { namespace }) => {
                c.raw(DELETE, &format!("/v1/namespaces/{namespace}/gateway"), NONE)
                    .await?;
            }
            NamespaceCmd::Unpin { id } => {
                c.raw(POST, &format!("/v1/namespaces/{id}/unpin"), NONE)
                    .await?;
            }
            NamespaceCmd::Quota {
                id,
                machines,
                memory_mb,
                vcpus,
                disk_gb,
                region,
                cpu_millis,
            } => {
                let q = api::Quota {
                    machines,
                    memory_mb,
                    vcpus,
                    disk_gb,
                    cpu_millis,
                };
                let shown: api::NamespaceQuota = if q == api::Quota::default() {
                    c.call(GET, &format!("/v1/namespaces/{id}/quota"), NONE)
                        .await?
                } else {
                    let path = namespace_put_path(&id, "quota", region.as_deref());
                    c.call(PUT, &path, Some(&q)).await?
                };
                print_json(&shown)
            }
        },
        Cmd::Backup(BackupCmd::Rm {
            machine,
            backup,
            chain,
            namespace,
        }) => {
            c.raw(
                DELETE,
                &backup_rm_path(&machine, &backup, chain, namespace.as_deref()),
                NONE,
            )
            .await?;
        }
        Cmd::Backups { namespace, machine } => {
            let path = backups_path(namespace.as_deref(), machine.as_deref());
            print_json(&c.call::<Vec<api::Backup>>(GET, &path, NONE).await?)
        }
        Cmd::Doctor => doctor(),
        Cmd::Events {
            namespace,
            machine,
            since,
            watch,
        } => {
            let path = events_path(namespace.as_deref(), machine.as_deref(), watch);
            print!("{}", events_table(&[]));
            if watch {
                let path = with_since(&path, since.as_deref().unwrap_or(""));
                c.watch(&path, |e| print!("{}", event_row(e))).await?;
            } else {
                let (evs, next) = c.events(&path, since).await?;
                for e in &evs {
                    print!("{}", event_row(e));
                }
                eprintln!("(next: --since {next})");
            }
        }
        Cmd::Top { namespace, json } => {
            let path = match &namespace {
                Some(t) => format!("/v1/top?namespace={t}"),
                None => "/v1/top".into(),
            };
            let ms: Vec<api::TopMachine> = c.call(GET, &path, NONE).await?;
            if json {
                print_json(&ms);
            } else {
                print!("{}", top_table(ms));
            }
        }
        Cmd::Usage {
            from,
            to,
            namespace,
            json,
        } => {
            let bs: Vec<api::UsageBucket> = c
                .call(GET, &usage_path(from, to, namespace.as_deref()), NONE)
                .await?;
            if json {
                print_json(&bs);
            } else {
                print!("{}", usage_table(&bs));
            }
        }
        Cmd::Image(i) => match i {
            ImageCmd::Ls => {
                let ims: Vec<api::Image> = c.call(GET, "/v1/images", NONE).await?;
                print!("{}", image_table(&ims));
            }
            ImageCmd::Rm { key } => {
                c.raw(DELETE, &format!("/v1/images/{key}"), NONE).await?;
            }
        },
        Cmd::Host(h) => match h {
            HostCmd::Ls => {
                let hs: Vec<api::Host> = c.call(GET, "/v1/hosts", NONE).await?;
                let st: api::Status = c.call(GET, "/v1/status", NONE).await?;
                print!("{}", host_table(&hs));
                print!("{}", region_table(&st.regions));
            }
            HostCmd::Add {
                ssh,
                address,
                region,
                id,
                public_tcp_ports,
            } => {
                let req = api::AddHostRequest {
                    ssh,
                    address,
                    region,
                    id,
                    public_tcp_ports: public_tcp_ports.as_deref().map(port_list).transpose()?,
                };
                print_json(&c.call::<api::Host>(POST, "/v1/hosts", Some(&req)).await?)
            }
            HostCmd::Token { cmd } => host_token::run(c, cmd).await?,
            HostCmd::Drain { id } => {
                c.raw(POST, &format!("/v1/hosts/{id}/drain"), NONE).await?;
            }
            HostCmd::Undrain { id } => {
                c.raw(POST, &format!("/v1/hosts/{id}/undrain"), NONE)
                    .await?;
            }
            HostCmd::Upgrade { id, all, release } => {
                let ids = match (id, all) {
                    (Some(id), _) => vec![id],
                    (None, _) => {
                        let hs: Vec<api::Host> = c.call(GET, "/v1/hosts", NONE).await?;
                        let (ids, skipped) = upgrade_order(&hs);
                        for (id, state) in skipped {
                            eprintln!("{id}: {state}, not upgraded");
                        }
                        ids
                    }
                };
                let req = api::UpgradeHostRequest { release };
                for (i, id) in ids.iter().enumerate() {
                    eprintln!("{id}: upgrading");
                    let path = format!("/v1/hosts/{id}/upgrade");
                    match c.send(POST, &path, Some(&req), Some(UPGRADE_TIMEOUT)).await {
                        Ok(resp) => {
                            let h: api::Host = resp.json().await?;
                            println!("{id}: {}", h.note);
                        }
                        Err(e) => {
                            let left = &ids[i + 1..];
                            match left.is_empty() {
                                true => bail!("{id}: {e:#}"),
                                false => bail!("{id}: {e:#}; not upgraded: {}", left.join(", ")),
                            }
                        }
                    }
                }
            }
            HostCmd::Retire { id } => print_json(
                &c.call::<api::Host>(POST, &format!("/v1/hosts/{id}/retire"), NONE)
                    .await?,
            ),
            HostCmd::Rm { id, force } => {
                let q = if force { "?force=true" } else { "" };
                c.raw(DELETE, &format!("/v1/hosts/{id}{q}"), NONE).await?;
                if force {
                    eprintln!("host {id} forgotten: a pool key it held went with its record, and its pool is unreadable at its next restart");
                }
            }
        },
    }
    Ok(())
}
