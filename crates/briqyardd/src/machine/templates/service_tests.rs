//! `service-ready-v1`: a running service parked, sealed and cloned (ADR 0127).
use super::*;
use crate::machine::tests::{harness_config, Harness};
use sha2::Digest;

fn hooks() -> guest::CloneHooks {
    guest::CloneHooks {
        park: vec!["/app/park".into()],
        resume: vec!["/app/resume".into()],
        park_timeout_s: 30,
        resume_timeout_s: 30,
    }
}

async fn harness(service: bool) -> Harness {
    let h = harness_config(move |cfg| {
        cfg.network.range = "10.64.0.0/22".into();
        cfg.capacity.memory_mb = 4096;
        cfg.capacity.vcpus = 8;
        cfg.jailer = "/mock/jailer".into();
        cfg.templates.enabled = true;
        cfg.templates.service_ready = service;
        cfg.templates.init_ready_init_sha256 = hex::encode(sha2::Sha256::digest(b"init"));
    })
    .await;
    h.namespace("t1");
    let config = ImageConfig {
        cmd: vec!["/app/svc".into()],
        workdir: "/".into(),
        ..Default::default()
    };
    h.m.inner
        .images
        .seed_with_config_digest(ALPINE, config, ALPINE_CONFIG_DIGEST)
        .await
        .unwrap();
    h
}

fn builder_request(h: &Harness) -> api::CreateMachineRequest {
    let mut req = h.request("service");
    req.image = ALPINE.into();
    req.sleep = "never".into();
    req.template_build = Some(guest::SERVICE_READY_V1.into());
    req.clone_hooks = Some(hooks());
    req
}

fn seal() -> api::SnapshotRequest {
    api::SnapshotRequest {
        consistency: None,
        name: Some("loaded".into()),
        memory: true,
        template: true,
    }
}

fn clone_request(builder: &str, name: &str) -> api::CreateMachineRequest {
    api::CreateMachineRequest {
        namespace: "t1".into(),
        name: name.into(),
        fork: Some(api::ForkSpec {
            consistency: None,
            machine_id: builder.into(),
            copy: String::new(),
            snapshot: Some("loaded".into()),
        }),
        ..Default::default()
    }
}

#[tokio::test]
async fn a_builder_in_another_runtime_class_is_refused_before_anything_is_created() {
    let h = harness(true).await;
    let mut req = builder_request(&h);
    req.runtime_class = "kvm".into();
    let error = h.m.create_made(req).await.unwrap_err();
    assert!(
        error.to_string().contains("default runtime class"),
        "{error}"
    );
    assert!(h.m.list(None, &[]).is_empty());
}

#[tokio::test]
async fn the_profile_is_off_unless_the_flag_is_on() {
    let off = harness(false).await;
    assert_eq!(off.m.named_memory_profiles(), ["init-ready-v1"]);
    assert!(off.m.create_made(builder_request(&off)).await.is_err());
    let on = harness(true).await;
    assert_eq!(
        on.m.named_memory_profiles(),
        ["init-ready-v1", "service-ready-v1"]
    );
}

#[tokio::test]
async fn a_builder_without_hooks_or_with_a_volume_is_refused_before_anything_is_made() {
    let h = harness(true).await;
    let mut req = builder_request(&h);
    req.clone_hooks = None;
    assert!(h.m.create_made(req).await.is_err());
    let mut req = builder_request(&h);
    req.clone_hooks.as_mut().unwrap().resume.clear();
    assert!(h.m.create_made(req).await.is_err());
    let mut req = builder_request(&h);
    req.volume = Some(api::VolumeSpec {
        size_gb: 1,
        mount: "/data".into(),
    });
    assert!(h.m.create_made(req).await.is_err());
    let mut req = builder_request(&h);
    req.template_build = Some(guest::INIT_READY_V1.into());
    assert!(h.m.create_made(req).await.is_err());
}

#[tokio::test]
async fn a_service_serves_until_sealed_then_the_source_stops_and_three_clones_start() {
    let h = harness(true).await;
    let builder = h.m.create_made(builder_request(&h)).await.unwrap();
    assert_eq!(builder.state, state::RUNNING);
    assert!(
        builder.ready,
        "a service builder is an ordinary machine until the seal"
    );
    h.m.exec(
        &builder.id,
        api::ExecRequest {
            cmd: vec!["/bin/true".into()],
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let snapshot = h.m.snapshot(&builder.id, seal()).await.unwrap();
    assert_eq!(
        snapshot.clone_profile.as_deref(),
        Some(guest::SERVICE_READY_V1)
    );
    assert_eq!(h.m.get(&builder.id).unwrap().state, state::STOPPED);
    h.host_calls();
    let mut ids = Vec::new();
    for n in 0..3 {
        let clone =
            h.m.create_made(clone_request(&builder.id, &format!("c{n}")))
                .await
                .unwrap();
        assert_eq!(clone.state, state::RUNNING);
        assert_eq!(clone.memory_origin.as_ref().unwrap().stage, "active");
        ids.push(clone.id);
    }
    let calls = h.host_calls();
    let order = |op: &str, n: usize| {
        calls
            .iter()
            .enumerate()
            .filter(|(_, c)| c.starts_with(op))
            .nth(n)
            .map(|(i, _)| i)
            .unwrap()
    };
    for n in 0..3 {
        assert!(
            order("clone_configure_v1", n) < order("activate_quarantined", n)
                && order("activate_quarantined", n) < order("clone_activate_v1", n),
            "{calls:?}"
        );
    }
    assert!(matches!(
        h.m.delete_snapshot(&builder.id, &snapshot.id).await,
        Err(MError::Conflict(_))
    ));
    for id in ids {
        h.m.destroy(&id, None).await.unwrap();
    }
    h.m.delete_snapshot(&builder.id, &snapshot.id)
        .await
        .unwrap();
}

#[tokio::test]
async fn a_failed_park_leaves_the_source_running_and_keeps_no_artifact() {
    for (fault, needle) in [(1, "clone_hook_failed"), (2, "established_socket")] {
        let h = harness(true).await;
        let builder = h.m.create_made(builder_request(&h)).await.unwrap();
        h.service_fault(fault);
        let error = h.m.snapshot(&builder.id, seal()).await.unwrap_err();
        assert!(
            matches!(&error, MError::Conflict(m) if m.contains(needle)),
            "{error:?}"
        );
        let after = h.m.get(&builder.id).unwrap();
        assert_eq!(after.state, state::RUNNING);
        assert!(h.m.snapshots(&builder.id).await.unwrap().is_empty());
        h.service_fault(0);
        // The service can still be sealed once the cause is gone.
        h.m.snapshot(&builder.id, seal()).await.unwrap();
    }
}

#[tokio::test]
async fn a_failed_resume_quarantines_that_clone_and_releases_its_capacity() {
    let h = harness(true).await;
    let builder = h.m.create_made(builder_request(&h)).await.unwrap();
    h.m.snapshot(&builder.id, seal()).await.unwrap();
    let ok =
        h.m.create_made(clone_request(&builder.id, "first"))
            .await
            .unwrap();
    let used = h.m.usage().0.memory_mb;
    h.service_fault(3);
    let error =
        h.m.create_made(clone_request(&builder.id, "second"))
            .await
            .unwrap_err();
    let MError::BootFailed(view) = error else {
        panic!("{error:?}");
    };
    assert_eq!(view.state, state::ERROR);
    assert_eq!(
        view.error_reason,
        reason::CLONE_HOOK_FAILED,
        "{}",
        view.error
    );
    assert!(view.error.contains("resume hook"), "{}", view.error);
    h.service_fault(0);
    // It cannot be started again: the same identity and entropy would come back.
    let again = h.m.start(&view.id, None).await.unwrap_err();
    assert!(matches!(again, MError::Conflict(_)), "{again:?}");
    // The first clone is untouched and the failed one holds no memory once its VMM exited.
    assert_eq!(h.m.get(&ok.id).unwrap().state, state::RUNNING);
    assert_eq!(h.m.usage().0.memory_mb, used);
    let third =
        h.m.create_made(clone_request(&builder.id, "third"))
            .await
            .unwrap();
    assert_eq!(third.state, state::RUNNING);
}
