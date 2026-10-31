use super::*;

fn response(body: &str, status: u16) -> &'static str {
    Box::leak(
        format!(
            "HTTP/1.1 {status} Response\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_boxed_str(),
    )
}

#[tokio::test]
async fn balloon_profile_is_typed_exact_and_rejections_are_errors() {
    let (_dir, path) = socket();
    let server = serve(
        &path,
        vec![
            NO_CONTENT,
            response(r#"{"fault_message":"unsupported reporting"}"#, 400),
        ],
    );
    let client = Client::new(&path);
    client
        .configure_balloon(&BalloonConfig::reporting())
        .await
        .unwrap();
    assert!(client
        .configure_balloon(&BalloonConfig::reporting())
        .await
        .is_err());
    let seen = server.await.unwrap();
    assert!(seen[0].starts_with("PUT /balloon "));
    assert_eq!(
        body(&seen[0]),
        json!({"amount_mib":0,"deflate_on_oom":true,
        "stats_polling_interval_s":5,"free_page_hinting":false,"free_page_reporting":true})
    );
}

#[tokio::test]
async fn optional_device_and_stats_reads_preserve_missing_guest_counters() {
    let (_dir, path) = socket();
    let server = serve(
        &path,
        vec![
            response(r#"{"fault_message":"No balloon device found."}"#, 400),
            response(
                r#"{"target_pages":0,"actual_pages":7,"free_memory":0}"#,
                200,
            ),
            response(r#"{"fault_message":"other fault"}"#, 400),
        ],
    );
    let client = Client::new(&path);
    assert!(client.balloon_config().await.unwrap().is_none());
    let stats = client.balloon_statistics().await.unwrap();
    assert_eq!(stats.free_memory, Some(0));
    assert_eq!(stats.available_memory, None);
    assert!(client.balloon_config().await.is_err());
    let seen = server.await.unwrap();
    assert!(seen[1].starts_with("GET /balloon/statistics "));
}

#[tokio::test(start_paused = true)]
async fn statistics_read_is_bounded() {
    let (_dir, path) = socket();
    let listener = UnixListener::bind(&path).unwrap();
    let pending = tokio::spawn(async move {
        let (_connection, _) = listener.accept().await.unwrap();
        std::future::pending::<()>().await;
    });
    let err = Client::new(&path).balloon_statistics().await.unwrap_err();
    assert!(err.to_string().contains("timed out"));
    pending.abort();
}

#[test]
fn compatibility_requires_exact_artifacts_transport_schema_and_known_profile() {
    let identity = BootIdentity {
        schema: 1,
        device_profile: REPORTING_PROFILE.into(),
        kernel_sha256: "kernel".into(),
        vmm_sha256: "vmm".into(),
        host_kernel: "6.8".into(),
        transport: "mmio".into(),
    };
    assert!(identity.compatible(&identity.with_reporting(false)));
    for key in [
        "schema",
        "kernel_sha256",
        "vmm_sha256",
        "host_kernel",
        "transport",
        "device_profile",
    ] {
        let mut altered = serde_json::to_value(&identity).unwrap();
        altered[key] = if key == "schema" {
            json!(2)
        } else {
            json!("other")
        };
        let altered: BootIdentity = serde_json::from_value(altered).unwrap();
        assert!(!altered.compatible(&identity), "{key}");
    }
    assert!(!BootIdentity::ambiguous(REPORTING_PROFILE).compatible(&identity));
}

#[test]
fn fifo_balloon_counters_accumulate_increments_and_failed_reads_have_no_zero_sample() {
    let io = DiskIo::default();
    let line = r#"{"balloon":{"stats_updates_count":2,"free_page_report_count":3,"free_page_report_freed":4096,"free_page_report_fails":1}}"#;
    io.add(line);
    io.add(line);
    let sample = io
        .balloon
        .sample(chrono::Utc::now(), Err(anyhow!("unavailable")));
    assert_eq!(sample.stats_updates, 4);
    assert_eq!(sample.free_page_reported_bytes, 8192);
    assert_eq!(sample.free_page_report_failures, 2);
    assert_eq!(sample.status, "error");
    assert!(sample.target_bytes.is_none());
    assert!(sample.actual_bytes.is_none());
    assert!(sample.last_stats_update_observed_at.is_some());
    io.balloon.reset_observation();
    assert!(io
        .balloon
        .sample(chrono::Utc::now(), Ok(None))
        .last_stats_update_observed_at
        .is_none());
}

#[test]
fn memory_stat_components_are_optional_and_do_not_claim_to_sum_to_current() {
    let stat = "anon 123\nfile 456\nfile_mapped 789\n";
    assert_eq!(memory_stat_bytes(stat, "anon"), Some(123));
    assert_eq!(memory_stat_bytes(stat, "file"), Some(456));
    assert_eq!(memory_stat_bytes("anon invalid", "anon"), None);
    assert_eq!(memory_stat_bytes("anon 123", "file"), None);
}

#[test]
fn adoption_invalidates_contradictions_but_preserves_identity_on_telemetry_failure() {
    let reporting = BootIdentity {
        schema: 1,
        device_profile: REPORTING_PROFILE.into(),
        kernel_sha256: "kernel".into(),
        vmm_sha256: "vmm".into(),
        host_kernel: "test".into(),
        transport: "mmio".into(),
    };
    let observed_reporting = BootIdentity::ambiguous(REPORTING_PROFILE);
    let unavailable = BootIdentity::ambiguous(UNAVAILABLE_PROFILE);
    assert_eq!(
        BootIdentity::after_adoption(Some(&reporting), Some(&unavailable), true),
        Some(reporting.clone())
    );
    assert_eq!(
        BootIdentity::after_adoption(Some(&reporting), Some(&observed_reporting), true),
        Some(reporting.clone())
    );
    let legacy = BootIdentity::after_adoption(Some(&reporting), None, true).unwrap();
    assert_eq!(
        (legacy.schema, legacy.device_profile.as_str()),
        (0, LEGACY_PROFILE)
    );
    let observed = BootIdentity::after_adoption(
        Some(&reporting.with_reporting(false)),
        Some(&observed_reporting),
        true,
    )
    .unwrap();
    assert_eq!(
        (observed.schema, observed.device_profile.as_str()),
        (0, REPORTING_PROFILE)
    );
    let mut future = reporting;
    future.schema = 2;
    assert_eq!(
        BootIdentity::after_adoption(Some(&future), None, true),
        Some(future)
    );
}

#[test]
fn matching_device_without_incarnation_cannot_certify_artifacts() {
    let legacy = BootIdentity {
        schema: 1,
        device_profile: LEGACY_PROFILE.into(),
        kernel_sha256: "old-kernel".into(),
        vmm_sha256: "old-vmm".into(),
        host_kernel: "test".into(),
        transport: "mmio".into(),
    };
    let identity = BootIdentity::after_adoption(Some(&legacy), None, false).unwrap();
    assert_eq!(identity.schema, 0);
    assert_eq!(identity.device_profile, LEGACY_PROFILE);
    let reporting = legacy.with_reporting(true);
    let observation = BootIdentity::ambiguous(REPORTING_PROFILE);
    assert_eq!(
        BootIdentity::after_adoption(Some(&reporting), Some(&observation), false)
            .unwrap()
            .schema,
        0
    );
}

#[test]
fn process_start_ticks_parse_comm_parentheses_and_reject_missing_or_invalid_fields() {
    let prior = (4..22).map(|n| n.to_string()).collect::<Vec<_>>().join(" ");
    let stat = format!("123 (a b) c) S {prior} 98765 0 0");
    assert_eq!(super::super::incarnation::start_ticks(&stat), Some(98765));
    assert_eq!(
        super::super::incarnation::start_ticks("123 (short) S 0"),
        None
    );
    assert_eq!(
        super::super::incarnation::start_ticks(&stat.replace("98765", "invalid")),
        None
    );
}

#[tokio::test]
async fn pinned_vmm_absent_device_action_error_preserves_legacy_classification() {
    let (_dir, path) = socket();
    let server = serve(
        &path,
        vec![response(
            r#"{"fault_message":"Internal VMM error: Failed perform action on device: Device not found"}"#,
            400,
        )],
    );
    assert!(Client::new(&path).balloon_config().await.unwrap().is_none());
    let seen = server.await.unwrap();
    assert!(seen[0].starts_with("GET /balloon "));
}
