use super::*;

fn frames(responses: &[Response]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for response in responses {
        guest::write_frame(&mut bytes, response).unwrap();
    }
    bytes
}

#[tokio::test]
async fn retains_raw_prefixes_per_stream_and_drains_through_exit() {
    for cap in [1, 4, 5] {
        let bytes = frames(&[
            Response::chunk("stdout", vec![0xff, 0, 1, 2]),
            Response::chunk("stderr", b"abcd".to_vec()),
            Response::chunk("stdout", b"excess".to_vec()),
            Response::chunk("stderr", b"excess".to_vec()),
            Response {
                kind: "exit".into(),
                code: 42,
                timed_out: true,
                ..Default::default()
            },
        ]);
        let mut input = bytes.as_slice();
        let out = collect_capture(&mut input, cap).await.unwrap();
        assert_eq!(out.stdout, [0xff, 0, 1, 2, b'e'][..cap as usize]);
        assert_eq!(out.stderr, b"abcde"[..cap as usize]);
        assert_eq!((out.code, out.timed_out), (42, true));
        assert!(input.is_empty());
        assert!(out.stdout.capacity() <= cap as usize);
        assert!(out.stderr.capacity() <= cap as usize);
    }
}

#[tokio::test]
async fn full_capture_never_substitutes_for_a_terminal_exit() {
    let bytes = frames(&[Response::chunk("stdout", b"excess".to_vec())]);
    let err = collect_capture(&mut bytes.as_slice(), 1).await.unwrap_err();
    assert!(err.downcast_ref::<Closed>().is_some());
    let (mut input, mut writer) = tokio::io::duplex(4096);
    writer.write_all(&bytes).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(10), collect_capture(&mut input, 1))
            .await
            .is_err()
    );
    let bytes = frames(&[
        Response::chunk("stdout", b"excess".to_vec()),
        Response::error("command failed"),
    ]);
    assert_eq!(
        collect_capture(&mut bytes.as_slice(), 1)
            .await
            .unwrap_err()
            .to_string(),
        "command failed"
    );
}

#[tokio::test]
async fn capture_limit_is_positive_and_no_larger_than_storage_bound() {
    for cap in [0, briqyard_api::execution::MAX_CAPTURE_BYTES + 1] {
        assert!(collect_capture(&mut &[][..], cap).await.is_err());
    }
    let bytes = frames(&[Response {
        kind: "exit".into(),
        ..Default::default()
    }]);
    assert!(collect_capture(
        &mut bytes.as_slice(),
        briqyard_api::execution::MAX_CAPTURE_BYTES
    )
    .await
    .is_ok());
}
