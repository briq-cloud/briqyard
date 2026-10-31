//! Image builds, pulls and removals.

use super::builds::{take, Turn};
use super::gc::removed;
use super::pull::{check_layers, parse_config, pulled};
use super::*;
use oci_client::manifest::OciImageManifest;
use std::path::Path;

#[test]
fn a_removal_is_an_event_that_says_why() {
    let im = Image {
        config_digest: String::new(),
        r#ref: "alpine:3.20".into(),
        digest: "sha256:abc".into(),
        key: "k1".into(),
        config: ImageConfig::default(),
        size_gb: 8,
        built_at: Utc::now(),
    };
    let dir = tempfile::tempdir().unwrap();
    let log = Events::open(dir.path()).unwrap();
    for how in [Removal::Request, Removal::Unused, Removal::DiskPressure] {
        log.emit(removed(&im, how));
    }
    let evs = log.read(0, &Default::default(), 10).unwrap().events;
    let got: Vec<(&str, &str, &str)> = evs
        .iter()
        .map(|e| {
            (
                e.reason.as_str(),
                e.message.as_str(),
                e.data.as_ref().unwrap()["reason"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        got,
        vec![
            (
                "image_removed",
                "removed alpine:3.20: on request",
                "request"
            ),
            (
                "image_removed",
                "removed alpine:3.20: unused past image_keep_days",
                "unused"
            ),
            (
                "image_removed",
                "removed alpine:3.20: unused, the pool under its free threshold",
                "disk_pressure"
            ),
        ]
    );
    assert_eq!(
        evs[0].data,
        Some(serde_json::json!({
            "image": "alpine:3.20", "digest": "sha256:abc", "key": "k1", "reason": "request"
        }))
    );
}

#[test]
fn a_pull_is_an_event_with_its_digest_source_and_time() {
    let dir = tempfile::tempdir().unwrap();
    let log = Events::open(dir.path()).unwrap();
    log.emit(pulled(
        "alpine:3.20",
        "sha256:abc",
        Some("10.0.0.2:7440"),
        std::time::Duration::from_millis(1000),
    ));
    log.emit(pulled(
        "alpine:3.20",
        "sha256:abc",
        None,
        std::time::Duration::from_millis(4240),
    ));
    let mut evs = log.read(0, &Default::default(), 2).unwrap().events;
    assert_eq!(
        evs[0].message,
        "pulled alpine:3.20 in 1 s through 10.0.0.2:7440"
    );
    assert_eq!(evs[0].data.as_ref().unwrap()["from"], "10.0.0.2:7440");
    let e = evs.remove(1);
    assert_eq!(
        (e.reason.as_str(), e.message.as_str()),
        ("image_pulled", "pulled alpine:3.20 in 4.2 s")
    );
    assert_eq!(
        e.data,
        Some(
            serde_json::json!({"image": "alpine:3.20", "digest": "sha256:abc", "from": "registry", "seconds": 4.2})
        )
    );
    assert_eq!(e.machine_id, "");
}

#[test]
fn config_parsing() {
    let c = parse_config(br#"{"config":{"Entrypoint":["docker-entrypoint.sh"],"Cmd":["postgres"],"Env":["PATH=/usr/bin","PGDATA=/var/lib/postgresql/data"],"WorkingDir":"","User":"","Volumes":{"/var/lib/postgresql/data":{}},"ExposedPorts":{"5432/tcp":{}}}}"#).unwrap();
    assert_eq!(c.entrypoint, vec!["docker-entrypoint.sh"]);
    assert_eq!(c.env["PGDATA"], "/var/lib/postgresql/data");
    assert_eq!(c.volumes, vec!["/var/lib/postgresql/data"]);
    assert_eq!(c.exposed_ports, vec![5432]);
}

#[test]
fn layers_are_checked_before_any_pull() {
    let manifest = |layers: serde_json::Value| -> OciImageManifest {
        serde_json::from_value(serde_json::json!({
            "schemaVersion": 2,
            "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": "sha256:c0", "size": 1},
            "layers": layers
        }))
        .unwrap()
    };
    let err = check_layers(&manifest(serde_json::json!([]))).unwrap_err();
    assert_eq!(err.to_string(), "image has no layers");
    let ok = serde_json::json!({"mediaType": oci_client::manifest::IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE, "digest": "sha256:a1", "size": 1});
    check_layers(&manifest(serde_json::json!([ok]))).unwrap();
    let odd = serde_json::json!({"mediaType": "application/vnd.oci.image.layer.v1.tar+xz", "digest": "sha256:b2", "size": 1});
    let err = check_layers(&manifest(serde_json::json!([ok, odd]))).unwrap_err();
    assert_eq!(
        err.to_string(),
        "layer sha256:b2: media type \"application/vnd.oci.image.layer.v1.tar+xz\" is not supported"
    );
}

/// A build whose future is dropped half way frees its key: a waiter wakes and the next
/// `ensure` of the key builds instead of waiting forever.
#[tokio::test]
async fn a_dropped_build_frees_its_key_and_wakes_its_waiters() {
    use futures::FutureExt;
    let building: Builds = Mutex::new(HashMap::new());
    let Turn::Build(slot) = take(&building, "k") else {
        panic!("the first taker builds");
    };
    let Turn::Wait(mut rx) = take(&building, "k") else {
        panic!("the second waits");
    };
    assert!(
        rx.changed().now_or_never().is_none(),
        "nothing to wake on yet"
    );
    drop(slot);
    assert!(rx.changed().now_or_never().is_some(), "woken by the drop");
    assert!(building.lock().unwrap().is_empty());
    assert!(matches!(take(&building, "k"), Turn::Build(_)));
    // A build that ended normally frees the key the same way.
    let Turn::Build(slot) = take(&building, "k2") else {
        panic!();
    };
    drop(slot);
    assert!(matches!(take(&building, "k2"), Turn::Build(_)));
}

/// A registry on loopback serving manifests by tag or digest and blobs by digest, and
/// logging each request as `METHOD manifests/<ref>` or `GET blobs/<digest>`.
#[derive(Default)]
struct FakeRegistry {
    manifests: HashMap<String, (Vec<u8>, String)>,
    blobs: HashMap<String, Vec<u8>>,
    log: Mutex<Vec<String>>,
}

fn sha(b: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(b)))
}

impl FakeRegistry {
    /// An image of one config and one layer, under `tag` and its digest. Its digest.
    fn add(&mut self, tag: &str, layer: &[u8]) -> String {
        let config = br#"{"config":{"Cmd":["sh"]}}"#.to_vec();
        let manifest = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "mediaType": oci_client::manifest::OCI_IMAGE_MEDIA_TYPE,
            "config": {"mediaType": oci_client::manifest::IMAGE_CONFIG_MEDIA_TYPE,
                       "digest": sha(&config), "size": config.len()},
            "layers": [{"mediaType": oci_client::manifest::IMAGE_LAYER_MEDIA_TYPE,
                        "digest": sha(layer), "size": layer.len()}],
        }))
        .unwrap();
        let digest = sha(&manifest);
        self.blobs.insert(sha(&config), config);
        self.blobs.insert(sha(layer), layer.to_vec());
        self.manifests
            .insert(tag.into(), (manifest.clone(), digest.clone()));
        self.manifests
            .insert(digest.clone(), (manifest, digest.clone()));
        digest
    }

    fn requests(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }

    /// Serves on a loopback port: its `host:port`.
    async fn serve(self) -> (String, std::sync::Arc<FakeRegistry>) {
        use axum::http::{header, Method, StatusCode, Uri};
        use axum::response::IntoResponse;
        let me = std::sync::Arc::new(self);
        let state = me.clone();
        let app = axum::Router::new().fallback(move |method: Method, uri: Uri| {
            let f = state.clone();
            async move {
                let path = uri.path().to_string();
                if path == "/v2/" {
                    return StatusCode::OK.into_response();
                }
                let (kind, name) =
                    match (path.rsplit_once("/manifests/"), path.rsplit_once("/blobs/")) {
                        (Some((_, r)), _) => ("manifests", r.to_string()),
                        (_, Some((_, d))) => ("blobs", d.to_string()),
                        _ => return StatusCode::NOT_FOUND.into_response(),
                    };
                f.log
                    .lock()
                    .unwrap()
                    .push(format!("{method} {kind}/{name}"));
                let found = match kind {
                    "manifests" => f.manifests.get(&name).map(|(b, d)| {
                        (
                            oci_client::manifest::OCI_IMAGE_MEDIA_TYPE,
                            b.clone(),
                            d.clone(),
                        )
                    }),
                    _ => f
                        .blobs
                        .get(&name)
                        .map(|b| ("application/octet-stream", b.clone(), name.clone())),
                };
                match found {
                    Some((media_type, body, digest)) => (
                        [
                            (header::CONTENT_TYPE, media_type.to_string()),
                            (
                                header::HeaderName::from_static("docker-content-digest"),
                                digest,
                            ),
                        ],
                        body,
                    )
                        .into_response(),
                    None => StatusCode::NOT_FOUND.into_response(),
                }
            }
        });
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let host = l.local_addr().unwrap().to_string();
        tokio::spawn(async move { axum::serve(l, app).await });
        (host, me)
    }
}

/// A builder whose registries are `origin` (the image's) and its mirror at `mirror`, both
/// plain HTTP on loopback.
async fn builder(dir: &Path, origin: &str, mirror: &str) -> Builder {
    let fake = crate::zfs::fake::Fake::open("byard").await.unwrap();
    let init = dir.join("init");
    std::fs::write(&init, b"init").unwrap();
    let mirror = Mirror::parse(origin, &format!("http://{mirror}")).unwrap();
    let mut b = Builder::new(
        fake.zfs.clone(),
        dir.join("images"),
        init,
        8,
        vec![mirror.clone()],
    )
    .unwrap();
    let plain = vec![origin.to_string(), mirror.host.clone()];
    b.client = Client::new(client_config(plain, std::time::Duration::from_secs(1)));
    b
}

/// Resolves `reference` and pulls its manifest and layer as a build does: the layer's
/// bytes, and which mirror served (None: the registry).
async fn pull(
    b: &Builder,
    reference: &str,
    dir: &Path,
) -> Result<(String, Vec<u8>, Option<String>)> {
    let r: Reference = reference.parse()?;
    let digest = b.resolve(&r, reference, &RegistryAuth::Anonymous).await?;
    let mut sources = b.sources(&r, &digest);
    let (manifest, _) = b.pull_manifest(&mut sources, reference).await?;
    let file = dir.join("layer");
    b.pull_layer(&mut sources, reference, &manifest.layers[0], &file)
        .await?;
    let from = sources[0].mirror.clone();
    Ok((digest, std::fs::read(&file)?, from))
}

/// ADR 0036: a tag is asked of the registry alone, by a HEAD, and the content by its
/// digest of the mirror; the mirror's own idea of the tag is never asked.
#[tokio::test]
async fn a_tag_is_resolved_by_the_registry_and_the_content_pulled_from_the_mirror() {
    let dir = tempfile::tempdir().unwrap();
    let mut origin = FakeRegistry::default();
    let want = origin.add("1", b"the layer");
    let mut mirror = FakeRegistry::default();
    assert_eq!(mirror.add("1", b"the layer"), want);
    // The mirror says the tag is another image: it must not matter.
    mirror.add("1", b"another layer");
    let (origin_host, origin) = origin.serve().await;
    let (mirror_host, mirror) = mirror.serve().await;
    let b = builder(dir.path(), &origin_host, &mirror_host).await;
    let (digest, layer, from) = pull(&b, &format!("{origin_host}/app:1"), dir.path())
        .await
        .unwrap();
    assert_eq!(digest, want);
    assert_eq!(layer, b"the layer");
    assert_eq!(from.as_deref(), Some(mirror_host.as_str()));
    assert_eq!(origin.requests(), ["HEAD manifests/1"]);
    let asked = mirror.requests();
    assert!(asked.iter().all(|r| !r.ends_with("/1")), "{asked:?}");
    assert_eq!(asked[0], format!("GET manifests/{want}"));
    assert_eq!(asked.len(), 3, "manifest, config, layer: {asked:?}");
}

/// A mirror that is down, silent, does not have the image, or serves other bytes for the
/// digest is left for the registry, which serves the rest of the pull.
#[tokio::test]
async fn a_mirror_that_fails_or_lies_leaves_the_pull_to_the_registry() {
    let dir = tempfile::tempdir().unwrap();
    let mut origin = FakeRegistry::default();
    let want = origin.add("1", b"the layer");
    let (origin_host, origin) = origin.serve().await;
    let reference = format!("{origin_host}/app:1");

    // Down: nothing listens there.
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let down = closed.local_addr().unwrap().to_string();
    drop(closed);
    // Empty: it has nothing.
    let (empty, _) = FakeRegistry::default().serve().await;
    // A lying layer: the manifest is right, the layer's bytes are not its digest.
    let mut liar = FakeRegistry::default();
    liar.add("1", b"the layer");
    let layer_digest = sha(b"the layer");
    liar.blobs
        .insert(layer_digest.clone(), b"evil layer".to_vec());
    let (lying_layer, liar) = liar.serve().await;
    // A lying manifest: other bytes under the image's digest.
    let mut forger = FakeRegistry::default();
    let other = forger.add("x", b"evil layer");
    let forged = forger.manifests[&other].clone();
    forger.manifests.insert(want.clone(), forged);
    let (lying_manifest, _) = forger.serve().await;

    // Silent: it takes the connection and never answers (bounded by the read timeout, 1 s
    // in these tests).
    let silent = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let quiet = silent.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((s, _)) = silent.accept().await {
            held.push(s);
        }
    });

    for mirror in [down, empty, lying_layer, lying_manifest, quiet] {
        let b = builder(dir.path(), &origin_host, &mirror).await;
        let (digest, layer, from) = pull(&b, &reference, dir.path()).await.unwrap();
        assert_eq!(
            (digest.as_str(), layer.as_slice(), from),
            (want.as_str(), &b"the layer"[..], None),
            "mirror {mirror}"
        );
    }
    // The liar served the manifest and config; only the layer came from the registry.
    assert_eq!(liar.requests().len(), 3);
    assert!(origin
        .requests()
        .contains(&format!("GET blobs/{layer_digest}")));

    // With the registry gone too, the pull fails with the registry's error.
    let b = builder(dir.path(), "127.0.0.1:9", "127.0.0.1:9").await;
    let err = pull(&b, &format!("127.0.0.1:9/app@{want}"), dir.path())
        .await
        .unwrap_err();
    assert!(format!("{err:#}").contains("127.0.0.1:9"), "{err:#}");
}
