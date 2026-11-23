//! The commitment preimages (erratum 2). Every expected digest below was computed by an
//! independent Python implementation (sorted-key canonical JSON, base64url text, SHA-256), never
//! by the code under test; the inputs are public synthetic values.

use crate::execution::sealed::canonical::{decode, encode, h};
use crate::execution::sealed::custody::Resource;
use crate::execution::sealed::inputs::Path;
use crate::execution::sealed::inputs::Text;
use crate::execution::sealed::owner::ArmReceipt;
use crate::execution::sealed::preimage::*;
use crate::execution::sealed::prim::{HexDigest, Ident, PosInt, Uint};

const OP: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn operation_dir(serial: u64) -> String {
    format!("/var/lib/briqyard/sealed/{OP}/{serial}")
}

fn daemon_guarded(serial: u64) -> Argv {
    Argv::new(
        "/usr/local/bin/briqyardd",
        &[
            "/usr/local/bin/briqyardd",
            "sealed-guard",
            "--resource",
            "daemon",
            "--operation-dir",
            &operation_dir(serial),
        ],
    )
    .unwrap()
}

fn argv(exec: &str, rest: &[&str]) -> Argv {
    let mut args = vec![exec];
    args.extend_from_slice(rest);
    Argv::new(exec, &args).unwrap()
}

fn ident(text: &str) -> Ident {
    Ident::new(text).unwrap()
}

fn path(text: &str) -> Path {
    Path::new(text).unwrap()
}

fn sandbox(binds: Vec<BindReadOnly>, env_files: Vec<EnvFile>) -> Sandbox {
    Sandbox {
        format: SandboxFormat::V1,
        uid: Uint::new(0).unwrap(),
        gid: Uint::new(0).unwrap(),
        supplementary_gids: vec![],
        umask: Uint::new(18).unwrap(),
        dynamic_user: false,
        no_new_privileges: true,
        protect_system: ProtectSystem::Strict,
        protect_home: ProtectHome::Yes,
        private_tmp: true,
        private_devices: true,
        families: Families {
            mode: FamilyMode::Allow,
            names: vec![ident("AF_INET"), ident("AF_INET6"), ident("AF_UNIX")],
        },
        state_dirs: vec![ident("briqyard")],
        state_dir_mode: Uint::new(488).unwrap(),
        read_write: vec![path("/run/briqyard"), path("/var/lib/briqyard")],
        read_only: vec![path("/etc/briqyard")],
        inaccessible: vec![],
        bind_read_only: binds,
        public_env: vec![EnvAssignment {
            name: ident("RUST_LOG"),
            value: Text::new("info").unwrap(),
        }],
        env_files,
    }
}

fn bind(source: &str, dest: &str) -> BindReadOnly {
    BindReadOnly {
        source: path(source),
        dest: path(dest),
        recursive: false,
    }
}

fn env_file(file: &str) -> EnvFile {
    EnvFile {
        path: path(file),
        optional: false,
    }
}

fn daemon_legacy_sandbox() -> Sandbox {
    sandbox(vec![], vec![env_file("/etc/briqyard/daemon.env")])
}

fn daemon_guarded_sandbox() -> Sandbox {
    sandbox(
        vec![bind(
            "/usr/local/libexec/briqyard/guard-daemon",
            "/usr/local/bin/briqyardd",
        )],
        vec![],
    )
}

#[test]
fn the_fragment_is_the_raw_file_with_its_exact_final_line_feed() {
    let legacy = "[Unit]\nDescription=briqyardd (synthetic)\n\n[Service]\nExecStart=/usr/local/bin/briqyardd serve --config /etc/briqyard/config.yaml\nRestart=on-failure\n";
    assert_eq!(
        fragment_digest(legacy.as_bytes()).unwrap().to_string(),
        "2b60ab1c12936f2b05c9adfee1c995b42954671d2e49cf2882c1b59e6e3cbaca"
    );
    assert_eq!(
        fragment_digest(legacy.trim_end_matches('\n').as_bytes())
            .unwrap()
            .to_string(),
        "33639d0af67787f96dacd79200aa173d39f3e7d8b4b5e60d9e5dce2847d608f9"
    );
    assert!(fragment_digest(b"").is_err());
    assert!(fragment_digest(&vec![b'a'; MAX_FRAGMENT_BYTES + 1]).is_err());
    assert!(fragment_digest(&vec![b'a'; MAX_FRAGMENT_BYTES]).is_ok());
    let crlf = legacy.replace('\n', "\r\n");
    assert_ne!(
        fragment_digest(crlf.as_bytes()).unwrap(),
        fragment_digest(legacy.as_bytes()).unwrap(),
        "no normalization"
    );
}

#[test]
fn argv_is_the_whole_ordered_vector_and_only_the_operation_fields_differ() {
    let guarded = daemon_guarded(1);
    assert_eq!(
        String::from_utf8(encode(&guarded).unwrap()).unwrap(),
        "{\"args\":[\"L3Vzci9sb2NhbC9iaW4vYnJpcXlhcmRk\",\"c2VhbGVkLWd1YXJk\",\"LS1yZXNvdXJjZQ\",\"ZGFlbW9u\",\"LS1vcGVyYXRpb24tZGly\",\"L3Zhci9saWIvYnJpcXlhcmQvc2VhbGVkL2FhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWEvMQ\"],\"exec\":\"L3Vzci9sb2NhbC9iaW4vYnJpcXlhcmRk\",\"format\":\"owner.argv/v1\"}"
    );
    let expected = [
        (
            daemon_guarded(1),
            "2e2d13871b79d62e22fbdc130d9f072b018f9a773a535b58f80146aca28a8648",
        ),
        (
            daemon_guarded(2),
            "d8f3984d222f65693597ed4a9df3a0357e93843e695d2c54afa727711b8777aa",
        ),
        (
            argv(
                "/usr/local/bin/briqyardd",
                &["serve", "--config", "/etc/briqyard/config.yaml"],
            ),
            "820b329f1d1f86d286a0c5deb5b1dfd15a2ecd1935541147b22b323c9b9e5d34",
        ),
        (
            argv(
                "/usr/local/bin/briqyard-fleet",
                &["serve", "--config", "/etc/briqyard/fleet.yaml"],
            ),
            "fe0341cc1fd5337923fa1adeba89a18e3a268e83bbbc723fd41e3318fe4818c6",
        ),
        (
            argv(
                "/usr/local/bin/briqyard-fleet",
                &[
                    "sealed-guard",
                    "--resource",
                    "authority",
                    "--operation-dir",
                    &operation_dir(1),
                ],
            ),
            "c1a3c4a0297235783e310a7d6fb88c02fd5b253398395fa790132389993acb3f",
        ),
    ];
    for (value, want) in expected {
        assert_eq!(value.digest().unwrap().to_string(), want);
    }
}

#[test]
fn argv_refuses_a_merged_or_unanchored_vector() {
    let merged = argv(
        "/usr/local/bin/briqyardd",
        &[
            "sealed-guard --resource daemon",
            "--operation-dir",
            &operation_dir(1),
        ],
    );
    assert_ne!(
        merged.digest().unwrap().to_string(),
        "2e2d13871b79d62e22fbdc130d9f072b018f9a773a535b58f80146aca28a8648",
        "two tokens as one is another vector"
    );
    assert_eq!(
        merged.digest().unwrap().to_string(),
        "5023a3c7e4d0a658455a8e46238198ac91f5f6aa6c89495c630b9bd442b90359"
    );
    assert!(Argv::new("/usr/local/bin/briqyardd", &[]).is_err());
    assert!(Argv::new("/usr/local/bin/briqyardd", &["briqyardd", "serve"]).is_err());
    assert!(Argv::new("relative/briqyardd", &["relative/briqyardd"]).is_err());
    let mut reordered = daemon_guarded(1);
    reordered.args.swap(1, 2);
    assert_ne!(
        reordered.digest().unwrap(),
        daemon_guarded(1).digest().unwrap()
    );
    let mut shifted = daemon_guarded(1);
    shifted.args[0] = Text::new("briqyardd").unwrap();
    let bytes = encode(&shifted).unwrap();
    assert!(decode::<Argv>(&bytes).is_err(), "argv[0] is the executable");
    let mut unknown = String::from_utf8(encode(&daemon_guarded(1)).unwrap()).unwrap();
    unknown.insert_str(1, "\"extra\":1,");
    assert!(decode::<Argv>(unknown.as_bytes()).is_err());
}

#[test]
fn sandbox_digests_match_the_independent_computation_and_every_phase_differs() {
    let legacy = daemon_legacy_sandbox();
    let guarded = daemon_guarded_sandbox();
    assert_eq!(
        legacy.digest().unwrap().to_string(),
        "9e889b2c33ce205f91564eef5f43c4178fd70db87feb9eee10f6379e2357e593"
    );
    assert_eq!(
        guarded.digest().unwrap().to_string(),
        "cf8d13d1096782edfca9bf6cc953fd9aa6f9074428b518c72ac94c40a2163fa9"
    );
    assert_eq!(
        String::from_utf8(encode(&legacy).unwrap()).unwrap(),
        "{\"bind_read_only\":[],\"dynamic_user\":false,\"env_files\":[{\"optional\":false,\"path\":\"L2V0Yy9icmlxeWFyZC9kYWVtb24uZW52\"}],\"families\":{\"mode\":\"allow\",\"names\":[\"AF_INET\",\"AF_INET6\",\"AF_UNIX\"]},\"format\":\"owner.sandbox/v1\",\"gid\":0,\"inaccessible\":[],\"no_new_privileges\":true,\"private_devices\":true,\"private_tmp\":true,\"protect_home\":\"yes\",\"protect_system\":\"strict\",\"public_env\":[{\"name\":\"RUST_LOG\",\"value\":\"aW5mbw\"}],\"read_only\":[\"L2V0Yy9icmlxeWFyZA\"],\"read_write\":[\"L3J1bi9icmlxeWFyZA\",\"L3Zhci9saWIvYnJpcXlhcmQ\"],\"state_dir_mode\":488,\"state_dirs\":[\"briqyard\"],\"supplementary_gids\":[],\"uid\":0,\"umask\":18}"
    );
    let authority_legacy = sandbox(vec![], vec![env_file("/etc/briqyard/fleet.env")]);
    let authority_guarded = sandbox(
        vec![bind(
            "/usr/local/libexec/briqyard/guard-fleet",
            "/usr/local/bin/briqyard-fleet",
        )],
        vec![],
    );
    assert_eq!(
        authority_legacy.digest().unwrap().to_string(),
        "dc28ee2718132bb214417338e0244f95e257e326d89cc117adeffd9a34bb603b"
    );
    assert_eq!(
        authority_guarded.digest().unwrap().to_string(),
        "21c631653f3d024ff9909678b28f4d6f1811ef304e1d40d0f060eab9705388ac"
    );
}

#[test]
fn sandbox_refuses_everything_that_is_not_positively_one_closed_form() {
    type Case = (&'static str, Box<dyn Fn(&mut Sandbox)>);
    let cases: Vec<Case> = vec![
        (
            "groups out of order",
            Box::new(|s| {
                s.supplementary_gids = vec![Uint::new(2).unwrap(), Uint::new(1).unwrap()];
            }),
        ),
        (
            "duplicate group",
            Box::new(|s| {
                s.supplementary_gids = vec![Uint::new(1).unwrap(), Uint::new(1).unwrap()];
            }),
        ),
        (
            "unrestricted families with names",
            Box::new(|s| s.families.mode = FamilyMode::None),
        ),
        (
            "restriction with no names",
            Box::new(|s| s.families.names.clear()),
        ),
        (
            "families out of order",
            Box::new(|s| s.families.names.reverse()),
        ),
        (
            "lowercase family",
            Box::new(|s| s.families.names = vec![ident("af_unix")]),
        ),
        (
            "not an address family",
            Box::new(|s| s.families.names = vec![ident("TCP")]),
        ),
        (
            "state dir with a separator",
            Box::new(|s| s.state_dirs = vec![ident("a/b")]),
        ),
        (
            "state dir alias",
            Box::new(|s| s.state_dirs = vec![ident("..")]),
        ),
        (
            "path set out of order",
            Box::new(|s| s.read_write.reverse()),
        ),
        (
            "duplicate path",
            Box::new(|s| s.read_only.push(path("/etc/briqyard"))),
        ),
        (
            "two binds to one destination",
            Box::new(|s| {
                let b = bind("/usr/local/libexec/briqyard/a", "/usr/local/bin/briqyardd");
                s.bind_read_only = vec![b.clone(), b];
            }),
        ),
        (
            "environment name that is not a variable",
            Box::new(|s| s.public_env[0].name = ident("a-b")),
        ),
        (
            "duplicate environment name",
            Box::new(|s| {
                let e = s.public_env[0].clone();
                s.public_env.push(e);
            }),
        ),
        (
            "duplicate environment file",
            Box::new(|s| {
                s.env_files = vec![
                    env_file("/etc/briqyard/a.env"),
                    env_file("/etc/briqyard/a.env"),
                ];
            }),
        ),
        (
            "permission bits beyond the mode space",
            Box::new(|s| s.umask = Uint::new(0o10000).unwrap()),
        ),
    ];
    for (name, mutate) in cases {
        let mut value = daemon_legacy_sandbox();
        mutate(&mut value);
        assert!(value.digest().is_err(), "{name}");
    }
    let mut ordered = daemon_legacy_sandbox();
    ordered.env_files = vec![
        env_file("/etc/briqyard/b.env"),
        env_file("/etc/briqyard/a.env"),
    ];
    let reversed = {
        let mut other = ordered.clone();
        other.env_files.reverse();
        other
    };
    assert_ne!(
        ordered.digest().unwrap(),
        reversed.digest().unwrap(),
        "environment files keep the manager's lookup order"
    );
}

#[test]
fn fdstore_order_and_every_policy_field_change_the_commitment() {
    let api_ingress = FdStore::new(
        &["api", "ingress"],
        8,
        Preserve::Restart,
        NotifyAccess::Main,
    )
    .unwrap();
    let ingress_api = FdStore::new(
        &["ingress", "api"],
        8,
        Preserve::Restart,
        NotifyAccess::Main,
    )
    .unwrap();
    let yes = FdStore::new(&["api", "ingress"], 8, Preserve::Yes, NotifyAccess::Main).unwrap();
    let empty = FdStore::new(&[], 0, Preserve::No, NotifyAccess::None).unwrap();
    assert_eq!(
        api_ingress.digest().unwrap().to_string(),
        "f1693467bd23f490ef554fce6a9a5d9031560c761bfa871792171ae35b71f19a"
    );
    assert_eq!(
        ingress_api.digest().unwrap().to_string(),
        "081d710c525723679918eb5145d41dd5fa9db5d31f0580f94b5723801b8ab5c2",
        "same count, other order, other hash"
    );
    assert_eq!(
        yes.digest().unwrap().to_string(),
        "c4f799a5fb9907ed6a3b2dd6616b7a9e3f043c6de6a6d39634f794e8902bce42"
    );
    assert_eq!(
        empty.digest().unwrap().to_string(),
        "f1173eeb2d278a9ef384cf20685d677f19ed49bca7835dab14f20278a74f880c"
    );
    assert_eq!(
        String::from_utf8(encode(&empty).unwrap()).unwrap(),
        "{\"format\":\"owner.fdstore/v1\",\"listeners\":{\"count\":0,\"names\":\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\",\"store_max\":0},\"notify_access\":\"none\",\"preserve\":\"no\"}"
    );
    assert_eq!(
        api_ingress.listeners.names.to_string(),
        "b57faf2efe9cc2a8142d26504192b5f4112d3b14ad8220dbdc1958fd7ac9cd2e"
    );
    assert_eq!(
        empty.listeners.names,
        crate::execution::sealed::prim::HexDigest::of(b""),
        "empty bytes iff positively empty"
    );
}

#[test]
fn fdstore_refuses_names_it_cannot_order_or_a_count_that_disagrees() {
    for names in [&["a:b"][..], &[""], &["a", "a"], &["white space"]] {
        assert!(
            FdStore::new(names, 8, Preserve::No, NotifyAccess::None).is_err(),
            "{names:?}"
        );
    }
    let mut lying = FdStore::new(&["api"], 8, Preserve::No, NotifyAccess::None).unwrap();
    lying.listeners.names = crate::execution::sealed::prim::HexDigest::of(b"");
    assert!(
        lying.digest().is_err(),
        "nonempty count with the empty digest"
    );
    let mut zero = FdStore::new(&[], 0, Preserve::No, NotifyAccess::None).unwrap();
    zero.listeners.names = crate::execution::sealed::prim::HexDigest::of(b"api");
    assert!(zero.digest().is_err(), "zero count with a nonempty digest");
    let bytes = encode(&lying).unwrap();
    assert!(decode::<FdStore>(&bytes).is_err());
}

const GOLDEN: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/testdata/owner_v1/sealed_owner_v1.golden"
));

fn golden_arm() -> ArmReceipt {
    let line = GOLDEN
        .lines()
        .find(|line| line.starts_with("arm\t"))
        .unwrap();
    decode(line.split('\t').nth(2).unwrap().as_bytes()).unwrap()
}

fn guarded_fragment(resource: &str, binary: &str, restart: &str) -> Vec<u8> {
    format!(
        "[Unit]\nDescription={binary} (synthetic)\n\n[Service]\nExecStart=/usr/local/bin/{binary} sealed-guard --resource {resource} --operation-dir /var/lib/briqyard/sealed/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/1\n{restart}"
    )
    .into_bytes()
}

fn daemon_receipt(version: u64, names: &[&str]) -> ArmReceipt {
    let mut receipt = golden_arm();
    receipt.resource = Resource::Daemon;
    receipt.lease = HexDigest::from_raw([0x88; 32]);
    receipt.version = PosInt::new(version).unwrap();
    receipt.fragment = fragment_digest(&guarded_fragment(
        "daemon",
        "briqyardd",
        "Restart=on-failure\nRestartForceExitStatus=75\n",
    ))
    .unwrap();
    receipt.argv = daemon_guarded(1).digest().unwrap();
    receipt.sandbox = daemon_guarded_sandbox().digest().unwrap();
    receipt.fdstore = FdStore::new(names, 8, Preserve::Restart, NotifyAccess::Main)
        .unwrap()
        .digest()
        .unwrap();
    receipt
}

fn authority_receipt() -> ArmReceipt {
    let mut receipt = golden_arm();
    receipt.resource = Resource::Authority;
    receipt.lease = HexDigest::from_raw([0x99; 32]);
    receipt.fragment = fragment_digest(&guarded_fragment(
        "authority",
        "briqyard-fleet",
        "Restart=no\n",
    ))
    .unwrap();
    receipt.argv = argv(
        "/usr/local/bin/briqyard-fleet",
        &[
            "sealed-guard",
            "--resource",
            "authority",
            "--operation-dir",
            &operation_dir(1),
        ],
    )
    .digest()
    .unwrap();
    receipt.sandbox = sandbox(
        vec![bind(
            "/usr/local/libexec/briqyard/guard-fleet",
            "/usr/local/bin/briqyard-fleet",
        )],
        vec![],
    )
    .digest()
    .unwrap();
    receipt.fdstore = FdStore::new(&[], 0, Preserve::No, NotifyAccess::None)
        .unwrap()
        .digest()
        .unwrap();
    receipt
}

#[test]
fn arm_receipts_built_from_the_preimages_hash_to_the_independent_values() {
    let api_ingress = ["api", "ingress"];
    assert_eq!(
        h(&daemon_receipt(3, &api_ingress)).unwrap().to_string(),
        "31ba44462295e7f43cbefec828be080665bf78e5e9fb40e6f817d65203aa1a53"
    );
    assert_eq!(
        h(&authority_receipt()).unwrap().to_string(),
        "1acaa71834c34791c9824710cd71e9d94c621c0008033d71531977ec7e749a24"
    );
    assert_eq!(
        h(&daemon_receipt(4, &api_ingress)).unwrap().to_string(),
        "d050e9b65ea90f3ea3b2da4faf4c9e401ab76368021ee3bbc46936caa3097d3e",
        "a changed version is a changed receipt"
    );
    assert_eq!(
        h(&daemon_receipt(3, &["ingress", "api"]))
            .unwrap()
            .to_string(),
        "1009747f23e63ee7495a8d9ff66d9e63bec73a3d42aad90240d0af9a18edf41e",
        "the same listeners in another order is a changed receipt"
    );
}
