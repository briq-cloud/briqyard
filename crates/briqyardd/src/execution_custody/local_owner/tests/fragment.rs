use super::super::fragment::read_fragment;
use super::super::OwnerError;
use briqyard_api::execution::sealed::inputs::Path;
use briqyard_api::execution::sealed::preimage::{fragment_digest, MAX_FRAGMENT_BYTES};
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

struct Tree {
    dir: tempfile::TempDir,
    owner: u32,
}

impl Tree {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let owner = std::fs::metadata(dir.path()).unwrap().uid();
        std::fs::create_dir(dir.path().join("units")).unwrap();
        std::fs::set_permissions(
            dir.path().join("units"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        Self { dir, owner }
    }

    fn write(&self, name: &str, bytes: &[u8], mode: u32) {
        let file = self.dir.path().join("units").join(name);
        std::fs::write(&file, bytes).unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn read(&self, name: &str) -> Result<Vec<u8>, OwnerError> {
        read_fragment(
            self.dir.path(),
            &Path::new(format!("/units/{name}")).unwrap(),
            self.owner,
        )
    }
}

fn refused<T: std::fmt::Debug>(result: Result<T, OwnerError>) {
    assert!(
        matches!(result, Err(OwnerError::Refused(_) | OwnerError::Io { .. })),
        "{result:?}"
    );
}

#[test]
fn the_exact_bytes_come_back_with_their_final_line_feed_or_without() {
    let tree = Tree::new();
    tree.write("with.service", b"[Service]\nExecStart=/bin/true\n", 0o644);
    tree.write("without.service", b"[Service]\nExecStart=/bin/true", 0o644);
    tree.write(
        "crlf.service",
        b"[Service]\r\nExecStart=/bin/true\r\n",
        0o644,
    );
    let with = tree.read("with.service").unwrap();
    assert_eq!(with, b"[Service]\nExecStart=/bin/true\n");
    assert_ne!(
        fragment_digest(&with).unwrap(),
        fragment_digest(&tree.read("without.service").unwrap()).unwrap()
    );
    assert_eq!(
        tree.read("crlf.service").unwrap(),
        b"[Service]\r\nExecStart=/bin/true\r\n"
    );
}

#[test]
fn links_special_files_other_writers_and_bad_sizes_refuse() {
    let tree = Tree::new();
    tree.write("real.service", b"[Service]\n", 0o644);
    symlink("real.service", tree.dir.path().join("units/alias.service")).unwrap();
    refused(tree.read("alias.service"));

    std::fs::hard_link(
        tree.dir.path().join("units/real.service"),
        tree.dir.path().join("units/second.service"),
    )
    .unwrap();
    refused(tree.read("real.service"));
    refused(tree.read("second.service"));

    tree.write("group.service", b"[Service]\n", 0o664);
    refused(tree.read("group.service"));
    tree.write("other.service", b"[Service]\n", 0o646);
    refused(tree.read("other.service"));

    tree.write("empty.service", b"", 0o644);
    refused(tree.read("empty.service"));
    tree.write("large.service", &vec![b'a'; MAX_FRAGMENT_BYTES + 1], 0o644);
    refused(tree.read("large.service"));
    tree.write("limit.service", &vec![b'a'; MAX_FRAGMENT_BYTES], 0o644);
    assert_eq!(
        tree.read("limit.service").unwrap().len(),
        MAX_FRAGMENT_BYTES
    );

    std::fs::create_dir(tree.dir.path().join("units/directory.service")).unwrap();
    refused(tree.read("directory.service"));
    refused(tree.read("missing.service"));
}

#[test]
fn an_ancestor_that_is_linked_or_writable_by_others_refuses_the_whole_path() {
    let tree = Tree::new();
    tree.write("a.service", b"[Service]\n", 0o644);
    std::fs::set_permissions(
        tree.dir.path().join("units"),
        std::fs::Permissions::from_mode(0o775),
    )
    .unwrap();
    refused(tree.read("a.service"));
    std::fs::set_permissions(
        tree.dir.path().join("units"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    tree.read("a.service").unwrap();

    std::fs::rename(tree.dir.path().join("units"), tree.dir.path().join("real")).unwrap();
    symlink("real", tree.dir.path().join("units")).unwrap();
    refused(tree.read("a.service"));
}

#[test]
fn another_owner_refuses() {
    let tree = Tree::new();
    tree.write("a.service", b"[Service]\n", 0o644);
    let stranger = tree.owner + 1;
    refused(read_fragment(
        tree.dir.path(),
        &Path::new("/units/a.service").unwrap(),
        stranger,
    ));
}
