//! An image layer from any registry: tar entries with any name, type and link, extracted
//! into a root by the extractor (`image/extract.rs`, Linux only). Nothing may be written,
//! removed or changed outside the root.
//!
//! The entries are built from the input with valid checksums (the tar crate refuses the rest
//! before the extractor sees it) and raw names, `..` and absolute links included. The root
//! sits two levels inside a temporary directory, beside a file and a directory a layer must
//! not reach; run it as a user who owns nothing else of value (docs/DEVELOPMENT.md).
#![no_main]

use arbitrary::Arbitrary;
use briqyardd::image::extract::extract;
use libfuzzer_sys::fuzz_target;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

#[derive(Arbitrary, Debug)]
enum Kind {
    Directory,
    Regular,
    Symlink,
    Link,
    Char,
}

#[derive(Arbitrary, Debug)]
struct Entry {
    name: Vec<u8>,
    kind: Kind,
    link: Vec<u8>,
    mode: u16,
    body: Vec<u8>,
}

fn archive(entries: &[Entry]) -> Vec<u8> {
    let mut b = tar::Builder::new(Vec::new());
    for e in entries {
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(match e.kind {
            Kind::Directory => tar::EntryType::Directory,
            Kind::Regular => tar::EntryType::Regular,
            Kind::Symlink => tar::EntryType::Symlink,
            Kind::Link => tar::EntryType::Link,
            Kind::Char => tar::EntryType::Char,
        });
        h.set_mode(e.mode as u32);
        h.set_size(e.body.len() as u64);
        let g = h.as_gnu_mut().unwrap();
        let (n, l) = (e.name.len().min(99), e.link.len().min(99));
        g.name[..n].copy_from_slice(&e.name[..n]);
        g.linkname[..l].copy_from_slice(&e.link[..l]);
        h.set_cksum();
        b.append(&h, &e.body[..]).unwrap();
    }
    b.into_inner().unwrap()
}

fuzz_target!(|entries: Vec<Entry>| {
    let base = tempfile::tempdir().unwrap();
    let outer = base.path().join("a");
    let root = outer.join("root");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir(outer.join("out")).unwrap();
    std::fs::write(outer.join("keep"), "k").unwrap();
    std::fs::set_permissions(&outer, std::fs::Permissions::from_mode(0o711)).unwrap();
    let _ = extract(&root, &archive(&entries)[..]);
    assert_eq!(names(&outer), ["keep", "out", "root"], "beside the root");
    assert_eq!(names(base.path()), ["a"], "beside the root's parent");
    assert_eq!(std::fs::read_to_string(outer.join("keep")).unwrap(), "k");
    let keep = std::fs::symlink_metadata(outer.join("keep")).unwrap();
    assert_eq!(keep.nlink(), 1, "a file outside the root linked from it");
    assert_eq!(std::fs::read_dir(outer.join("out")).unwrap().count(), 0);
    let mode = std::fs::metadata(&outer).unwrap().permissions().mode() & 0o7777;
    assert_eq!(mode, 0o711, "the root's parent changed mode");
    unlock(&root);
});

/// The names in a directory, sorted.
fn names(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

/// Gives back what a layer made unreadable, so the temporary directory can be removed.
fn unlock(p: &Path) {
    let Ok(m) = std::fs::symlink_metadata(p) else {
        return;
    };
    if m.is_dir() {
        let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700));
        for e in std::fs::read_dir(p).into_iter().flatten().flatten() {
            unlock(&e.path());
        }
    }
}
