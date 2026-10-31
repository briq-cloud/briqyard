//! Lifetime membership-permission and held-directory joins for the supported domain.
use super::{
    fs::{Dir, Membership, Owner},
    unit,
};
use std::{io, path::Path, sync::Mutex};

pub(in crate::fc) struct Namespace {
    proc: Dir,
    start: u64,
    root: Dir,
    slice: Dir,
    service: Dir,
    root_members: Membership,
    slice_members: Membership,
    service_members: Membership,
    parent: Mutex<Option<(Dir, Membership)>>,
}
impl Namespace {
    pub(super) fn capture(proc: &Dir, start: u64, root: &Dir, service: &Dir) -> io::Result<Self> {
        let slice = root.child(c"system.slice")?;
        let namespace = Self {
            proc: Dir(proc.0.try_clone()?),
            start,
            root: Dir(root.0.try_clone()?),
            service: Dir(service.0.try_clone()?),
            root_members: Membership::capture(&root.0, Owner::ROOT)?,
            slice_members: Membership::capture(&slice.0, Owner::ROOT)?,
            service_members: Membership::capture(&service.0, Owner::ROOT)?,
            slice,
            parent: Mutex::new(None),
        };
        namespace.check()?;
        Ok(namespace)
    }
    pub(in crate::fc) fn check(&self) -> io::Result<()> {
        unit::self_membership(&self.proc, self.start)?;
        if !self.root.same(&unit::root_cgroup()?)?
            || !self.slice.same(&self.root.child(c"system.slice")?)?
            || !self.service.same(&unit::actual_group(&self.root)?)?
        {
            return Err(super::fs::invalid());
        }
        self.root_members.check()?;
        self.slice_members.check()?;
        self.service_members.check()?;
        let mut parent = self.parent.lock().unwrap();
        match self.root.child(c"firecracker") {
            Ok(current) => {
                current.owned(Owner::ROOT, false)?;
                if let Some((held, members)) = parent.as_ref() {
                    if !held.same(&current)? {
                        return Err(super::fs::invalid());
                    }
                    members.check()?;
                } else {
                    let members = Membership::capture(&current.0, Owner::ROOT)?;
                    *parent = Some((current, members));
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound && parent.is_none() => {}
            Err(e) => return Err(e),
        }
        // The proc directory itself is held, not a fresh numeric-PID observation.
        let current = Dir::absolute(Path::new(&format!("/proc/{}", std::process::id())))?;
        if !self.proc.same(&current)? {
            return Err(super::fs::invalid());
        }
        Ok(())
    }
    pub(super) fn service_pids(&self) -> io::Result<Vec<u32>> {
        self.service_members.procs()
    }
}
