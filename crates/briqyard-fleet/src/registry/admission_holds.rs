//! The capacity a placement admission holds for its requirements until each is dispatched
//! (ADR 0128). A hold of the same kind as a create's (ADR 0044), tagged with the requirement it
//! is for and given a deadline the heartbeat prunes.

use super::{Hold, Registry};
use chrono::{DateTime, Utc};

impl Registry {
    /// Holds `need_mb` of memory, `need_disk_mb` and `need_cpu_millis` on `host` for the
    /// requirement `owner`, given back at `deadline` if no dispatch has taken it over. 0: no such
    /// host, nothing held.
    pub fn hold_for(
        &mut self,
        host: &str,
        need: (u32, u64, u32),
        owner: String,
        deadline: DateTime<Utc>,
    ) -> u64 {
        let id = self.hold(host, need.0, need.1, need.2);
        if let Some(hold) = self
            .hosts
            .get_mut(host)
            .and_then(|h| h.holds.iter_mut().find(|x| x.id == id))
        {
            hold.owner = Some(owner);
            hold.deadline = Some(deadline);
        }
        id
    }

    /// Takes the hold of requirement `owner` off `host`, giving back what it took, and returns
    /// it: a dispatch counts the requirement's own hold as free while it checks the host's room,
    /// and puts it back (`restore_hold`) if the room is not there.
    pub fn take_over_hold(&mut self, host: &str, owner: &str) -> Option<Hold> {
        let h = self.hosts.get_mut(host)?;
        let i = h
            .holds
            .iter()
            .position(|x| x.owner.as_deref() == Some(owner))?;
        Some(h.give_back(i))
    }

    /// Takes `hold` again on `host`, as it was.
    pub fn restore_hold(&mut self, host: &str, hold: Hold) {
        if let Some(h) = self.hosts.get_mut(host) {
            h.take(hold);
        }
    }

    /// Gives back every hold whose owner starts with `prefix`: an admission cancelled or expired.
    pub fn release_owned(&mut self, prefix: &str) {
        for h in self.hosts.values_mut() {
            while let Some(i) = h
                .holds
                .iter()
                .position(|x| x.owner.as_ref().is_some_and(|o| o.starts_with(prefix)))
            {
                h.give_back(i);
            }
        }
    }

    /// Gives back the admission holds whose deadline is before `now`.
    pub fn expire_holds(&mut self, now: DateTime<Utc>) {
        for h in self.hosts.values_mut() {
            while let Some(i) = h
                .holds
                .iter()
                .position(|x| x.deadline.is_some_and(|d| d < now))
            {
                h.give_back(i);
            }
        }
    }
}

#[cfg(test)]
impl Hold {
    /// Whether a placement admission made it and no dispatch has taken it over.
    pub fn is_admission(&self) -> bool {
        self.owner.is_some()
    }
}
