//! Durable evacuation holds. Acquisition never waits behind an active operation.
use super::*;

tokio::task_local! { pub static JOB: Option<String>; }

impl Manager {
    pub(super) fn check_hold(&self, rec: &Record) -> Result<(), MError> {
        if let Some(holder) = &rec.held {
            if !JOB
                .try_with(|job| job.as_ref() == Some(holder))
                .unwrap_or(false)
            {
                return Err(MError::Held(holder.clone()));
            }
        }
        Ok(())
    }

    pub(super) fn operation(
        &self,
        e: &Arc<Entry>,
    ) -> Result<tokio::sync::OwnedRwLockReadGuard<()>, MError> {
        let guard = e
            .operations
            .clone()
            .try_read_owned()
            .map_err(|_| MError::Busy(e.snapshot().id))?;
        self.check_hold(&e.snapshot())?;
        Ok(guard)
    }

    pub async fn hold_machine(&self, id: &str, job: &str) -> Result<(), MError> {
        if job.is_empty() || job.len() > 128 {
            return Err(invalid("hold needs a job id of 1..128 bytes"));
        }
        let e = self.own_entry(id)?;
        let _operation = e
            .operations
            .clone()
            .try_write_owned()
            .map_err(|_| MError::Busy(id.into()))?;
        let _backup = e
            .backup_turn
            .clone()
            .try_lock_owned()
            .map_err(|_| MError::Busy(id.into()))?;
        let _lock = e.lock.lock().await;
        let mut r = e.rec.lock().unwrap();
        if let Some(holder) = &r.held {
            return if holder == job {
                Ok(())
            } else {
                Err(MError::Held(holder.clone()))
            };
        }
        if r.template_birth.is_some()
            || r.warm_slot.is_some()
            || r.launch_identity.is_some()
            || r.clone_origin.is_some()
        {
            return Err(invalid("host-local machine cannot be held for evacuation"));
        }
        if r.state != state::STOPPED {
            return Err(MError::BadState(format!(
                "{}: hold requires stopped",
                r.state
            )));
        }
        self.inner.store.put_durable("machines", id, &{
            let mut next = r.clone();
            next.held = Some(job.into());
            next
        })?;
        r.held = Some(job.into());
        Ok(())
    }

    pub fn hold_owner(&self, id: &str) -> Result<Option<String>, MError> {
        Ok(self.entry(id)?.snapshot().held)
    }

    pub async fn release_machine(&self, id: &str, job: &str, force: bool) -> Result<(), MError> {
        let e = self.own_entry(id)?;
        let _operation = e
            .operations
            .clone()
            .try_write_owned()
            .map_err(|_| MError::Busy(id.into()))?;
        let _lock = e.lock.lock().await;
        let mut r = e.rec.lock().unwrap();
        if !force && r.held.as_deref().is_some_and(|holder| holder != job) {
            return Err(MError::Held(r.held.clone().unwrap()));
        }
        let mut next = r.clone();
        next.held = None;
        self.inner.store.put_durable("machines", id, &next)?;
        r.held = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::tests::{harness_config, record};

    #[tokio::test]
    async fn stopped_hold_survives_disk_roundtrip_and_refuses_wake_and_mutation() {
        let h = harness_config(|_| {}).await;
        let e = h.add("m_held", state::STOPPED, 256);
        h.m.hold_machine("m_held", "ev_1").await.unwrap();
        let saved: Record = h.m.inner.store.get("machines", "m_held").unwrap().unwrap();
        assert_eq!(saved.held.as_deref(), Some("ev_1"));
        let recovered = Entry::new(saved, e.events.clone());
        h.m.inner
            .machines
            .lock()
            .unwrap()
            .insert("m_held".into(), recovered);
        assert!(matches!(
            h.m.start("m_held", None).await,
            Err(MError::Held(_))
        ));
        assert!(matches!(
            h.m.wake("m_held", None).await,
            Err(MError::Held(_))
        ));
        assert!(matches!(
            h.m.machine_addr("m_held", true).await,
            Err(MError::Held(_))
        ));
        assert!(matches!(
            h.m.destroy("m_held", None).await,
            Err(MError::Held(_))
        ));
        assert!(matches!(
            h.m.update("m_held", Default::default(), None).await,
            Err(MError::Held(_))
        ));
        assert!(matches!(
            h.m.hold_machine("m_held", "ev_2").await,
            Err(MError::Held(_))
        ));
        assert!(matches!(
            h.m.release_machine("m_held", "ev_2", false).await,
            Err(MError::Held(_))
        ));
        JOB.scope(Some("ev_1".into()), async {
            let e = h.m.entry("m_held").unwrap();
            assert!(h.m.operation(&e).is_ok());
        })
        .await;
        h.m.release_machine("m_held", "ev_1", false).await.unwrap();
        assert!(h.m.entry("m_held").unwrap().snapshot().held.is_none());
    }

    #[tokio::test]
    async fn hold_refuses_an_active_backup_turn_or_an_operation_without_writing() {
        let h = harness_config(|_| {}).await;
        let e = h.add("m_held", state::STOPPED, 256);
        let backup = e.backup_turn.clone().lock_owned().await;
        assert!(matches!(
            h.m.hold_machine("m_held", "ev_1").await,
            Err(MError::Busy(_))
        ));
        assert!(e.snapshot().held.is_none());
        drop(backup);
        let operation = h.m.operation(&e).unwrap();
        assert!(matches!(
            h.m.hold_machine("m_held", "ev_1").await,
            Err(MError::Busy(_))
        ));
        drop(operation);
        h.m.hold_machine("m_held", "ev_1").await.unwrap();
        assert!(matches!(h.m.operation(&e), Err(MError::Held(_))));
        // Old records have no hold and retain their former behavior.
        let mut old = serde_json::to_value(record()).unwrap();
        old.as_object_mut().unwrap().remove("held");
        assert!(serde_json::from_value::<Record>(old)
            .unwrap()
            .held
            .is_none());
    }
}

impl Manager {
    /// Compare configuration without sending write-only values to the fleet journal.
    /// Disk receive completion is represented by a stopped state; a partial create
    /// remains creating/error and cannot produce a successful verification.
    pub async fn evacuation_manifest(&self, id: &str) -> Result<serde_json::Value, MError> {
        let e = self.own_entry(id)?;
        let _lock = e.lock.lock().await;
        let rec = e.snapshot();
        let value = serde_json::to_value(&rec).map_err(anyhow::Error::from)?;
        let mut config = serde_json::Map::new();
        for key in [
            "id",
            "namespace",
            "role",
            "name",
            "image",
            "image_key",
            "image_digest",
            "image_config_digest",
            "image_config",
            "root_key",
            "entrypoint",
            "cmd",
            "env",
            "files",
            "size",
            "runtime_class",
            "volume",
            "ports",
            "sleep",
            "restart",
            "probes",
            "egress",
            "limits",
            "disk_limits",
            "metadata",
            "pending",
            "created_at",
        ] {
            config.insert(key.into(), value[key].clone());
        }
        config.insert(
            "backup_policy".into(),
            serde_json::to_value(&rec.backup.policy).map_err(anyhow::Error::from)?,
        );
        let bytes = serde_json::to_vec(&config).map_err(anyhow::Error::from)?;
        let digest = hex::encode(ring::digest::digest(&ring::digest::SHA256, &bytes));
        let root = self.inner.zfs.volsize(&rec.root_dataset()).await?;
        let data = if rec.volume.is_some() {
            self.inner.zfs.volsize(&rec.data_dataset()).await?
        } else {
            0
        };
        Ok(
            json!({"id": id, "state": rec.state, "held": rec.held, "ip": rec.ip, "config_digest": digest, "root_bytes": root, "data_bytes": data, "host_local": rec.template_birth.is_some() || rec.warm_slot.is_some() || rec.launch_identity.is_some() || rec.clone_origin.is_some()}),
        )
    }
}
