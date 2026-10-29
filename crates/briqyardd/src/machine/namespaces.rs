//! Namespaces: their view and their removal.

use super::*;

impl Manager {
    pub(super) fn namespace_of(&self, id: &str) -> Option<Namespace> {
        self.inner.namespaces.lock().unwrap().get(id).cloned()
    }

    pub fn namespaces(&self) -> Vec<api::Namespace> {
        let namespaces: Vec<Namespace> = self
            .inner
            .namespaces
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect();
        let mut out: Vec<api::Namespace> =
            namespaces.iter().map(|t| self.namespace_view(t)).collect();
        out.sort_by(|a, b| a.id.cmp(&b.id));
        out
    }

    pub fn namespace(&self, id: &str) -> Result<api::Namespace, MError> {
        let t = self.namespace_of(id).ok_or(MError::NotFound)?;
        Ok(self.namespace_view(&t))
    }

    fn namespace_view(&self, t: &Namespace) -> api::Namespace {
        let machines = self
            .inner
            .machines
            .lock()
            .unwrap()
            .values()
            .filter(|e| {
                let r = e.rec.lock().unwrap();
                r.namespace == t.rec.id && r.is_namespaces()
            })
            .count();
        let gateway = self.gateway_of(&t.rec.id).map(|e| {
            let r = e.snapshot();
            api::GatewayView {
                state: r.state,
                ip: r.ip,
                port: r.ports.first().copied().unwrap_or(0),
                machine_id: r.id,
                error: r.error,
            }
        });
        api::Namespace {
            id: t.rec.id.clone(),
            subnet: t.subnet.cidr(),
            router: t.subnet.gateway().to_string(),
            machines,
            created_at: t.rec.created_at,
            host: String::new(),
            region: String::new(),
            gateway,
        }
    }

    /// Removes the network of a namespace with no machine left, and its gateway first. Missing
    /// is success.
    pub async fn delete_namespace(&self, id: &str) -> Result<(), MError> {
        check_namespace_id(id)?;
        let t = match self.namespace_of(id) {
            Some(t) => t,
            None => return Ok(()),
        };
        let in_use = self.inner.machines.lock().unwrap().values().any(|e| {
            let r = e.rec.lock().unwrap();
            r.namespace == id && r.is_namespaces()
        });
        if in_use {
            return Err(MError::NamespaceInUse);
        }
        {
            let _turn = t.lock.lock().await;
            if let Some(gw) = self.gateway_of(id) {
                self.destroy_machine(&gw.snapshot().id, None).await?;
            }
        }
        self.inner.dns.unset(t.subnet.gateway());
        self.inner.net.delete_bridge(t.rec.subnet_index).await?;
        self.inner.namespaces.lock().unwrap().remove(id);
        self.inner.store.delete(crate::store::NAMESPACES, id)?;
        Ok(())
    }
}
