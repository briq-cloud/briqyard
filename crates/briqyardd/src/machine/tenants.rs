//! Tenants: their view and their removal.

use super::*;

impl Manager {
    pub(super) fn tenant_of(&self, id: &str) -> Option<Tenant> {
        self.inner.tenants.lock().unwrap().get(id).cloned()
    }

    pub fn tenants(&self) -> Vec<api::Tenant> {
        let tenants: Vec<Tenant> = self
            .inner
            .tenants
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect();
        let mut out: Vec<api::Tenant> = tenants.iter().map(|t| self.tenant_view(t)).collect();
        out.sort_by(|a, b| a.id.cmp(&b.id));
        out
    }

    pub fn tenant(&self, id: &str) -> Result<api::Tenant, MError> {
        let t = self.tenant_of(id).ok_or(MError::NotFound)?;
        Ok(self.tenant_view(&t))
    }

    fn tenant_view(&self, t: &Tenant) -> api::Tenant {
        let machines = self
            .inner
            .machines
            .lock()
            .unwrap()
            .values()
            .filter(|e| {
                let r = e.rec.lock().unwrap();
                r.tenant == t.rec.id && r.is_tenants()
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
        api::Tenant {
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

    /// Removes the network of a tenant with no machine left, and its gateway first. Missing
    /// is success.
    pub async fn delete_tenant(&self, id: &str) -> Result<(), MError> {
        check_tenant_id(id)?;
        let t = match self.tenant_of(id) {
            Some(t) => t,
            None => return Ok(()),
        };
        let in_use = self.inner.machines.lock().unwrap().values().any(|e| {
            let r = e.rec.lock().unwrap();
            r.tenant == id && r.is_tenants()
        });
        if in_use {
            return Err(MError::TenantInUse);
        }
        {
            let _turn = t.lock.lock().await;
            if let Some(gw) = self.gateway_of(id) {
                self.destroy_machine(&gw.snapshot().id, None).await?;
            }
        }
        self.inner.dns.unset(t.subnet.gateway());
        self.inner.net.delete_bridge(t.rec.subnet_index).await?;
        self.inner.tenants.lock().unwrap().remove(id);
        self.inner.store.delete("tenants", id)?;
        Ok(())
    }
}
