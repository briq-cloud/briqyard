//! A machine's endpoints: the ports the host exposes for it.

use super::*;

impl Manager {
    // --- endpoints ---

    pub fn endpoint_events(&self) -> broadcast::Receiver<(EndpointRec, bool)> {
        self.inner.endpoint_events.subscribe()
    }

    pub fn all_endpoints(&self) -> Vec<EndpointRec> {
        let mut out: Vec<EndpointRec> = self
            .inner
            .endpoints
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect();
        out.sort_by_key(|a| a.created_at);
        out
    }

    pub fn endpoint(&self, id: &str) -> Option<EndpointRec> {
        self.inner.endpoints.lock().unwrap().get(id).cloned()
    }

    pub fn endpoints_of(&self, machine_id: &str) -> Vec<api::Endpoint> {
        let mut out: Vec<api::Endpoint> = self
            .inner
            .endpoints
            .lock()
            .unwrap()
            .values()
            .filter(|e| e.machine_id == machine_id)
            .map(|e| self.endpoint_view(e))
            .collect();
        out.sort_by_key(|a| a.created_at);
        out
    }

    pub fn endpoint_view(&self, e: &EndpointRec) -> api::Endpoint {
        let address = match e.protocol.as_str() {
            "http" => format!("http://{}", e.host),
            _ => format!("{}:{}", self.inner.advertise, e.host_port.unwrap_or(0)),
        };
        api::Endpoint {
            id: e.id.clone(),
            machine_id: e.machine_id.clone(),
            port: e.port,
            protocol: e.protocol.clone(),
            host_port: e.host_port,
            host: e.host.clone(),
            address,
            created_at: e.created_at,
        }
    }

    pub fn create_endpoint(
        &self,
        machine_id: &str,
        req: api::CreateEndpointRequest,
    ) -> Result<api::Endpoint, MError> {
        let e = self.own_entry(machine_id)?;
        if req.port == 0 {
            return Err(invalid("port must be 1..65535"));
        }
        let proto = if req.protocol.is_empty() {
            "tcp".to_string()
        } else {
            req.protocol.clone()
        };
        if proto != "tcp" && proto != "http" {
            return Err(invalid("protocol must be tcp or http"));
        }
        let tenant = e.snapshot().tenant;
        let name = e.snapshot().name;
        let mut endpoints = self.inner.endpoints.lock().unwrap();
        if let Some(ex) = endpoints
            .values()
            .find(|ex| ex.machine_id == machine_id && ex.port == req.port && ex.protocol == proto)
        {
            return Ok(self.endpoint_view(ex));
        }
        let mut ep = EndpointRec {
            id: new_id("ep"),
            machine_id: machine_id.to_string(),
            tenant,
            port: req.port,
            protocol: proto.clone(),
            host_port: None,
            host: String::new(),
            created_at: Utc::now(),
        };
        if proto == "tcp" {
            let used: Vec<u16> = endpoints.values().filter_map(|x| x.host_port).collect();
            ep.host_port = Some(free_tcp_port(&self.inner.cfg.ingress.tcp_ports, used)?);
        } else {
            if self.inner.cfg.ingress.http.is_empty() {
                return Err(invalid(
                    "http endpoints are not enabled on this host (ingress.http)",
                ));
            }
            let label = if req.host.is_empty() {
                format!("{name}-{}", &new_id("")[1..5])
            } else {
                req.host.clone()
            };
            if !api::valid_name(&label) {
                return Err(invalid("host must be a DNS label"));
            }
            ep.host = format!("{label}.{}", self.inner.cfg.ingress.domain);
            if endpoints.values().any(|x| x.host == ep.host) {
                return Err(invalid(format!("host {} is taken", ep.host)));
            }
        }
        self.inner.store.put("endpoints", &ep.id, &ep)?;
        endpoints.insert(ep.id.clone(), ep.clone());
        drop(endpoints);
        let _ = self.inner.endpoint_events.send((ep.clone(), true));
        Ok(self.endpoint_view(&ep))
    }

    pub fn delete_endpoint(&self, id: &str) -> Result<(), MError> {
        let ep = self.inner.endpoints.lock().unwrap().remove(id);
        if let Some(ep) = ep {
            self.inner.store.delete("endpoints", id)?;
            let _ = self.inner.endpoint_events.send((ep, false));
        }
        Ok(())
    }
}

pub(super) fn port_range(s: &str) -> Result<(u16, u16), MError> {
    let bad = || invalid(format!("ingress.tcp_ports {s:?}: want \"lo-hi\""));
    let (lo, hi) = s.split_once('-').ok_or_else(bad)?;
    let lo: u16 = lo.trim().parse().map_err(|_| bad())?;
    let hi: u16 = hi.trim().parse().map_err(|_| bad())?;
    if lo == 0 || lo > hi {
        return Err(bad());
    }
    Ok((lo, hi))
}

/// The lowest host port in the ingress range no endpoint holds.
pub(super) fn free_tcp_port(spec: &str, used: Vec<u16>) -> Result<u16, MError> {
    let (lo, hi) = port_range(spec)?;
    let used = used.into_iter().map(u32::from).collect();
    netw::first_free(used, lo as u32, hi as u32)
        .map(|p| p as u16)
        .ok_or_else(|| MError::Capacity("no tcp endpoint port left".into()))
}
