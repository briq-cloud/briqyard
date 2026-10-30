//! A server joins on its own (ADR 0057; Kubernetes's `kubeadm join` with a bootstrap token):
//! the operator mints a one-time token, the server presents it with a few facts, and the fleet
//! answers with what the SSH bootstrap sends a host added by hand. The fleet also serves the two
//! scripts that do the rest on the server: `install.sh` (asks the join, runs the bootstrap) and
//! `bootstrap-host.sh` (the one the SSH path runs).

use super::*;

/// What a host runs to join: `curl -fsSL <fleet>/install.sh | FLEET_URL=… JOIN_TOKEN=… sh`.
const INSTALL: &str = include_str!("../../../hack/install.sh");

const SHORTEST_TTL: i64 = 60;

fn invalid(m: impl Into<String>) -> Refusal {
    err(StatusCode::BAD_REQUEST, "invalid", m)
}

/// The bootstrap path (SSH or join) is off: nothing is installed on a server by this fleet.
fn bootstrap_on(b: &config::Bootstrap) -> Result<(), Refusal> {
    if !b.enabled {
        return Err(err(
            StatusCode::CONFLICT,
            "bootstrap_off",
            "bootstrap.enabled is false: the fleet installs no host",
        ));
    }
    Ok(())
}

/// `POST /v1/hosts/tokens`: a token for one server to join with. Answered once with the secret;
/// written to the registry before it is.
pub(super) async fn create_token(
    State(st): S,
    Json(req): Json<api::CreateJoinTokenRequest>,
) -> Result<Response, Refusal> {
    bootstrap_on(&st.cfg.bootstrap)?;
    let ttl = req.ttl_sec.map(|s| s as i64);
    if ttl.is_some_and(|s| !(SHORTEST_TTL..=registry::MAX_TTL.num_seconds()).contains(&s)) {
        return Err(invalid(format!(
            "ttl_sec: between {SHORTEST_TTL} seconds and {} days",
            registry::MAX_TTL.num_days()
        )));
    }
    if !req.region.is_empty() && !api::valid_id(&req.region) {
        return Err(invalid(format!(
            "region {:?}: a-z, 0-9, _ and -",
            req.region
        )));
    }
    if !req.host.is_empty() && !api::valid_id(&req.host) {
        return Err(invalid(format!("host {:?}: a-z, 0-9, _ and -", req.host)));
    }
    for (k, v) in &req.labels {
        api::Label::parse(&format!("{k}={v}")).map_err(invalid)?;
    }
    let now = Utc::now();
    let (token, rec) = st.reg.lock().unwrap().mint_token(
        registry::TokenSpec {
            ttl: ttl.map(Duration::seconds),
            region: req.region,
            labels: req.labels,
            host: req.host,
        },
        now,
    );
    if let Err(e) = st.save().await {
        // Never answered, never kept.
        st.reg
            .lock()
            .unwrap()
            .join_tokens
            .retain(|t| t.id != rec.id);
        return Err(registry_error(e));
    }
    tracing::warn!(
        token = rec.id,
        expires_at = %rec.expires_at,
        region = rec.region,
        host = rec.host,
        "join token made"
    );
    let created = api::JoinTokenCreated {
        token,
        info: rec.to_api(now),
    };
    Ok((StatusCode::CREATED, Json(created)).into_response())
}

pub(super) async fn list_tokens(State(st): S) -> Json<Vec<api::JoinToken>> {
    let now = Utc::now();
    let reg = st.reg.lock().unwrap();
    let mut tokens: Vec<api::JoinToken> = reg.join_tokens.iter().map(|t| t.to_api(now)).collect();
    tokens.sort_by_key(|t| std::cmp::Reverse(t.created_at));
    Json(tokens)
}

/// Ends a token no host has used; one used stays as the record of who did.
pub(super) async fn revoke_token(
    State(st): S,
    Path(id): Path<String>,
) -> Result<Response, Refusal> {
    let revoked = st.reg.lock().unwrap().revoke_token(&id, Utc::now());
    match revoked {
        Err(registry::RevokeError::Unknown) => {
            return Err(err(StatusCode::NOT_FOUND, "not_found", "token not found"))
        }
        Err(registry::RevokeError::Used) => {
            return Err(err(
                StatusCode::CONFLICT,
                "conflict",
                format!("token {id} was used: it cannot be taken back"),
            ))
        }
        Ok(()) => {}
    }
    st.save().await.map_err(registry_error)?;
    tracing::warn!(token = id, "join token revoked");
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// The refusal for a token that cannot be used, whatever the reason: the caller is told one
/// thing, the log the reason.
fn denied(why: registry::TokenError, peer: &str) -> Refusal {
    tracing::warn!(reason = %why, peer, "join refused: the token is not usable");
    err(
        StatusCode::UNAUTHORIZED,
        "invalid_token",
        "the join token is invalid, expired or already used",
    )
}

/// What a join gets from the caller's side: the address its API will be at, which is the one the
/// call came from. The fleet vouches for an address only when it sees where a call comes from
/// (ADR 0026): behind a proxy it cannot see through, a token would let a caller name any address.
fn caller_address(caller: Caller, asked: &str) -> Result<std::net::Ipv4Addr, Refusal> {
    let refuse = |m: String| err(StatusCode::FORBIDDEN, "unknown_host", m);
    let Some(peer) = caller.peer.filter(|_| caller.checked) else {
        return Err(refuse(
            "the fleet cannot tell where this call came from, and a host joins only from the address it will serve at: give the fleet its own TLS, or put it behind a loopback proxy that sets X-Forwarded-For".into(),
        ));
    };
    let std::net::IpAddr::V4(ip) = peer else {
        return Err(invalid(format!(
            "the call came from {peer}: the API's address is an IPv4 one"
        )));
    };
    if !asked.is_empty() && asked != ip.to_string() {
        return Err(refuse(format!(
            "address {asked} is not the one the call came from ({ip}): join from the address the host serves its API at"
        )));
    }
    Ok(ip)
}

/// `POST /v1/hosts/join`, with a join token as the bearer: the host is recorded `joining`, with
/// its own API token, and told what the SSH bootstrap would send it. Everything is checked
/// before the token is used, and the token is used in the step that records the host, under the
/// registry's lock: of two calls with one token, one gets a host.
pub(super) async fn join_host(
    State(st): S,
    info: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    headers: HeaderMap,
    Json(req): Json<api::JoinRequest>,
) -> Result<Response, Refusal> {
    let b = &st.cfg.bootstrap;
    bootstrap_on(b)?;
    if b.release.is_empty() {
        return Err(err(
            StatusCode::CONFLICT,
            "bootstrap_off",
            "bootstrap.release is not set: a joining host has nowhere to get its binaries",
        ));
    }
    let now = Utc::now();
    let caller = Caller::of(&st, info, &headers);
    let peer = caller.peer.map(|p| p.to_string()).unwrap_or_default();
    let presented = bearer(&headers);
    let rec = {
        let mut reg = st.reg.lock().unwrap();
        let token = reg
            .check_token(presented, now)
            .map_err(|why| denied(why, &peer))?
            .clone();
        let ip = caller_address(caller, &req.address)?;
        if !matches!(req.arch.as_str(), "x86_64" | "aarch64") {
            return Err(invalid(format!("arch {:?}: x86_64 or aarch64", req.arch)));
        }
        let asked = match (token.host.as_str(), req.name.as_str()) {
            ("", name) => name.to_string(),
            (bound, "") => bound.to_string(),
            (bound, name) if bound == name => name.to_string(),
            (bound, name) => {
                tracing::warn!(
                    token = token.id,
                    bound,
                    name,
                    peer,
                    "join refused: not the name the token is bound to"
                );
                return Err(err(
                    StatusCode::FORBIDDEN,
                    "wrong_name",
                    format!("this token is for host {bound}, not {name}"),
                ));
            }
        };
        let id = host_id(asked, ip)?;
        let url = bootstrap::host_url(&ip.to_string());
        if let Some(other) = reg
            .hosts
            .values()
            .find(|o| o.id == id || (!o.url.is_empty() && url_host(&o.url) == ip.to_string()))
        {
            return Err(err(
                StatusCode::CONFLICT,
                "conflict",
                format!("host {} is already at {}", other.id, url_host(&other.url)),
            ));
        }
        let host = HostRec {
            id: id.clone(),
            url,
            token: bootstrap::new_token(),
            region: token.region.clone(),
            provider: "join".into(),
            state: "joining".into(),
            last_seen: now,
            note: format!(
                "joined with token {} from {peer} ({}, {} vCPUs, {} MB); waiting for its first heartbeat",
                token.id, req.arch, req.vcpus, req.memory_mb
            ),
            public_tcp_ports: Some(b.public_tcp_ports.clone()),
            labels: token.labels.clone(),
            ..Default::default()
        };
        let by = api::JoinTokenUse {
            host: id,
            at: now,
            peer: peer.clone(),
        };
        reg.consume_token(presented, now, by)
            .map_err(|why| denied(why, &peer))?;
        reg.hosts.insert(host.id.clone(), host.clone());
        host
    };
    if let Err(e) = st.save().await {
        // The host never got its answer: the token is whole again, and no host is recorded.
        let mut reg = st.reg.lock().unwrap();
        reg.hosts.remove(&rec.id);
        if let Some(t) = presented.split_once('.').map(|(id, _)| id) {
            reg.release_token(t);
        }
        return Err(registry_error(e));
    }
    tracing::warn!(
        host = rec.id,
        url = rec.url,
        peer,
        "host joined; it heartbeats once installed"
    );
    // A join sends the fleet's URL only when the fleet has one set: the host reached it by the
    // URL it was given, and uses that otherwise.
    let env = bootstrap::bootstrap_settings(b, "", &rec, &b.release)
        .into_iter()
        .filter(|(_, v)| !v.is_empty())
        .map(|(k, v)| (k.to_string(), v))
        .collect();
    Ok((
        StatusCode::CREATED,
        Json(api::JoinResponse { id: rec.id, env }),
    )
        .into_response())
}

/// `GET /install.sh`: the script a server runs to join. It holds no secret.
pub(super) async fn install_script(State(st): S) -> Result<Response, Refusal> {
    bootstrap_on(&st.cfg.bootstrap)?;
    Ok(text(INSTALL.to_string()))
}

/// `GET /bootstrap-host.sh`: the script `install.sh` runs, the one the SSH bootstrap sends. It
/// holds no secret.
pub(super) async fn bootstrap_script(State(st): S) -> Result<Response, Refusal> {
    bootstrap_on(&st.cfg.bootstrap)?;
    let script = bootstrap::script(&st.cfg.bootstrap).map_err(|e| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "script",
            format!("read bootstrap.script: {e}"),
        )
    })?;
    Ok(text(script))
}

fn text(body: String) -> Response {
    ([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], body).into_response()
}
