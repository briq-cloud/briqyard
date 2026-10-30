//! A server joins on its own (ADR 0059; Kubernetes's `kubeadm join` with a bootstrap token):
//! the operator mints a token, reusable until it expires or is revoked, the server presents it with a few facts, and the fleet
//! answers with what the SSH bootstrap sends a host added by hand. The fleet also serves the two
//! scripts that do the rest on the server: `install.sh` (asks the join, runs the bootstrap) and
//! `bootstrap-host.sh` (the one the SSH path runs).

use super::*;

/// What a host runs to join: `curl -fsSL <fleet>/install.sh | FLEET_URL=… JOIN_TOKEN=… sh`.
const INSTALL: &str = include_str!("../../../hack/install.sh");

/// A description is a line of free text in a listing.
const LONGEST_DESCRIPTION: usize = 256;

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

/// `POST /v1/hosts/tokens`: a token for servers to join with. Answered once with the secret;
/// written to the registry before it is.
pub(super) async fn create_token(
    State(st): S,
    Json(req): Json<api::CreateJoinTokenRequest>,
) -> Result<Response, Refusal> {
    bootstrap_on(&st.cfg.bootstrap)?;
    // 0 never expires; anything else is a life up to ten years.
    let max = registry::MAX_TTL.num_seconds() as u64;
    if req.ttl_sec.is_some_and(|s| s > max) {
        return Err(invalid(format!(
            "ttl_sec: at most {} days; 0 for a token that never expires",
            registry::MAX_TTL.num_days()
        )));
    }
    let ttl = req.ttl_sec.map(|s| s as i64);
    if req.description.chars().count() > LONGEST_DESCRIPTION
        || req.description.chars().any(char::is_control)
    {
        return Err(invalid(format!(
            "description: one line of at most {LONGEST_DESCRIPTION} characters"
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
    if !req.address.is_empty() {
        registry::parse_address(&req.address).map_err(|e| invalid(format!("address {e:#}")))?;
    }
    let now = Utc::now();
    let (token, rec) = st.reg.lock().unwrap().mint_token(
        registry::TokenSpec {
            ttl: ttl.map(Duration::seconds),
            description: req.description,
            region: req.region,
            labels: req.labels,
            host: req.host,
            address: req.address,
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
        expires_at = rec
            .expires_at
            .map(|at| at.to_rfc3339())
            .unwrap_or_else(|| "never".into()),
        description = rec.description,
        region = rec.region,
        host = rec.host,
        address = rec.address,
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
    let mut reg = st.reg.lock().unwrap();
    reg.prune_tokens(now);
    let mut tokens: Vec<api::JoinToken> = reg.join_tokens.iter().map(|t| t.to_api(now)).collect();
    tokens.sort_by_key(|t| std::cmp::Reverse(t.created_at));
    Json(tokens)
}

/// Ends a token. The hosts that joined with it stay: it is a way in, not a lease.
pub(super) async fn revoke_token(
    State(st): S,
    Path(id): Path<String>,
) -> Result<Response, Refusal> {
    let revoked = st.reg.lock().unwrap().revoke_token(&id, Utc::now());
    match revoked {
        Err(registry::RevokeError::Unknown) => {
            return Err(err(StatusCode::NOT_FOUND, "not_found", "token not found"))
        }
        Ok(fresh) => {
            if let Err(e) = st.save().await {
                // Not written, not revoked: a restart would bring the token back otherwise.
                if fresh {
                    st.reg.lock().unwrap().unrevoke_token(&id);
                }
                return Err(registry_error(e));
            }
        }
    }
    tracing::warn!(token = id, "join token revoked");
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// A host that joined and has not heartbeated since: no daemon holds its token, nothing runs on
/// it, so a new join may take its place.
fn never_heartbeated(h: &HostRec) -> bool {
    h.provider == "join" && h.state == "joining" && h.tls_fingerprint.is_empty()
}

/// Whether a refused join from `peer` is logged now: one line per peer per minute, so a caller
/// guessing tokens cannot fill the log. The call itself is never limited. The map is bounded:
/// when full, the peers last seen over a minute ago are dropped, and if none is, the table
/// starts over.
pub(crate) fn log_refusal(peer: &str) -> bool {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    use std::time::{Duration as Wait, Instant};
    const EVERY: Wait = Wait::from_secs(60);
    const PEERS: usize = 1024;
    static LAST: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();
    let mut last = LAST
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let now = Instant::now();
    if last.get(peer).is_some_and(|at| now - *at < EVERY) {
        return false;
    }
    if last.len() >= PEERS && !last.contains_key(peer) {
        last.retain(|_, at| now - *at < EVERY);
        if last.len() >= PEERS {
            last.clear();
        }
    }
    last.insert(peer.to_string(), now);
    true
}

/// The refusal for a token that cannot be used, whatever the reason: the caller is told one
/// thing, the log the reason (once a minute per peer, [`log_refusal`]).
fn denied(why: registry::TokenError, peer: &str) -> Refusal {
    if log_refusal(peer) {
        tracing::warn!(reason = %why, peer, "join refused: the token is not usable");
    }
    err(
        StatusCode::UNAUTHORIZED,
        "invalid_token",
        "the join token is invalid, expired or revoked",
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
/// before the use is counted, and it is counted in the step that records the host, under the
/// registry's lock. A token takes as many joins as come until it expires or is revoked.
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
        if !token.allows(ip) {
            return Err(denied(registry::TokenError::WrongAddress, &peer));
        }
        if !matches!(req.arch.as_str(), "x86_64" | "aarch64") {
            return Err(invalid(format!("arch {:?}: x86_64 or aarch64", req.arch)));
        }
        let asked = match (token.host.as_str(), req.name.as_str()) {
            ("", name) => name.to_string(),
            (bound, "") => bound.to_string(),
            (bound, name) if bound == name => name.to_string(),
            (bound, name) => {
                if log_refusal(&peer) {
                    tracing::warn!(
                        token = token.id,
                        bound,
                        name,
                        peer,
                        "join refused: not the name the token is bound to"
                    );
                }
                return Err(err(
                    StatusCode::FORBIDDEN,
                    "wrong_name",
                    format!("this token is for host {bound}, not {name}"),
                ));
            }
        };
        let id = host_id(asked, ip)?;
        let url = bootstrap::host_url(&ip.to_string());
        // A host that joined and never heartbeated holds nothing but a token no daemon has (a
        // failed install): a new join replaces it, rotating its token, when it comes from the
        // record's own address or with the token that made it. Any other host at the id or the
        // address is a conflict, so the holder of another token cannot take a record by its id.
        let in_the_way: Vec<HostRec> = reg
            .hosts
            .values()
            .filter(|o| o.id == id || (!o.url.is_empty() && url_host(&o.url) == ip.to_string()))
            .cloned()
            .collect();
        let ours = |o: &HostRec| {
            never_heartbeated(o) && (url_host(&o.url) == ip.to_string() || o.join_token == token.id)
        };
        if let Some(other) = in_the_way.iter().find(|o| !ours(o)) {
            return Err(err(
                StatusCode::CONFLICT,
                "conflict",
                format!("host {} is already at {}", other.id, url_host(&other.url)),
            ));
        }
        let replaced = in_the_way;
        let note_replaced = match replaced.as_slice() {
            [] => String::new(),
            r => format!(
                "; replaces {} (joined, never heartbeated)",
                r.iter()
                    .map(|o| o.id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        };
        let host = HostRec {
            id: id.clone(),
            url,
            token: bootstrap::new_token(),
            region: token.region.clone(),
            provider: "join".into(),
            state: "joining".into(),
            last_seen: now,
            note: format!(
                "joined with token {} from {peer} ({}, {} vCPUs, {} MB){note_replaced}; waiting for its first heartbeat",
                token.id, req.arch, req.vcpus, req.memory_mb
            ),
            public_tcp_ports: Some(b.public_tcp_ports.clone()),
            labels: token.labels.clone(),
            join_token: token.id.clone(),
            ..Default::default()
        };
        let by = api::JoinTokenUse {
            host: id,
            at: now,
            peer: peer.clone(),
        };
        let (_, before) = reg
            .consume_token(presented, now, by)
            .map_err(|why| denied(why, &peer))?;
        for o in &replaced {
            tracing::warn!(
                host = o.id,
                peer,
                "joining host replaced: it never heartbeated"
            );
            reg.hosts.remove(&o.id);
        }
        reg.hosts.insert(host.id.clone(), host.clone());
        (host, replaced, before)
    };
    let (rec, replaced, before) = rec;
    if let Err(e) = st.save().await {
        // The host never got its answer: the use is taken back, and no host is recorded. Only
        // while the record is still the one this call made: a join that came in between and
        // took its place owns it now.
        let mut reg = st.reg.lock().unwrap();
        if reg.hosts.get(&rec.id).is_some_and(|h| h.token == rec.token) {
            reg.hosts.remove(&rec.id);
            for o in replaced {
                reg.hosts.insert(o.id.clone(), o);
            }
            if let Some(t) = presented.split_once('.').map(|(id, _)| id) {
                reg.release_token(t, before);
            }
        }
        return Err(registry_error(e));
    }
    tracing::warn!(
        host = rec.id,
        url = rec.url,
        peer,
        token = presented.split_once('.').map_or("", |(id, _)| id),
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

/// What `GET /bootstrap-host.sh` is asked with: the URL the host advertises, as the join
/// answered it (`ADVERTISE`), to find its record by.
#[derive(serde::Deserialize)]
pub(super) struct ScriptQuery {
    #[serde(default)]
    url: String,
}

/// `GET /bootstrap-host.sh?url=<ADVERTISE>`: the script `install.sh` runs, the one the SSH
/// bootstrap sends, for a host that presents its own token from its own address, as `POST
/// /v1/hosts/key` is served. It is the operator's `bootstrap.script` when set, whose contents
/// the fleet cannot vouch for, so it is not served to anyone else.
pub(super) async fn bootstrap_script(
    State(st): S,
    info: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    headers: HeaderMap,
    Query(q): Query<ScriptQuery>,
) -> Result<Response, Refusal> {
    bootstrap_on(&st.cfg.bootstrap)?;
    let caller = Caller::of(&st, info, &headers);
    {
        let reg = st.reg.lock().unwrap();
        the_host(&reg, &q.url, &headers, caller, "bootstrap script")?;
    }
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
