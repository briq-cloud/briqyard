//! `host token`: the tokens servers join a fleet with (ADR 0059), as `kubeadm token`.

use super::*;

#[derive(Subcommand)]
pub(super) enum TokenCmd {
    /// Make a token servers join with until it expires or is revoked, shown once. Bind it to
    /// the server it is for when you know it:
    /// briqyard host token create --address 10.42.0.12 --ttl 1h --description "rack a1"
    Create {
        /// How long it can be used (1h, 30m, 2d); default 24h; 0 never expires
        #[arg(long)]
        ttl: Option<humantime::Duration>,
        /// Free text shown in `host token ls`
        #[arg(long, default_value = "")]
        description: String,
        /// The region the host that joins with it is put in
        #[arg(long, default_value = "")]
        region: String,
        /// Labels the host carries, comma-separated: rack=a1,disk=nvme
        #[arg(long, value_delimiter = ',')]
        labels: Vec<String>,
        /// The id the host must join as; default: its own choice
        #[arg(long, default_value = "")]
        host: String,
        /// The address (10.42.0.12) or network (10.42.0.0/24) the join must come from: a token
        /// bound to the server it is for is useless from any other (our addition to kubeadm's
        /// model). Default: from anywhere
        #[arg(long, default_value = "")]
        address: String,
    },
    /// The tokens: active, expired, revoked, with their uses
    #[command(alias = "list")]
    Ls,
    /// End a token; the hosts that joined with it stay
    Revoke { id: String },
}

pub(super) async fn run(c: &Client, cmd: TokenCmd) -> Result<()> {
    use reqwest::Method;
    match cmd {
        TokenCmd::Create {
            ttl,
            description,
            region,
            labels,
            host,
            address,
        } => {
            let req = api::CreateJoinTokenRequest {
                ttl_sec: ttl.map(|t| t.as_secs()),
                description,
                region,
                labels: label_args(&labels)?,
                host,
                address,
            };
            let made: api::JoinTokenCreated =
                c.call(Method::POST, "/v1/hosts/tokens", Some(&req)).await?;
            // The token once, on stdout, where a script reads it; the command that uses it
            // names it by a placeholder, so a terminal does not show it twice.
            println!("{}", made.token);
            let bound = if made.info.address.is_empty() {
                "from any address (bind it with --address)".to_string()
            } else {
                format!("from {} only", made.info.address)
            };
            eprintln!(
                "{}, usable {bound}; shown once. On each server, as root:\n  {}",
                expiry_line(&made.info),
                install_command(&c.base)
            );
        }
        TokenCmd::Ls => {
            let tokens: Vec<api::JoinToken> = c.call(Method::GET, "/v1/hosts/tokens", NONE).await?;
            print!("{}", token_table(&tokens));
        }
        TokenCmd::Revoke { id } => {
            c.raw(Method::DELETE, &format!("/v1/hosts/tokens/{id}"), NONE)
                .await?;
        }
    }
    Ok(())
}

fn expiry_line(t: &api::JoinToken) -> String {
    match t.expires_at {
        Some(at) => format!("expires {}", at.to_rfc3339()),
        None => "never expires".to_string(),
    }
}

/// What a server runs to join, against the fleet this CLI talks to; the token is a placeholder
/// to fill in. The fetch of the script is as strict as the script's own calls: `https` only,
/// redirects included.
pub(super) fn install_command(fleet: &str) -> String {
    if fleet.starts_with("https://") {
        format!("curl -fsSL --proto '=https' --proto-redir '=https' {fleet}/install.sh | FLEET_URL={fleet} JOIN_TOKEN=<token> sh")
    } else {
        format!("curl -fsSL {fleet}/install.sh | ALLOW_INSECURE_HTTP=1 FLEET_URL={fleet} JOIN_TOKEN=<token> sh")
    }
}

pub(super) fn token_table(tokens: &[api::JoinToken]) -> String {
    let mut out = format!(
        "{:<8} {:<8} {:<24} {:<5} {:<45} {:<8} {:<20} {:<24} DESCRIPTION\n",
        "ID", "STATE", "EXPIRES", "USES", "LAST USED", "REGION", "LABELS", "BOUND TO"
    );
    for t in tokens {
        let labels: Vec<String> = t.labels.iter().map(|(k, v)| format!("{k}={v}")).collect();
        let last = match &t.last_used {
            Some(u) => format!(
                "{} from {} {}",
                u.host,
                u.peer,
                u.at.format("%Y-%m-%d %H:%M")
            ),
            None => "-".to_string(),
        };
        let mut bound = Vec::new();
        if !t.host.is_empty() {
            bound.push(format!("host {}", t.host));
        }
        if !t.address.is_empty() {
            bound.push(format!("from {}", t.address));
        }
        let or_dash = |s: String| if s.is_empty() { "-".to_string() } else { s };
        out.push_str(&format!(
            "{:<8} {:<8} {:<24} {:<5} {:<45} {:<8} {:<20} {:<24} {}\n",
            t.id,
            t.state,
            t.expires_at.map_or("never".to_string(), |at| at
                .format("%Y-%m-%d %H:%M UTC")
                .to_string()),
            t.uses,
            last,
            or_dash(t.region.clone()),
            or_dash(labels.join(",")),
            or_dash(bound.join(", ")),
            or_dash(t.description.clone()),
        ));
    }
    out
}
