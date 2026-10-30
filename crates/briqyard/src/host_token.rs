//! `host token`: the one-time tokens a server joins a fleet with (ADR 0057).

use super::*;

#[derive(Subcommand)]
pub(super) enum TokenCmd {
    /// Make a token for a server to join with, shown once. Bind it to the server it is for:
    /// briqyard host token create --address 10.42.0.12 --ttl 1h --region gra --labels rack=a1
    Create {
        /// How long it can be used (1h, 30m, 2d); default and at most: the fleet's (an hour, 30 days)
        #[arg(long)]
        ttl: Option<humantime::Duration>,
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
        /// bound to the server it is for is useless from any other. Default: from anywhere
        #[arg(long, default_value = "")]
        address: String,
    },
    /// The tokens: active, used (by which host), expired, revoked
    #[command(alias = "list")]
    Ls,
    /// End a token no host has used
    Revoke { id: String },
}

pub(super) async fn run(c: &Client, cmd: TokenCmd) -> Result<()> {
    use reqwest::Method;
    match cmd {
        TokenCmd::Create {
            ttl,
            region,
            labels,
            host,
            address,
        } => {
            let req = api::CreateJoinTokenRequest {
                ttl_sec: ttl.map(|t| t.as_secs()),
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
                "expires {}, usable {bound}; shown once. On the server, as root:\n  {}",
                made.info.expires_at.to_rfc3339(),
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
        "{:<8} {:<8} {:<26} {:<8} {:<24} USED BY\n",
        "ID", "STATE", "EXPIRES", "REGION", "LABELS"
    );
    for t in tokens {
        let labels: Vec<String> = t.labels.iter().map(|(k, v)| format!("{k}={v}")).collect();
        let used = match &t.used_by {
            Some(u) => format!("{} from {} at {}", u.host, u.peer, u.at.to_rfc3339()),
            None => {
                let mut bound = Vec::new();
                if !t.host.is_empty() {
                    bound.push(format!("for {}", t.host));
                }
                if !t.address.is_empty() {
                    bound.push(format!("from {}", t.address));
                }
                if bound.is_empty() {
                    "-".to_string()
                } else {
                    format!("({})", bound.join(", "))
                }
            }
        };
        out.push_str(&format!(
            "{:<8} {:<8} {:<26} {:<8} {:<24} {}\n",
            t.id,
            t.state,
            t.expires_at.format("%Y-%m-%d %H:%M:%S UTC"),
            if t.region.is_empty() { "-" } else { &t.region },
            if labels.is_empty() {
                "-".to_string()
            } else {
                labels.join(",")
            },
            used
        ));
    }
    out
}
