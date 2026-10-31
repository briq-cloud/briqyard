//! Namespace membership and bidirectional bridge policy. Evaluated on every packet.

use super::*;

pub(super) fn member(bridge: &str, ip: &str) -> String {
    format!("\"{bridge}\" . {ip}")
}

pub(super) fn mac_pin(tap: &str, ip: &str) -> String {
    // Invalid persisted addresses already make the IP pin invalid, so table installation
    // fails closed. The fallback only keeps rendering fallible at the nft boundary.
    let mac = ip.parse().map(super::super::mac_for).unwrap_or_default();
    format!("\"{tap}\" . {mac}")
}

pub(super) fn chains() -> &'static str {
    "\tchain via_ipv4 {\n\
     \t\tip saddr . ip daddr @via_allowed return\n\
     \t\tip saddr @via_siblings meta ibrname . ip daddr @members return\n\
     \t\tdrop\n\t}\n\
     \tchain via_arp {\n\
     \t\tarp saddr ip . arp daddr ip @via_allowed return\n\
     \t\tarp saddr ip @via_siblings meta ibrname . arp daddr ip @members return\n\
     \t\tdrop\n\t}\n\
     \tchain via_forward_ipv4 {\n\
     \t\toifname . ip daddr != @pins drop\n\
     \t\tip saddr . ip daddr @via_allowed ip saddr . oifname @via_targets return\n\
     \t\tip saddr @via_siblings meta obrname . ip daddr @members return\n\
     \t\tdrop\n\t}\n\
     \tchain via_forward_arp {\n\
     \t\toifname . arp daddr ip != @pins drop\n\
     \t\tarp saddr ip . arp daddr ip @via_allowed arp saddr ip . oifname @via_targets return\n\
     \t\tarp saddr ip @via_siblings meta obrname . arp daddr ip @members return\n\
     \t\tdrop\n\t}\n\
     \tchain via_reply_ipv4 {\n\
     \t\toifname . ip daddr != @pins drop\n\
     \t\tip daddr . ip saddr @via_allowed ip daddr . iifname @via_targets return\n\
     \t\tip daddr @via_siblings meta obrname . ip saddr @members return\n\
     \t\tdrop\n\t}\n\
     \tchain via_reply_arp {\n\
     \t\toifname . arp daddr ip != @pins drop\n\
     \t\tarp daddr ip . arp saddr ip @via_allowed arp daddr ip . iifname @via_targets return\n\
     \t\tarp daddr ip @via_siblings meta obrname . arp saddr ip @members return\n\
     \t\tdrop\n\t}\n\
     \tchain forward {\n\
     \t\ttype filter hook forward priority -200; policy accept;\n\
     \t\tiifname \"bt*\" oifname \"bt*\" ip saddr @via_sources jump via_forward_ipv4\n\
     \t\tiifname \"bt*\" oifname \"bt*\" arp saddr ip @via_sources jump via_forward_arp\n\
     \t\tiifname \"bt*\" oifname \"bt*\" ip daddr @via_sources jump via_reply_ipv4\n\
     \t\tiifname \"bt*\" oifname \"bt*\" arp daddr ip @via_sources jump via_reply_arp\n\
     \t}\n"
}

pub(super) fn prerouting() -> &'static str {
    "\tchain prerouting {\n\
     \t\ttype filter hook prerouting priority -200; policy drop;\n\
     \t\tiifname . ether saddr != @mac_pins drop\n\
     \t\tiifname . arp saddr ether != @mac_pins drop\n\
     \t\tiifname . arp saddr ip != @pins drop\n\
     \t\tiifname . ip saddr != @pins drop\n\
     \t\tip saddr @via_sources jump via_ipv4\n\
     \t\tarp saddr ip @via_sources jump via_arp\n\
     \t\tiifname . arp saddr ip @pins accept\n\
     \t\tiifname . ip saddr @pins accept\n\
     \t}\n"
}

/// Admission and revocation include pins, membership and policy in one nft transaction.
pub fn attachment_elements(
    verb: &str,
    tap: &str,
    bridge: &str,
    ip: &str,
    policy: Option<&Policy>,
) -> String {
    // `add` keeps an existing element/object. Ensure every item exists, then remove all
    // of them in the same transaction: idempotent even after partial external damage.
    // No temporary permission is visible between operations in one nft batch.
    let mut script = if verb == "delete" {
        attachment_elements("add", tap, bridge, ip, policy)
    } else {
        String::new()
    };
    script += &format!(
        "{verb} element bridge briqyard pins {{ {} }}\n\
         {verb} element bridge briqyard mac_pins {{ {} }}\n\
         {verb} element bridge briqyard members {{ {} }}\n",
        pin(tap, ip),
        mac_pin(tap, ip),
        member(bridge, ip)
    );
    if let Some(policy) = policy {
        script += &policy.elements(verb);
    }
    script
}
