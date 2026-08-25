//! Strict validation for the one user-supplied field that reaches network code.
//!
//! The security model promises that user text never becomes a command argument.
//! Quick Check keeps that promise by never spawning a process at all: the target
//! is parsed here into a typed value and handed to an in-process socket. This
//! module is the single gate, and it rejects by default.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Maximum length of a DNS name, including dots (RFC 1035).
const MAX_HOSTNAME_LEN: usize = 253;
/// Maximum length of a single DNS label (RFC 1035).
const MAX_LABEL_LEN: usize = 63;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuickTarget {
    Ip(IpAddr),
    Hostname(String),
}

impl QuickTarget {
    /// Text safe to show in the UI and to write into local reports.
    pub fn display(&self) -> String {
        match self {
            QuickTarget::Ip(ip) => ip.to_string(),
            QuickTarget::Hostname(name) => name.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetError {
    Empty,
    TooLong,
    LeadingDash,
    ContainsWhitespace,
    ContainsControl,
    NotHostnameOrIp,
    EmptyLabel,
    LabelTooLong,
    LabelDash,
    Loopback,
    Unspecified,
    Multicast,
    Broadcast,
    LinkLocal,
}

impl TargetError {
    /// Stable identifier the UI maps to a localized message.
    pub fn code(self) -> &'static str {
        match self {
            TargetError::Empty => "empty",
            TargetError::TooLong => "tooLong",
            TargetError::LeadingDash => "leadingDash",
            TargetError::ContainsWhitespace => "whitespace",
            TargetError::ContainsControl => "control",
            TargetError::NotHostnameOrIp => "notHostnameOrIp",
            TargetError::EmptyLabel => "emptyLabel",
            TargetError::LabelTooLong => "labelTooLong",
            TargetError::LabelDash => "labelDash",
            TargetError::Loopback => "loopback",
            TargetError::Unspecified => "unspecified",
            TargetError::Multicast => "multicast",
            TargetError::Broadcast => "broadcast",
            TargetError::LinkLocal => "linkLocal",
        }
    }
}

impl fmt::Display for TargetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

/// Parse user input into a target that is safe to probe.
///
/// Rejects anything that is not plainly an IP literal or a hostname. The
/// leading-dash rule matters even though we never exec: it keeps the value
/// safe if a future change ever does pass it to a process, and it blocks the
/// `-f` (flood) shape reviewers look for.
pub fn parse_target(raw: &str) -> Result<QuickTarget, TargetError> {
    let trimmed = raw.trim();

    if trimmed.is_empty() {
        return Err(TargetError::Empty);
    }
    if trimmed.len() > MAX_HOSTNAME_LEN {
        return Err(TargetError::TooLong);
    }
    if trimmed.starts_with('-') {
        return Err(TargetError::LeadingDash);
    }
    if trimmed.chars().any(char::is_whitespace) {
        return Err(TargetError::ContainsWhitespace);
    }
    if trimmed.chars().any(|c| c.is_control() || !c.is_ascii()) {
        return Err(TargetError::ContainsControl);
    }

    // Accept a bracketed IPv6 literal the way a URL would write it.
    let unbracketed = trimmed
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(trimmed);

    if let Ok(ip) = unbracketed.parse::<IpAddr>() {
        check_ip(ip)?;
        return Ok(QuickTarget::Ip(ip));
    }

    check_hostname(trimmed)?;
    Ok(QuickTarget::Hostname(trimmed.to_ascii_lowercase()))
}

/// Reject address ranges that are meaningless or unsafe to probe.
///
/// Multicast and broadcast are the ones that matter: a single echo request to
/// either can draw replies from every host on the segment, which is
/// amplification, not diagnosis.
fn check_ip(ip: IpAddr) -> Result<(), TargetError> {
    match ip {
        IpAddr::V4(v4) => check_ipv4(v4),
        IpAddr::V6(v6) => check_ipv6(v6),
    }
}

fn check_ipv4(ip: Ipv4Addr) -> Result<(), TargetError> {
    if ip.is_unspecified() {
        return Err(TargetError::Unspecified);
    }
    if ip.is_loopback() {
        return Err(TargetError::Loopback);
    }
    if ip.is_multicast() {
        return Err(TargetError::Multicast);
    }
    if ip.is_broadcast() {
        return Err(TargetError::Broadcast);
    }
    // A .255 host part is the common directed-broadcast shape on a /24.
    if ip.octets()[3] == 255 {
        return Err(TargetError::Broadcast);
    }
    if ip.is_link_local() {
        return Err(TargetError::LinkLocal);
    }
    Ok(())
}

fn check_ipv6(ip: Ipv6Addr) -> Result<(), TargetError> {
    if ip.is_unspecified() {
        return Err(TargetError::Unspecified);
    }
    if ip.is_loopback() {
        return Err(TargetError::Loopback);
    }
    if ip.is_multicast() {
        return Err(TargetError::Multicast);
    }
    // fe80::/10 link-local; `Ipv6Addr::is_unicast_link_local` is still unstable.
    let segments = ip.segments();
    if segments[0] & 0xffc0 == 0xfe80 {
        return Err(TargetError::LinkLocal);
    }
    Ok(())
}

/// RFC 1123 hostname: dot-separated labels of alphanumerics and inner hyphens.
fn check_hostname(name: &str) -> Result<(), TargetError> {
    // A single trailing dot is a legal fully-qualified name.
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty() {
        return Err(TargetError::Empty);
    }

    let mut saw_alpha = false;

    for label in name.split('.') {
        if label.is_empty() {
            return Err(TargetError::EmptyLabel);
        }
        if label.len() > MAX_LABEL_LEN {
            return Err(TargetError::LabelTooLong);
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(TargetError::LabelDash);
        }
        for c in label.chars() {
            if c.is_ascii_alphabetic() {
                saw_alpha = true;
            } else if !c.is_ascii_digit() && c != '-' {
                return Err(TargetError::NotHostnameOrIp);
            }
        }
    }

    // All-numeric names are malformed IPs (`1.2.3.4.5`, `999.1.1.1`), not hosts.
    if !saw_alpha {
        return Err(TargetError::NotHostnameOrIp);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_plain_hostnames_and_ips() {
        assert_eq!(
            parse_target("example.com"),
            Ok(QuickTarget::Hostname("example.com".to_string()))
        );
        assert_eq!(
            parse_target("  Example.COM  "),
            Ok(QuickTarget::Hostname("example.com".to_string()))
        );
        assert_eq!(
            parse_target("nvr-01.local"),
            Ok(QuickTarget::Hostname("nvr-01.local".to_string()))
        );
        assert!(matches!(parse_target("192.168.2.1"), Ok(QuickTarget::Ip(_))));
        assert!(matches!(parse_target("2606:4700::1111"), Ok(QuickTarget::Ip(_))));
        assert!(matches!(parse_target("[2606:4700::1111]"), Ok(QuickTarget::Ip(_))));
    }

    #[test]
    fn rejects_flag_shaped_input() {
        // The review-critical case: `-f` is flood ping.
        assert_eq!(parse_target("-f"), Err(TargetError::LeadingDash));
        assert_eq!(parse_target("-c100000"), Err(TargetError::LeadingDash));
        assert_eq!(parse_target("  --flood  "), Err(TargetError::LeadingDash));
    }

    #[test]
    fn rejects_amplification_targets() {
        assert_eq!(parse_target("224.0.0.1"), Err(TargetError::Multicast));
        assert_eq!(parse_target("239.255.255.250"), Err(TargetError::Multicast));
        assert_eq!(parse_target("255.255.255.255"), Err(TargetError::Broadcast));
        assert_eq!(parse_target("192.168.2.255"), Err(TargetError::Broadcast));
        assert_eq!(parse_target("ff02::1"), Err(TargetError::Multicast));
    }

    #[test]
    fn rejects_meaningless_targets() {
        assert_eq!(parse_target("127.0.0.1"), Err(TargetError::Loopback));
        assert_eq!(parse_target("0.0.0.0"), Err(TargetError::Unspecified));
        assert_eq!(parse_target("169.254.1.1"), Err(TargetError::LinkLocal));
        assert_eq!(parse_target("::1"), Err(TargetError::Loopback));
        assert_eq!(parse_target("fe80::1"), Err(TargetError::LinkLocal));
    }

    #[test]
    fn rejects_injection_shapes() {
        assert_eq!(parse_target(""), Err(TargetError::Empty));
        assert_eq!(parse_target("   "), Err(TargetError::Empty));
        assert_eq!(parse_target("a b"), Err(TargetError::ContainsWhitespace));
        assert_eq!(parse_target("host\nname"), Err(TargetError::ContainsWhitespace));
        // Separators are rejected on the character rule, not merely because a
        // shell payload would also contain a space.
        assert_eq!(parse_target("a;b"), Err(TargetError::NotHostnameOrIp));
        assert_eq!(parse_target("a&&b"), Err(TargetError::NotHostnameOrIp));
        assert_eq!(parse_target("a|b"), Err(TargetError::NotHostnameOrIp));
        assert_eq!(parse_target("$(id)"), Err(TargetError::NotHostnameOrIp));
        assert_eq!(parse_target("a`id`"), Err(TargetError::NotHostnameOrIp));
        assert_eq!(parse_target("host\0name"), Err(TargetError::ContainsControl));
        assert_eq!(parse_target("例子.com"), Err(TargetError::ContainsControl));
    }

    #[test]
    fn rejects_malformed_names() {
        assert_eq!(parse_target("a..b"), Err(TargetError::EmptyLabel));
        assert_eq!(parse_target("-lead.com"), Err(TargetError::LeadingDash));
        assert_eq!(parse_target("trail-.com"), Err(TargetError::LabelDash));
        assert_eq!(parse_target("a.-mid.com"), Err(TargetError::LabelDash));
        assert_eq!(parse_target("1.2.3.4.5"), Err(TargetError::NotHostnameOrIp));
        assert_eq!(parse_target("999.1.1.1"), Err(TargetError::NotHostnameOrIp));

        let long_label = "a".repeat(64);
        assert_eq!(parse_target(&long_label), Err(TargetError::LabelTooLong));

        let long_name = format!("{}.com", "a".repeat(60).repeat(5));
        assert_eq!(parse_target(&long_name), Err(TargetError::TooLong));
    }

    #[test]
    fn accepts_trailing_dot_fqdn() {
        assert_eq!(
            parse_target("example.com."),
            Ok(QuickTarget::Hostname("example.com.".to_string()))
        );
    }
}
