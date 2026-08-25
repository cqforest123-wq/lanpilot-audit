//! Detects when something local is answering on the internet's behalf.
//!
//! A TUN-mode proxy (Clash, Stash, Surge, and the corporate VPN clients that
//! work the same way) terminates ICMP locally and synthesizes replies. A naive
//! ping tool then reports "0.1 ms, no loss" for a link that may be entirely
//! broken. This module exists so Quick Check never tells that lie.
//!
//! The tell is physical: a reply from a distant anchor cannot arrive sooner
//! than a reply from the router in the same room. When several anchors on
//! different continents all answer in well under a millisecond, and faster than
//! the local gateway, nothing left the machine.

use serde::Serialize;
use std::net::{IpAddr, Ipv4Addr};

/// Anchors chosen to sit on different networks and continents, so agreement
/// between them is evidence about the local machine rather than about one ISP.
pub const ANCHORS: [(&str, &str); 3] = [
    ("Cloudflare", "1.1.1.1"),
    ("Google", "8.8.8.8"),
    ("Quad9", "9.9.9.9"),
];

/// RFC 2544 benchmarking range. No host is legitimately reachable here, so a
/// public hostname resolving into it means a local fake-IP resolver answered.
/// This is the default pool for Clash/Stash/Surge TUN mode.
const FAKE_IP_V4: (Ipv4Addr, u8) = (Ipv4Addr::new(198, 18, 0, 0), 15);

/// No real internet path is this fast; light alone needs ~1 ms per 100 km of fibre.
const IMPLAUSIBLE_RTT_MS: f64 = 3.0;
/// Independent anchors agreeing this closely indicates one local responder.
const SUSPICIOUS_SPREAD_MS: f64 = 1.5;

/// True when an address belongs to a synthetic range a local resolver hands out
/// instead of the real one.
pub fn is_fake_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => {
            let (base, prefix) = FAKE_IP_V4;
            let mask = u32::MAX << (32 - prefix);
            (u32::from(v4) & mask) == (u32::from(base) & mask)
        }
        IpAddr::V6(_) => false,
    }
}

/// True when the address is on the user's own network, where an external
/// interception verdict says nothing about reachability.
pub fn is_local_scope(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => v4.is_private() || v4.is_link_local() || v4.is_loopback(),
        // fc00::/7 unique-local, fe80::/10 link-local.
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            v6.is_loopback()
                || segments[0] & 0xfe00 == 0xfc00
                || segments[0] & 0xffc0 == 0xfe80
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnchorSample {
    pub label: String,
    pub address: String,
    pub rtt_ms: Option<f64>,
    pub reply_ttl: Option<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PathVerdict {
    /// Timings look like real network distance.
    Direct,
    /// Something on this Mac is answering for the internet.
    LocallyIntercepted,
    /// Nothing answered; there is no interception claim to make either way.
    NoExternalPath,
    /// Not enough evidence.
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Interference {
    pub verdict: PathVerdict,
    /// Machine-readable reasons; the UI turns each into a localized sentence.
    pub reasons: Vec<&'static str>,
    pub anchors: Vec<AnchorSample>,
    pub gateway_rtt_ms: Option<f64>,
}

/// Weigh gateway timing against the anchor set.
///
/// `gateway_rtt_ms` is the reference point: it is the one measurement we know
/// traversed real hardware.
pub fn assess(gateway_rtt_ms: Option<f64>, anchors: Vec<AnchorSample>) -> Interference {
    assess_with_resolution(gateway_rtt_ms, anchors, None)
}

/// As `assess`, but also weighs the address a public hostname resolved to.
///
/// A fake-IP answer is decisive on its own: it proves a local resolver rewrote
/// the lookup, which is the same component that synthesizes the echo replies.
pub fn assess_with_resolution(
    gateway_rtt_ms: Option<f64>,
    anchors: Vec<AnchorSample>,
    resolved: Option<IpAddr>,
) -> Interference {
    assess_full(gateway_rtt_ms, anchors, resolved, false)
}

/// The complete assessment.
///
/// `gateway_is_local_interface` matters more than it looks: with macOS Internet
/// Sharing or a VM bridge, the "default gateway" can be an address this Mac
/// holds itself. Timing it then measures the local stack, not real hardware, so
/// it cannot serve as the physical reference point and the
/// faster-than-gateway comparison must be withheld rather than trusted.
pub fn assess_full(
    gateway_rtt_ms: Option<f64>,
    anchors: Vec<AnchorSample>,
    resolved: Option<IpAddr>,
    gateway_is_local_interface: bool,
) -> Interference {
    let fake_ip = resolved.is_some_and(is_fake_ip);
    let reference = if gateway_is_local_interface { None } else { gateway_rtt_ms };
    let mut result = assess_timings(reference, anchors);
    if gateway_is_local_interface {
        result.reasons.push("gatewayIsLocalInterface");
        result.gateway_rtt_ms = gateway_rtt_ms;
    }
    if fake_ip {
        result.reasons.push("fakeIpResolution");
        result.verdict = PathVerdict::LocallyIntercepted;
    }
    result
}

fn assess_timings(gateway_rtt_ms: Option<f64>, anchors: Vec<AnchorSample>) -> Interference {
    let answered: Vec<&AnchorSample> = anchors.iter().filter(|a| a.rtt_ms.is_some()).collect();
    let mut reasons = Vec::new();

    if anchors.is_empty() {
        return Interference { verdict: PathVerdict::Unknown, reasons, anchors, gateway_rtt_ms };
    }

    if answered.is_empty() {
        reasons.push("noAnchorReplies");
        return Interference {
            verdict: PathVerdict::NoExternalPath,
            reasons,
            anchors,
            gateway_rtt_ms,
        };
    }

    // A single answering anchor cannot show agreement, so it cannot support the
    // interception claim on its own.
    if answered.len() < 2 {
        reasons.push("tooFewAnchorReplies");
        return Interference { verdict: PathVerdict::Unknown, reasons, anchors, gateway_rtt_ms };
    }

    let timings: Vec<f64> = answered.iter().filter_map(|a| a.rtt_ms).collect();
    let fastest = timings.iter().cloned().fold(f64::INFINITY, f64::min);
    let slowest = timings.iter().cloned().fold(f64::NEG_INFINITY, f64::max);

    let all_implausible = slowest < IMPLAUSIBLE_RTT_MS;
    let tightly_clustered = (slowest - fastest) < SUSPICIOUS_SPREAD_MS;
    // The decisive one: the far side beating the router in the same room.
    let beats_gateway = gateway_rtt_ms.is_some_and(|gateway| fastest < gateway);

    if all_implausible {
        reasons.push("implausiblySmallRtt");
    }
    if tightly_clustered && answered.len() >= 2 {
        reasons.push("anchorsAgreeTooClosely");
    }
    if beats_gateway {
        reasons.push("fasterThanGateway");
    }

    // Require the physical impossibility plus one corroborating signal, so a
    // genuinely excellent connection is never mislabeled.
    let verdict = if all_implausible && (beats_gateway || tightly_clustered) {
        PathVerdict::LocallyIntercepted
    } else {
        if reasons.is_empty() {
            reasons.push("timingsLookPhysical");
        }
        PathVerdict::Direct
    };

    Interference { verdict, reasons, anchors, gateway_rtt_ms }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn anchor(label: &str, rtt: Option<f64>) -> AnchorSample {
        AnchorSample {
            label: label.to_string(),
            address: "0.0.0.0".to_string(),
            rtt_ms: rtt,
            reply_ttl: Some(64),
        }
    }

    #[test]
    fn flags_the_tun_signature_measured_on_a_real_mac() {
        // Numbers taken from an actual Mac running a TUN-mode proxy: three
        // continents answering in 0.1 ms while the gateway needs 4.3 ms.
        let result = assess(
            Some(4.34),
            vec![
                anchor("Cloudflare", Some(0.12)),
                anchor("Google", Some(0.11)),
                anchor("Quad9", Some(0.10)),
            ],
        );
        assert_eq!(result.verdict, PathVerdict::LocallyIntercepted);
        assert!(result.reasons.contains(&"fasterThanGateway"));
        assert!(result.reasons.contains(&"implausiblySmallRtt"));
    }

    #[test]
    fn accepts_a_normal_home_connection() {
        let result = assess(
            Some(3.1),
            vec![
                anchor("Cloudflare", Some(12.4)),
                anchor("Google", Some(18.9)),
                anchor("Quad9", Some(31.2)),
            ],
        );
        assert_eq!(result.verdict, PathVerdict::Direct);
    }

    #[test]
    fn does_not_flag_a_genuinely_fast_lan_path() {
        // Fast fibre still cannot beat the gateway, and real anchors disagree.
        let result = assess(
            Some(0.9),
            vec![
                anchor("Cloudflare", Some(2.1)),
                anchor("Google", Some(4.8)),
                anchor("Quad9", Some(9.7)),
            ],
        );
        assert_eq!(result.verdict, PathVerdict::Direct);
    }

    #[test]
    fn reports_no_path_when_nothing_answers() {
        let result = assess(
            Some(2.0),
            vec![anchor("Cloudflare", None), anchor("Google", None), anchor("Quad9", None)],
        );
        assert_eq!(result.verdict, PathVerdict::NoExternalPath);
        assert!(result.reasons.contains(&"noAnchorReplies"));
    }

    #[test]
    fn stays_unknown_on_a_single_reply() {
        let result = assess(
            Some(4.0),
            vec![anchor("Cloudflare", Some(0.1)), anchor("Google", None), anchor("Quad9", None)],
        );
        assert_eq!(result.verdict, PathVerdict::Unknown);
        assert!(result.reasons.contains(&"tooFewAnchorReplies"));
    }

    #[test]
    fn tolerates_a_missing_gateway_measurement() {
        // Wi-Fi captive portals can hide the gateway; clustering alone still counts.
        let result = assess(
            None,
            vec![
                anchor("Cloudflare", Some(0.12)),
                anchor("Google", Some(0.13)),
                anchor("Quad9", Some(0.11)),
            ],
        );
        assert_eq!(result.verdict, PathVerdict::LocallyIntercepted);
        assert!(result.reasons.contains(&"anchorsAgreeTooClosely"));
    }
}

#[cfg(test)]
mod gateway_scope_tests {
    use super::*;

    fn anchor(rtt: f64) -> AnchorSample {
        AnchorSample {
            label: "a".to_string(),
            address: "1.1.1.1".to_string(),
            rtt_ms: Some(rtt),
            reply_ttl: None,
        }
    }

    #[test]
    fn a_self_held_gateway_is_not_used_as_the_reference() {
        // Anchors are fast but disagree, and the gateway cannot vouch for them.
        let result = assess_full(
            Some(4.0),
            vec![anchor(0.2), anchor(2.9)],
            None,
            true,
        );
        assert!(result.reasons.contains(&"gatewayIsLocalInterface"));
        assert!(
            !result.reasons.contains(&"fasterThanGateway"),
            "a self-ping must not be used as physical evidence"
        );
        // The measurement is still reported, just not relied upon.
        assert_eq!(result.gateway_rtt_ms, Some(4.0));
    }

    #[test]
    fn a_real_gateway_still_supports_the_comparison() {
        let result = assess_full(Some(4.0), vec![anchor(0.1), anchor(0.12)], None, false);
        assert!(result.reasons.contains(&"fasterThanGateway"));
        assert_eq!(result.verdict, PathVerdict::LocallyIntercepted);
    }
}
