//! What address the outside world sees, discovered over DNS rather than HTTP.
//!
//! The usual way to answer this is an HTTPS request to an "what is my IP"
//! service, which means shipping an HTTP client and sending headers and a user
//! agent to a third party. Two public resolvers answer the same question inside
//! a plain DNS query, which this app already speaks: no new dependency, no
//! request body, and nothing sent that the resolver would not have seen anyway.
//!
//! Both are queried because disagreement is itself the finding. A proxy in TUN
//! mode intercepts one path and not the other, and the mismatch shows the user
//! that their DNS and their traffic leave by different doors.

use std::net::Ipv4Addr;

use serde::Serialize;

use super::dns;
use super::interference::is_fake_ip;

/// Google's resolver answers this name with the querying address, as TXT.
const GOOGLE_PROBE: (&str, &str) = ("o-o.myaddr.l.google.com", "8.8.8.8");
/// OpenDNS answers the same question as a plain A record.
const OPENDNS_PROBE: (&str, &str) = ("myip.opendns.com", "208.67.222.222");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum EgressVerdict {
    /// Both probes agree; this is the address the internet sees.
    Confirmed,
    /// The probes disagree, so traffic is leaving by more than one route.
    Split,
    /// A probe came back with a proxy's synthetic address.
    Intercepted,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Egress {
    /// Address reported by the TXT probe, the one a fake-IP resolver rarely rewrites.
    pub primary: Option<String>,
    /// Address reported by the A-record probe.
    pub secondary: Option<String>,
    pub verdict: EgressVerdict,
    pub reasons: Vec<&'static str>,
}

/// Ask both probes and reconcile them.
pub fn lookup() -> Egress {
    let primary = query_txt();
    let secondary = query_a();
    reconcile(primary, secondary)
}

fn query_txt() -> Option<Ipv4Addr> {
    let (name, server) = GOOGLE_PROBE;
    let resolver: Ipv4Addr = server.parse().ok()?;
    let id = query_id();
    let packet = dns::build_typed_query(name, id, 16)?;
    let response = dns::exchange(resolver, &packet)?;
    dns::parse_txt_answers(&response, id)?
        .into_iter()
        .find_map(|value| value.trim().parse::<Ipv4Addr>().ok())
}

fn query_a() -> Option<Ipv4Addr> {
    let (name, server) = OPENDNS_PROBE;
    let resolver: Ipv4Addr = server.parse().ok()?;
    let answer = dns::query(resolver, name);
    answer.addresses.first().and_then(|value| value.parse().ok())
}

fn query_id() -> u16 {
    (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.subsec_nanos())
        .unwrap_or(0)
        & 0xffff) as u16
}

/// Pure reconciliation, so every combination is testable without a network.
pub fn reconcile(primary: Option<Ipv4Addr>, secondary: Option<Ipv4Addr>) -> Egress {
    let mut reasons = Vec::new();

    let primary_fake = primary.is_some_and(|ip| is_fake_ip(ip.into()));
    let secondary_fake = secondary.is_some_and(|ip| is_fake_ip(ip.into()));

    // A synthetic answer means a local resolver replied, not the internet.
    if primary_fake || secondary_fake {
        reasons.push("probeWasIntercepted");
        // The non-synthetic side, if any, is still the better answer to show.
        let usable = match (primary_fake, secondary_fake) {
            (false, true) => primary,
            (true, false) => secondary,
            _ => None,
        };
        return Egress {
            primary: usable.map(|ip| ip.to_string()),
            secondary: None,
            verdict: EgressVerdict::Intercepted,
            reasons,
        };
    }

    match (primary, secondary) {
        (Some(first), Some(second)) if first == second => {
            reasons.push("probesAgree");
            Egress {
                primary: Some(first.to_string()),
                secondary: None,
                verdict: EgressVerdict::Confirmed,
                reasons,
            }
        }
        (Some(first), Some(second)) => {
            reasons.push("probesDisagree");
            reasons.push("trafficSplitByRule");
            Egress {
                primary: Some(first.to_string()),
                secondary: Some(second.to_string()),
                verdict: EgressVerdict::Split,
                reasons,
            }
        }
        (Some(only), None) | (None, Some(only)) => {
            reasons.push("singleProbeOnly");
            Egress {
                primary: Some(only.to_string()),
                secondary: None,
                verdict: EgressVerdict::Confirmed,
                reasons,
            }
        }
        (None, None) => {
            reasons.push("noProbeAnswered");
            Egress { primary: None, secondary: None, verdict: EgressVerdict::Unknown, reasons }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(value: &str) -> Option<Ipv4Addr> {
        value.parse().ok()
    }

    #[test]
    fn agreeing_probes_confirm_one_address() {
        let result = reconcile(ip("203.0.113.7"), ip("203.0.113.7"));
        assert_eq!(result.verdict, EgressVerdict::Confirmed);
        assert_eq!(result.primary.as_deref(), Some("203.0.113.7"));
        assert_eq!(result.secondary, None, "no need to repeat the same address");
    }

    #[test]
    fn disagreement_is_reported_as_a_split_route() {
        // Measured shape: DNS leaves via the ISP while traffic leaves via a proxy.
        let result = reconcile(ip("125.64.134.133"), ip("178.128.82.131"));
        assert_eq!(result.verdict, EgressVerdict::Split);
        assert_eq!(result.primary.as_deref(), Some("125.64.134.133"));
        assert_eq!(result.secondary.as_deref(), Some("178.128.82.131"));
        assert!(result.reasons.contains(&"trafficSplitByRule"));
    }

    #[test]
    fn a_synthetic_answer_is_discarded_not_displayed() {
        // Measured on a Mac running a TUN proxy: the A probe came back 198.18.x.
        let result = reconcile(ip("125.64.134.133"), ip("198.18.26.93"));
        assert_eq!(result.verdict, EgressVerdict::Intercepted);
        assert_eq!(
            result.primary.as_deref(),
            Some("125.64.134.133"),
            "the untouched probe should still be shown"
        );
        assert!(result.reasons.contains(&"probeWasIntercepted"));
    }

    #[test]
    fn both_synthetic_leaves_nothing_to_show() {
        let result = reconcile(ip("198.18.1.1"), ip("198.18.26.93"));
        assert_eq!(result.verdict, EgressVerdict::Intercepted);
        assert_eq!(result.primary, None);
    }

    #[test]
    fn one_answer_is_enough() {
        let result = reconcile(ip("203.0.113.7"), None);
        assert_eq!(result.verdict, EgressVerdict::Confirmed);
        assert!(result.reasons.contains(&"singleProbeOnly"));
    }

    #[test]
    fn silence_is_unknown_not_an_answer() {
        let result = reconcile(None, None);
        assert_eq!(result.verdict, EgressVerdict::Unknown);
        assert_eq!(result.primary, None);
    }
}
