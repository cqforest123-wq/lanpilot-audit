//! Runs a Quick Check and turns measurements into a plain-language verdict.
//!
//! Everything here is in-process: one DNS resolution and a handful of ICMP
//! echoes. No subprocess, no configuration change, no privileged operation.

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::time::{Duration, Instant};

use serde::Serialize;

use super::icmp::{PingSocket, ProbeOutcome};
use super::interference::{self, AnchorSample, Interference, PathVerdict, ANCHORS};
use super::route;
use super::stats::{summarize, ProbeStats};
use super::target::{parse_target, QuickTarget};

/// Bounds are fixed in the backend. The user chooses a target, never a rate:
/// an adjustable count or interval is what turns a diagnostic into a flood tool.
const PROBE_COUNT: u32 = 8;
const PROBE_INTERVAL: Duration = Duration::from_millis(300);
const PROBE_TIMEOUT: Duration = Duration::from_millis(1500);
const ANCHOR_PROBES: u32 = 2;
const GATEWAY_PROBES: u32 = 3;

/// Round trips above this are noticeable in interactive use.
const SLOW_RTT_MS: f64 = 150.0;
/// Jitter above this breaks video and voice even when the average looks fine.
const HIGH_JITTER_MS: f64 = 30.0;
/// Any sustained loss is worth reporting; this is where it becomes visible.
const NOTABLE_LOSS_PCT: f64 = 2.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Health {
    Good,
    Fair,
    Poor,
    Unreachable,
    /// Measurements exist but a local proxy makes them meaningless.
    Untrustworthy,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuickCheckReport {
    pub target: String,
    pub resolved_address: Option<String>,
    pub dns_ms: Option<f64>,
    pub stats: ProbeStats,
    pub samples: Vec<f64>,
    pub gateway: Option<String>,
    pub gateway_stats: Option<ProbeStats>,
    pub interference: Interference,
    pub health: Health,
    /// Stable keys the UI renders as localized sentences.
    pub findings: Vec<&'static str>,
}

/// Streamed to the UI after every probe so the chart moves while the run is live.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeEvent {
    pub phase: &'static str,
    pub sequence: u32,
    pub total: u32,
    pub rtt_ms: Option<f64>,
    pub from: Option<String>,
}

/// Decide the headline result. Pure, so every branch is unit-testable.
/// `target_is_local` suppresses the interception override: a proxy that fakes
/// internet replies does not touch traffic to a device on the same LAN, so
/// those measurements stay valid and must still be reported.
pub fn judge(
    stats: &ProbeStats,
    interference: &Interference,
    target_is_local: bool,
) -> (Health, Vec<&'static str>) {
    let mut findings = Vec::new();

    // Interception first: if replies are synthetic, no timing below means anything.
    if !target_is_local && interference.verdict == PathVerdict::LocallyIntercepted {
        findings.push("localProxyIntercepts");
        findings.push("resultsNotTrustworthy");
        return (Health::Untrustworthy, findings);
    }

    if target_is_local && interference.verdict == PathVerdict::LocallyIntercepted {
        // These LAN numbers are real, but the user should know a proxy is running
        // and that any *internet* result from other tools is not.
        findings.push("localProxyPresentLanUnaffected");
    }

    if stats.received == 0 {
        findings.push("noReply");
        if !target_is_local && interference.verdict == PathVerdict::NoExternalPath {
            findings.push("noExternalPath");
        } else {
            findings.push("targetMayBlockIcmp");
        }
        return (Health::Unreachable, findings);
    }

    let mut health = Health::Good;

    if stats.loss_pct >= NOTABLE_LOSS_PCT {
        findings.push("packetLoss");
        health = if stats.loss_pct >= 20.0 { Health::Poor } else { Health::Fair };
    }

    if let Some(jitter) = stats.jitter_ms {
        if jitter >= HIGH_JITTER_MS {
            findings.push("highJitter");
            health = worst(health, Health::Fair);
        }
    }

    if let Some(avg) = stats.avg_ms {
        if avg >= SLOW_RTT_MS {
            findings.push("highLatency");
            health = worst(health, Health::Fair);
        }
    }

    if findings.is_empty() {
        findings.push("healthy");
    }

    (health, findings)
}

fn worst(current: Health, candidate: Health) -> Health {
    let rank = |health: Health| match health {
        Health::Good => 0,
        Health::Fair => 1,
        Health::Poor => 2,
        Health::Unreachable => 3,
        Health::Untrustworthy => 4,
    };
    if rank(candidate) > rank(current) {
        candidate
    } else {
        current
    }
}

/// Resolve a target to one address, timing the lookup.
pub fn resolve(target: &QuickTarget) -> Result<(IpAddr, Option<f64>), String> {
    match target {
        QuickTarget::Ip(ip) => Ok((*ip, None)),
        QuickTarget::Hostname(name) => {
            let started = Instant::now();
            // Port 0 with a dummy service; only the address matters.
            let mut addresses = format!("{name}:0")
                .to_socket_addrs()
                .map_err(|_| "resolveFailed".to_string())?;
            let elapsed = started.elapsed().as_secs_f64() * 1000.0;
            let first: SocketAddr = addresses.next().ok_or_else(|| "resolveEmpty".to_string())?;
            Ok((first.ip(), Some((elapsed * 100.0).round() / 100.0)))
        }
    }
}

/// Probe one address a fixed number of times, discarding a warm-up packet.
///
/// The first echo to a LAN address usually waits on ARP and looks like loss;
/// counting it would report 12% loss on a perfectly healthy switch.
fn measure(
    address: IpAddr,
    count: u32,
    mut on_probe: impl FnMut(u32, Option<f64>, Option<IpAddr>),
) -> Result<(Vec<f64>, ProbeStats), String> {
    let socket = PingSocket::open(address).map_err(|error| format!("socketFailed:{error}"))?;

    // Warm-up, not scored.
    let _ = socket.probe(address, 0, Duration::from_millis(600));

    let mut samples = Vec::new();
    for sequence in 1..=count {
        if sequence > 1 {
            std::thread::sleep(PROBE_INTERVAL);
        }
        match socket.probe(address, sequence as u16, PROBE_TIMEOUT) {
            Ok(ProbeOutcome::Reply { rtt, from, .. }) => {
                let milliseconds = (rtt.as_secs_f64() * 100_000.0).round() / 100.0;
                samples.push(milliseconds);
                on_probe(sequence, Some(milliseconds), Some(from));
            }
            Ok(_) => on_probe(sequence, None, None),
            Err(error) => return Err(format!("probeFailed:{error}")),
        }
    }

    let stats = summarize(count, &samples);
    Ok((samples, stats))
}

/// Run the full check. `on_event` receives live progress.
pub fn resolve_raw(raw: &str) -> Result<std::net::IpAddr, String> {
    let target = parse_target(raw).map_err(|error| format!("target:{}", error.code()))?;
    Ok(resolve(&target)?.0)
}

pub fn run(raw_target: &str, mut on_event: impl FnMut(ProbeEvent)) -> Result<QuickCheckReport, String> {
    let target = parse_target(raw_target).map_err(|error| format!("target:{}", error.code()))?;
    let (address, dns_ms) = resolve(&target)?;

    // The local reference point, measured before anything external.
    let gateway = route::default_gateway();
    let gateway_stats = gateway.and_then(|gateway_ip| {
        measure(gateway_ip, GATEWAY_PROBES, |sequence, rtt, from| {
            on_event(ProbeEvent {
                phase: "gateway",
                sequence,
                total: GATEWAY_PROBES,
                rtt_ms: rtt,
                from: from.map(|ip| ip.to_string()),
            });
        })
        .ok()
        .map(|(_, stats)| stats)
    });

    // Anchors establish whether external replies are real at all.
    let mut anchors = Vec::new();
    for (label, anchor_address) in ANCHORS {
        let anchor_ip: IpAddr = anchor_address.parse().expect("anchor constants are valid");
        let sample = measure(anchor_ip, ANCHOR_PROBES, |sequence, rtt, from| {
            on_event(ProbeEvent {
                phase: "anchor",
                sequence,
                total: ANCHOR_PROBES,
                rtt_ms: rtt,
                from: from.map(|ip| ip.to_string()),
            });
        })
        .ok();
        anchors.push(AnchorSample {
            label: label.to_string(),
            address: anchor_address.to_string(),
            rtt_ms: sample.as_ref().and_then(|(_, stats)| stats.min_ms),
            reply_ttl: None,
        });
    }

    // Internet Sharing and VM bridges can make the default gateway an address
    // this Mac holds, which would turn the reference point into a self-ping.
    let gateway_is_local_interface = gateway.is_some_and(|gateway_ip| {
        super::netinfo::interfaces()
            .iter()
            .any(|entry| entry.ipv4 == gateway_ip.to_string())
    });

    let interference = interference::assess_full(
        gateway_stats.as_ref().and_then(|stats| stats.min_ms),
        anchors,
        Some(address),
        gateway_is_local_interface,
    );

    let (samples, stats) = measure(address, PROBE_COUNT, |sequence, rtt, from| {
        on_event(ProbeEvent {
            phase: "target",
            sequence,
            total: PROBE_COUNT,
            rtt_ms: rtt,
            from: from.map(|ip| ip.to_string()),
        });
    })?;

    let target_is_local = interference::is_local_scope(address);
    let (health, findings) = judge(&stats, &interference, target_is_local);

    Ok(QuickCheckReport {
        target: target.display(),
        resolved_address: Some(address.to_string()),
        dns_ms,
        stats,
        samples,
        gateway: gateway.map(|ip| ip.to_string()),
        gateway_stats,
        interference,
        health,
        findings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quick_check::interference::assess;

    fn anchor(rtt: Option<f64>) -> AnchorSample {
        AnchorSample {
            label: "test".to_string(),
            address: "1.1.1.1".to_string(),
            rtt_ms: rtt,
            reply_ttl: None,
        }
    }

    fn healthy_path() -> Interference {
        assess(Some(3.0), vec![anchor(Some(14.0)), anchor(Some(22.0)), anchor(Some(35.0))])
    }

    fn intercepted_path() -> Interference {
        assess(Some(4.3), vec![anchor(Some(0.12)), anchor(Some(0.11)), anchor(Some(0.10))])
    }

    #[test]
    fn interception_overrides_apparently_perfect_numbers() {
        // The whole point: 0% loss and 0.1 ms must not be reported as excellent.
        let stats = summarize(8, &[0.1; 8]);
        let (health, findings) = judge(&stats, &intercepted_path(), false);
        assert_eq!(health, Health::Untrustworthy);
        assert!(findings.contains(&"localProxyIntercepts"));
        assert!(!findings.contains(&"healthy"));
    }

    #[test]
    fn clean_run_reads_as_good() {
        let stats = summarize(8, &[18.0, 19.0, 18.5, 20.0, 19.5, 18.2, 19.1, 18.8]);
        let (health, findings) = judge(&stats, &healthy_path(), false);
        assert_eq!(health, Health::Good);
        assert_eq!(findings, vec!["healthy"]);
    }

    #[test]
    fn flags_high_jitter_even_when_average_is_fine() {
        // The camera case: good average, unusable link.
        let stats = summarize(8, &[20.0, 100.0, 20.0, 100.0, 20.0, 100.0, 20.0, 100.0]);
        let (health, findings) = judge(&stats, &healthy_path(), false);
        assert!(findings.contains(&"highJitter"));
        assert_eq!(health, Health::Fair);
    }

    #[test]
    fn heavy_loss_reads_as_poor() {
        let stats = summarize(8, &[20.0, 21.0]);
        let (health, findings) = judge(&stats, &healthy_path(), false);
        assert_eq!(health, Health::Poor);
        assert!(findings.contains(&"packetLoss"));
    }

    #[test]
    fn silence_separates_blocked_icmp_from_no_path() {
        let stats = summarize(8, &[]);

        let (health, findings) = judge(&stats, &healthy_path(), false);
        assert_eq!(health, Health::Unreachable);
        assert!(findings.contains(&"targetMayBlockIcmp"));

        let dead = assess(Some(3.0), vec![anchor(None), anchor(None), anchor(None)]);
        let (_, findings) = judge(&stats, &dead, false);
        assert!(findings.contains(&"noExternalPath"));
    }

    #[test]
    fn lan_measurements_survive_an_intercepting_proxy() {
        // Regression: a proxy faking internet replies does not touch LAN traffic,
        // so a real gateway measurement must not be labeled untrustworthy.
        let stats = summarize(8, &[3.8, 7.2, 21.5, 4.0, 5.1, 6.3, 4.4, 5.0]);
        let (health, findings) = judge(&stats, &intercepted_path(), true);
        assert_ne!(health, Health::Untrustworthy);
        assert!(!findings.contains(&"resultsNotTrustworthy"));
        // The proxy is still worth mentioning, just not as a reason to distrust.
        assert!(findings.contains(&"localProxyPresentLanUnaffected"));
    }

    #[test]
    fn external_target_still_warns_while_lan_note_is_added() {
        let stats = summarize(8, &[18.0, 19.0, 18.5, 20.0, 19.5, 18.2, 19.1, 18.8]);
        let (health, _) = judge(&stats, &intercepted_path(), false);
        assert_eq!(health, Health::Untrustworthy);
    }

    #[test]
    fn fake_ip_resolution_alone_proves_interception() {
        use crate::quick_check::interference::{assess_with_resolution, is_fake_ip};
        assert!(is_fake_ip("198.18.16.6".parse().unwrap()));
        assert!(!is_fake_ip("17.253.144.10".parse().unwrap()));

        // Timings look entirely normal here; only the address betrays the proxy.
        let verdict = assess_with_resolution(
            Some(3.0),
            vec![anchor(Some(14.0)), anchor(Some(22.0)), anchor(Some(35.0))],
            Some("198.18.16.6".parse().unwrap()),
        );
        assert_eq!(verdict.verdict, PathVerdict::LocallyIntercepted);
        assert!(verdict.reasons.contains(&"fakeIpResolution"));
    }

    #[test]
    fn local_scope_covers_the_common_home_ranges() {
        use crate::quick_check::interference::is_local_scope;
        for local in ["192.168.2.1", "10.0.0.1", "172.16.5.5"] {
            assert!(is_local_scope(local.parse().unwrap()), "{local} should be local");
        }
        for remote in ["1.1.1.1", "17.253.144.10", "198.18.16.6"] {
            assert!(!is_local_scope(remote.parse().unwrap()), "{remote} should be remote");
        }
    }

    #[test]
    fn rejects_a_bad_target_before_touching_the_network() {
        let error = run("-f", |_| {}).unwrap_err();
        assert_eq!(error, "target:leadingDash");
    }
}
