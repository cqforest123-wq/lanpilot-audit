//! Clock accuracy, measured against a time server over NTP.
//!
//! This looks like it belongs in a clock app rather than a network tool, but a
//! wrong clock presents as a network fault and nothing else diagnoses it. TLS
//! certificates are only valid between two dates, so a Mac whose clock has
//! drifted far enough reports *every* HTTPS site as insecure, and the user
//! reasonably concludes their connection is broken or intercepted. Two-factor
//! codes fail first, at around thirty seconds of drift, long before the web
//! breaks.
//!
//! Plain UDP to port 123, same as the system's own time client.

use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;

/// Several servers are tried because one may be blocked or slow, and the
/// sample with the shortest round trip is the most accurate one available.
pub const SERVERS: [&str; 3] = ["time.apple.com", "pool.ntp.org", "time.cloudflare.com"];
/// The server macOS itself uses, so agreement is the expected state.
pub const DEFAULT_SERVER: &str = "time.apple.com";

const NTP_PORT: u16 = 123;
const TIMEOUT: Duration = Duration::from_millis(2500);
const PACKET_LEN: usize = 48;
/// Seconds between the NTP epoch (1900) and the Unix epoch (1970).
const NTP_TO_UNIX: f64 = 2_208_988_800.0;
/// Two-factor codes step every thirty seconds, so they break first.
const TWO_FACTOR_LIMIT_MS: f64 = 30_000.0;
/// Below this, drift is invisible in practice.
const ACCURATE_LIMIT_MS: f64 = 1_000.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ClockVerdict {
    Accurate,
    /// Noticeable but not yet breaking anything.
    Drifting,
    /// Far enough to break authentication and certificate validation.
    Wrong,
    Unreachable,
    /// A reply arrived, but the path is too slow or lopsided to measure with.
    Imprecise,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClockCheck {
    pub server: String,
    /// How far this Mac's clock is from the server's, in milliseconds.
    /// Positive means this Mac is behind.
    pub offset_ms: Option<f64>,
    pub round_trip_ms: Option<f64>,
    /// Half the round trip: the best case error bound on `offset_ms`.
    pub uncertainty_ms: Option<f64>,
    pub verdict: ClockVerdict,
    pub reasons: Vec<&'static str>,
}

/// Build a client-mode request. Only the mode byte matters on the way out.
fn build_request(transmit: f64) -> [u8; PACKET_LEN] {
    let mut packet = [0u8; PACKET_LEN];
    // Leap indicator 0, version 3, mode 3 (client).
    packet[0] = 0x1B;
    write_timestamp(&mut packet[40..48], transmit);
    packet
}

fn write_timestamp(target: &mut [u8], seconds_since_unix: f64) {
    let ntp = seconds_since_unix + NTP_TO_UNIX;
    let whole = ntp.trunc() as u32;
    let fraction = ((ntp - ntp.trunc()) * f64::from(u32::MAX)) as u32;
    target[0..4].copy_from_slice(&whole.to_be_bytes());
    target[4..8].copy_from_slice(&fraction.to_be_bytes());
}

/// Read an NTP timestamp as seconds since the Unix epoch.
pub fn read_timestamp(bytes: &[u8]) -> Option<f64> {
    let whole = u32::from_be_bytes(bytes.get(0..4)?.try_into().ok()?);
    let fraction = u32::from_be_bytes(bytes.get(4..8)?.try_into().ok()?);
    // An all-zero timestamp means "not set", not 1900.
    if whole == 0 && fraction == 0 {
        return None;
    }
    Some(f64::from(whole) + f64::from(fraction) / f64::from(u32::MAX) - NTP_TO_UNIX)
}

/// Offset and round trip from the four timestamps, per RFC 5905.
///
/// The averaging matters: a naive `server - local` comparison folds the network
/// delay into the answer and reports a fast link as an accurate clock.
pub fn offset_and_delay(t1: f64, t2: f64, t3: f64, t4: f64) -> (f64, f64) {
    let offset = ((t2 - t1) + (t3 - t4)) / 2.0;
    let delay = (t4 - t1) - (t3 - t2);
    (offset * 1000.0, delay.max(0.0) * 1000.0)
}

/// Grade an offset by what it actually breaks, allowing for how well it could
/// be measured.
///
/// NTP knows the offset to about half the round trip, and an asymmetric path --
/// which a proxy or VPN routinely produces -- biases it further still. Measured
/// here through a TUN proxy: an 817 ms round trip yielded a 1075 ms "offset" on
/// a Mac whose clock was in fact synchronised. Reporting that as drift would be
/// inventing a fault, so the margin is subtracted before judging and a path too
/// slow to measure on is called out as such.
pub fn judge(offset_ms: Option<f64>, delay_ms: Option<f64>) -> (ClockVerdict, Vec<&'static str>) {
    let Some(offset) = offset_ms else {
        return (ClockVerdict::Unreachable, vec!["noTimeReply"]);
    };

    // NTP knows the offset to about half the round trip, so the true value lies
    // somewhere in [|offset| - margin, |offset| + margin]. A conclusion is only
    // drawn when that whole interval sits on one side of a threshold; comparing
    // a single threshold against the midpoint would put a cliff in the middle
    // of the uncertainty, where two nearly identical samples land on opposite
    // verdicts.
    let margin = delay_ms.map(|delay| delay / 2.0).unwrap_or(0.0);
    let lowest = (offset.abs() - margin).max(0.0);
    let highest = offset.abs() + margin;

    if lowest >= TWO_FACTOR_LIMIT_MS {
        let mut reasons = vec!["clockWrong", "breaksTwoFactor"];
        // TLS tolerances are wider, so certificates fail later than codes do.
        if lowest >= 300_000.0 {
            reasons.push("breaksCertificates");
        }
        return (ClockVerdict::Wrong, reasons);
    }

    if lowest >= ACCURATE_LIMIT_MS {
        return (ClockVerdict::Drifting, vec!["clockDrifting"]);
    }

    // Provably fine only when even the worst case is under the limit.
    if highest < ACCURATE_LIMIT_MS {
        return (ClockVerdict::Accurate, vec!["clockAccurate"]);
    }

    (ClockVerdict::Imprecise, vec!["pathTooSlowToMeasure"])
}

fn unix_now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

/// Query a time server and compare its clock with this Mac's.
pub fn check(server: &str) -> ClockCheck {
    let label = server.to_string();

    let Some(address) = resolve(server) else {
        return ClockCheck {
            server: label,
            offset_ms: None,
            round_trip_ms: None,
            uncertainty_ms: None,
            verdict: ClockVerdict::Unreachable,
            reasons: vec!["resolveFailed"],
        };
    };

    let Ok(socket) = UdpSocket::bind("0.0.0.0:0") else {
        return unreachable(label, "socketFailed");
    };
    let _ = socket.set_read_timeout(Some(TIMEOUT));

    let t1 = unix_now();
    if socket.send_to(&build_request(t1), SocketAddr::new(address, NTP_PORT)).is_err() {
        return unreachable(label, "sendFailed");
    }

    let mut buffer = [0u8; PACKET_LEN];
    let Ok((len, _)) = socket.recv_from(&mut buffer) else {
        return unreachable(label, "noTimeReply");
    };
    let t4 = unix_now();

    if len < PACKET_LEN {
        return unreachable(label, "shortReply");
    }

    // Receive timestamp at 32, transmit at 40.
    let (Some(t2), Some(t3)) = (read_timestamp(&buffer[32..40]), read_timestamp(&buffer[40..48]))
    else {
        return unreachable(label, "emptyTimestamps");
    };

    let (offset_ms, delay_ms) = offset_and_delay(t1, t2, t3, t4);
    let (verdict, reasons) = judge(Some(offset_ms), Some(delay_ms));

    ClockCheck {
        server: label,
        offset_ms: Some((offset_ms * 10.0).round() / 10.0),
        round_trip_ms: Some((delay_ms * 10.0).round() / 10.0),
        uncertainty_ms: Some((delay_ms / 2.0 * 10.0).round() / 10.0),
        verdict,
        reasons,
    }
}

/// Try every server and keep the sample measured over the shortest path, which
/// is the one with the smallest error bound.
pub fn best_available() -> ClockCheck {
    let mut best: Option<ClockCheck> = None;
    for server in SERVERS {
        let sample = check(server);
        if sample.round_trip_ms.is_none() {
            continue;
        }
        let better = match &best {
            None => true,
            Some(current) => sample.round_trip_ms < current.round_trip_ms,
        };
        if better {
            // A clean, fast sample is as good as it gets; stop early.
            let fast = sample.round_trip_ms.is_some_and(|rtt| rtt < 100.0);
            best = Some(sample);
            if fast {
                break;
            }
        }
    }
    best.unwrap_or_else(|| unreachable(SERVERS[0].to_string(), "noTimeReply"))
}

fn unreachable(server: String, reason: &'static str) -> ClockCheck {
    ClockCheck {
        server,
        offset_ms: None,
        round_trip_ms: None,
        uncertainty_ms: None,
        verdict: ClockVerdict::Unreachable,
        reasons: vec![reason],
    }
}

fn resolve(server: &str) -> Option<IpAddr> {
    format!("{server}:{NTP_PORT}").to_socket_addrs().ok()?.next().map(|entry| entry.ip())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_is_a_client_mode_packet() {
        let packet = build_request(1_700_000_000.0);
        assert_eq!(packet.len(), PACKET_LEN);
        assert_eq!(packet[0], 0x1B, "leap 0, version 3, mode 3");
        assert_ne!(&packet[40..48], &[0u8; 8], "transmit timestamp must be set");
    }

    #[test]
    fn timestamps_round_trip_through_the_ntp_epoch() {
        let original = 1_700_000_000.5;
        let mut bytes = [0u8; 8];
        write_timestamp(&mut bytes, original);
        let parsed = read_timestamp(&bytes).expect("parses");
        assert!((parsed - original).abs() < 0.001, "got {parsed}");
    }

    #[test]
    fn an_all_zero_timestamp_is_absent_not_year_1900() {
        assert_eq!(read_timestamp(&[0u8; 8]), None);
    }

    #[test]
    fn offset_cancels_out_symmetric_network_delay() {
        // Server is exactly right; 100 ms each way must not look like drift.
        let (offset, delay) = offset_and_delay(0.0, 0.1, 0.1, 0.2);
        assert!(offset.abs() < 1.0, "offset was {offset} ms");
        assert!((delay - 200.0).abs() < 1.0, "delay was {delay} ms");
    }

    #[test]
    fn detects_a_clock_that_is_genuinely_behind() {
        // Local clock is 5 s behind, with 100 ms each way.
        let (offset, _) = offset_and_delay(0.0, 5.1, 5.1, 0.2);
        assert!((offset - 5000.0).abs() < 50.0, "offset was {offset} ms");
    }

    #[test]
    fn grades_by_what_the_drift_actually_breaks() {
        assert_eq!(judge(Some(120.0), Some(20.0)).0, ClockVerdict::Accurate);
        assert_eq!(judge(Some(4_000.0), Some(20.0)).0, ClockVerdict::Drifting);

        let (verdict, reasons) = judge(Some(45_000.0), Some(20.0));
        assert_eq!(verdict, ClockVerdict::Wrong);
        assert!(reasons.contains(&"breaksTwoFactor"));
        assert!(!reasons.contains(&"breaksCertificates"), "TLS tolerates more than codes do");

        let (_, reasons) = judge(Some(-600_000.0), Some(20.0));
        assert!(reasons.contains(&"breaksCertificates"));
    }

    #[test]
    fn a_clock_that_is_ahead_is_judged_the_same_as_one_behind() {
        assert_eq!(judge(Some(-45_000.0), Some(20.0)).0, ClockVerdict::Wrong);
        assert_eq!(judge(Some(45_000.0), Some(20.0)).0, ClockVerdict::Wrong);
    }

    #[test]
    fn no_reply_is_unreachable_not_accurate() {
        let (verdict, reasons) = judge(None, None);
        assert_eq!(verdict, ClockVerdict::Unreachable);
        assert!(reasons.contains(&"noTimeReply"));
    }

    #[test]
    fn a_slow_path_is_called_imprecise_rather_than_drifting() {
        // The measured case: ~800 ms round trip, ~1100 ms apparent offset, on a
        // Mac whose clock was actually synchronised.
        let (verdict, reasons) = judge(Some(1075.6), Some(817.0));
        assert_eq!(verdict, ClockVerdict::Imprecise);
        assert!(reasons.contains(&"pathTooSlowToMeasure"));
    }

    #[test]
    fn nearly_identical_samples_do_not_land_on_opposite_verdicts() {
        // Regression: a fixed uncertainty threshold graded 1089 ms / 769 ms as
        // accurate while 1126 ms / 948 ms came out imprecise.
        assert_eq!(judge(Some(1089.3), Some(769.3)).0, ClockVerdict::Imprecise);
        assert_eq!(judge(Some(1126.1), Some(947.7)).0, ClockVerdict::Imprecise);
        assert_eq!(judge(Some(1133.1), Some(851.3)).0, ClockVerdict::Imprecise);
    }

    #[test]
    fn a_fast_path_can_still_prove_the_clock_is_fine() {
        // 120 ms offset with a 20 ms round trip: even the worst case is small.
        assert_eq!(judge(Some(120.0), Some(20.0)).0, ClockVerdict::Accurate);
    }

    #[test]
    fn real_drift_still_surfaces_through_a_slow_path() {
        // Ten seconds cannot be explained by half of an 800 ms round trip.
        let (verdict, _) = judge(Some(10_000.0), Some(800.0));
        assert_eq!(verdict, ClockVerdict::Drifting);
    }

    #[test]
    fn the_error_bound_is_subtracted_before_judging() {
        // Just over the 30 s line, but half the round trip explains the excess.
        assert_eq!(judge(Some(31_000.0), Some(4_000.0)).0, ClockVerdict::Drifting);
        // And a 2 s round trip cannot explain away a 45 s offset.
        assert_eq!(judge(Some(45_000.0), Some(2_000.0)).0, ClockVerdict::Wrong);
        assert_eq!(judge(Some(31_000.0), Some(20.0)).0, ClockVerdict::Wrong);
    }

    #[test]
    fn negative_delay_from_clock_skew_is_clamped() {
        // A badly wrong clock can make the arithmetic produce a negative delay,
        // which would render as a nonsensical round trip.
        let (_, delay) = offset_and_delay(0.0, 100.0, 100.5, 0.1);
        assert!(delay >= 0.0, "delay was {delay}");
    }
}
