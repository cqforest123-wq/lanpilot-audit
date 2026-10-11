//! Hop-by-hop path discovery, using the same in-process ICMP socket.
//!
//! Each probe goes out with a deliberately small hop limit. The router that
//! discards it answers with time-exceeded, and its address is that hop. Raising
//! the limit one step at a time walks the path outward until the target itself
//! replies.
//!
//! A caveat this tool states rather than hides: when a local proxy terminates
//! traffic, every hop appears to answer instantly from the destination address,
//! and the resulting list describes the proxy, not the route. The caller passes
//! that verdict in so the UI can say so.

use std::ffi::CStr;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use serde::Serialize;

use super::icmp::{PingSocket, ProbeOutcome};

/// Standard traceroute ceiling; paths longer than this are effectively broken.
pub const MAX_HOPS: u8 = 30;
/// Give up early after this many silent hops in a row.
const CONSECUTIVE_SILENT_LIMIT: u8 = 5;
const HOP_TIMEOUT: Duration = Duration::from_millis(1200);

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Hop {
    pub ttl: u8,
    pub address: Option<String>,
    /// Reverse-DNS name, which is what makes a hop list readable.
    pub hostname: Option<String>,
    pub rtt_ms: Option<f64>,
    /// True once the destination itself answered.
    pub reached_target: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum TraceOutcome {
    /// The destination answered.
    Completed,
    /// The ceiling was reached without arriving.
    HopLimitReached,
    /// The path went quiet and the sweep stopped early.
    Abandoned,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Trace {
    pub target: String,
    pub hops: Vec<Hop>,
    pub outcome: TraceOutcome,
    /// True when the hop list is too short to be a real internet path.
    pub implausibly_short: bool,
}

/// A distant target that answers within a hop or two was not actually reached.
///
/// Real internet paths cross the local router, the ISP edge, and at least one
/// transit network. When a proxy terminates traffic locally it answers the very
/// first probe *from the destination address*, and reverse DNS resolves it, so
/// the result looks entirely convincing. Reporting "1 hop to Cloudflare" as a
/// route would be worse than reporting nothing.
pub fn is_implausibly_short(hops: &[Hop], target_is_local: bool) -> bool {
    if target_is_local {
        return false;
    }
    let answered = hops.iter().filter(|hop| hop.address.is_some()).count();
    let reached = hops.iter().any(|hop| hop.reached_target);
    reached && answered <= 2
}

/// Decide whether to keep walking outward.
///
/// Split out from the socket loop so the stopping rules are testable: an early
/// stop that fires too eagerly truncates a real path, and one that never fires
/// makes the user wait thirty timeouts for a dead route.
pub fn should_continue(ttl: u8, consecutive_silent: u8, reached: bool) -> bool {
    !reached && ttl < MAX_HOPS && consecutive_silent < CONSECUTIVE_SILENT_LIMIT
}

/// Final outcome from how the sweep ended.
pub fn classify(reached: bool, ttl: u8, consecutive_silent: u8) -> TraceOutcome {
    if reached {
        TraceOutcome::Completed
    } else if consecutive_silent >= CONSECUTIVE_SILENT_LIMIT {
        TraceOutcome::Abandoned
    } else if ttl >= MAX_HOPS {
        TraceOutcome::HopLimitReached
    } else {
        TraceOutcome::Abandoned
    }
}

/// Reverse-resolve an address, returning `None` when it has no name.
///
/// Uses `getnameinfo` rather than a PTR query so the system's own resolver
/// order and caching apply, and so no extra DNS traffic is generated.
pub fn reverse_lookup(address: IpAddr) -> Option<String> {
    let socket_address = SocketAddr::new(address, 0);
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let length: libc::socklen_t;

    match socket_address {
        SocketAddr::V4(v4) => {
            let target = &mut storage as *mut _ as *mut libc::sockaddr_in;
            // SAFETY: storage is large enough for sockaddr_in and is zeroed.
            unsafe {
                (*target).sin_family = libc::AF_INET as libc::sa_family_t;
                (*target).sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
            }
            length = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        }
        SocketAddr::V6(v6) => {
            let target = &mut storage as *mut _ as *mut libc::sockaddr_in6;
            // SAFETY: storage is large enough for sockaddr_in6 and is zeroed.
            unsafe {
                (*target).sin6_family = libc::AF_INET6 as libc::sa_family_t;
                (*target).sin6_addr.s6_addr = v6.ip().octets();
            }
            length = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
        }
    }

    let mut host = [0 as libc::c_char; 256];
    // SAFETY: storage and host are valid for the lengths passed.
    let status = unsafe {
        libc::getnameinfo(
            &storage as *const _ as *const libc::sockaddr,
            length,
            host.as_mut_ptr(),
            host.len() as libc::socklen_t,
            std::ptr::null_mut(),
            0,
            libc::NI_NAMEREQD,
        )
    };
    if status != 0 {
        return None;
    }

    // SAFETY: getnameinfo NUL-terminates on success.
    let name = unsafe { CStr::from_ptr(host.as_ptr()) }.to_string_lossy().into_owned();
    (!name.is_empty()).then_some(name)
}

/// Walk the path to `address`, reporting each hop as it is found.
pub fn run(
    address: IpAddr,
    resolve_names: bool,
    mut on_hop: impl FnMut(&Hop),
) -> Result<Trace, String> {
    let socket = PingSocket::open(address).map_err(|error| format!("socketFailed:{error}"))?;

    let mut hops = Vec::new();
    let mut consecutive_silent = 0u8;
    let mut reached = false;
    let mut ttl = 0u8;

    while should_continue(ttl, consecutive_silent, reached) {
        ttl += 1;
        socket.set_ttl(u32::from(ttl)).map_err(|error| format!("ttlFailed:{error}"))?;

        let outcome = socket
            .probe(address, u16::from(ttl), HOP_TIMEOUT)
            .map_err(|error| format!("probeFailed:{error}"))?;

        let hop = match outcome {
            ProbeOutcome::Reply { from, rtt, .. } => {
                reached = true;
                consecutive_silent = 0;
                build_hop(ttl, Some(from), Some(rtt), true, resolve_names)
            }
            ProbeOutcome::TimeExceeded { from, rtt } | ProbeOutcome::Unreachable { from, rtt } => {
                consecutive_silent = 0;
                build_hop(ttl, Some(from), Some(rtt), false, resolve_names)
            }
            ProbeOutcome::Timeout => {
                consecutive_silent += 1;
                build_hop(ttl, None, None, false, false)
            }
        };

        on_hop(&hop);
        hops.push(hop);
    }

    let target_is_local = super::interference::is_local_scope(address);
    Ok(Trace {
        target: address.to_string(),
        implausibly_short: is_implausibly_short(&hops, target_is_local),
        hops,
        outcome: classify(reached, ttl, consecutive_silent),
    })
}

fn build_hop(
    ttl: u8,
    address: Option<IpAddr>,
    rtt: Option<Duration>,
    reached_target: bool,
    resolve_names: bool,
) -> Hop {
    Hop {
        ttl,
        hostname: address.filter(|_| resolve_names).and_then(reverse_lookup),
        address: address.map(|ip| ip.to_string()),
        rtt_ms: rtt.map(|value| (value.as_secs_f64() * 100_000.0).round() / 100.0),
        reached_target,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_walking_while_the_path_answers() {
        assert!(should_continue(1, 0, false));
        assert!(should_continue(15, 2, false));
    }

    #[test]
    fn stops_as_soon_as_the_target_replies() {
        assert!(!should_continue(3, 0, true));
    }

    #[test]
    fn stops_at_the_hop_ceiling() {
        assert!(!should_continue(MAX_HOPS, 0, false));
    }

    #[test]
    fn tolerates_a_few_silent_hops_before_giving_up() {
        // Silent middle hops are common; abandoning at the first would truncate
        // paths that recover a hop or two later.
        assert!(should_continue(8, CONSECUTIVE_SILENT_LIMIT - 1, false));
        assert!(!should_continue(8, CONSECUTIVE_SILENT_LIMIT, false));
    }

    #[test]
    fn classifies_how_the_sweep_ended() {
        assert_eq!(classify(true, 7, 0), TraceOutcome::Completed);
        assert_eq!(classify(false, MAX_HOPS, 1), TraceOutcome::HopLimitReached);
        assert_eq!(classify(false, 9, CONSECUTIVE_SILENT_LIMIT), TraceOutcome::Abandoned);
    }

    fn hop(ttl: u8, address: Option<&str>, reached: bool) -> Hop {
        Hop {
            ttl,
            address: address.map(str::to_string),
            hostname: None,
            rtt_ms: address.map(|_| 1.0),
            reached_target: reached,
        }
    }

    #[test]
    fn one_hop_to_a_distant_target_is_not_believable() {
        // Measured on a Mac running a TUN proxy: 1.1.1.1 answered at ttl=1, and
        // reverse DNS even returned one.one.one.one.
        let hops = vec![hop(1, Some("1.1.1.1"), true)];
        assert!(is_implausibly_short(&hops, false));
    }

    #[test]
    fn a_real_path_is_not_flagged() {
        let hops = vec![
            hop(1, Some("192.168.2.1"), false),
            hop(2, Some("100.64.0.1"), false),
            hop(3, Some("203.0.113.9"), false),
            hop(4, Some("1.1.1.1"), true),
        ];
        assert!(!is_implausibly_short(&hops, false));
    }

    #[test]
    fn a_lan_target_is_legitimately_one_hop_away() {
        let hops = vec![hop(1, Some("192.168.2.1"), true)];
        assert!(!is_implausibly_short(&hops, true), "the router really is next door");
    }

    #[test]
    fn an_unfinished_trace_is_not_flagged() {
        // Nothing was reached, so there is no false "you arrived" to correct.
        let hops = vec![hop(1, Some("192.168.2.1"), false), hop(2, None, false)];
        assert!(!is_implausibly_short(&hops, false));
    }

    #[test]
    fn reverse_lookup_resolves_a_known_name_or_returns_none() {
        // Must never panic, whatever the resolver says.
        let _ = reverse_lookup("8.8.8.8".parse().unwrap());
        // A documentation-range address has no PTR record.
        assert_eq!(reverse_lookup("203.0.113.1".parse().unwrap()), None);
    }
}
