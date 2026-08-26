//! Find every device on the local subnet, not just the ones already known.
//!
//! The neighbour table is passive but partial: it only holds hosts this Mac has
//! already spoken to. Answering "what is on my network" means asking every
//! address, which is what this does -- one echo request per host on the local
//! subnet, then a re-read of the neighbour table so the replies can be paired
//! with hardware addresses and manufacturers.
//!
//! Presence is decided by the neighbour table, not by the echo replies. On a
//! local segment the echo is really a way of making the kernel resolve the
//! address: whatever answers ARP is on the wire, and ARP cannot be firewalled
//! away the way ICMP can. Cameras in particular very often ignore ping while
//! answering ARP perfectly, so scoring on replies alone would miss exactly the
//! devices this is for. Measured on the development network, echo replies found
//! one host and the neighbour table found the gateway as well.
//!
//! Two bounds keep it a discovery tool rather than a scanner. It only sweeps
//! the subnet this Mac is actually attached to, computed from the interface
//! address and netmask, never a range the caller supplies. And it refuses
//! anything larger than a /22, because a /16 is 65,000 probes and nobody
//! diagnosing a camera network needs that.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;

use super::icmp::{PingSocket, ProbeOutcome};
use super::neighbours::{self, Neighbour};

/// Smallest prefix worth sweeping. /22 is 1022 hosts, already a large network.
pub const MIN_PREFIX: u8 = 22;
/// Short, because a host on the same segment answers in single-digit
/// milliseconds or is not there.
const HOST_TIMEOUT: Duration = Duration::from_millis(700);
/// Enough to finish a /24 in a few seconds without flooding the segment.
const WORKERS: usize = 24;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SweepRefusal {
    /// The interface has no usable IPv4 address.
    NoLocalSubnet,
    /// The subnet is larger than this tool will sweep.
    SubnetTooLarge,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SweepResult {
    /// The subnet actually swept, in CIDR form.
    pub subnet: String,
    pub probed: u32,
    pub responded: u32,
    pub hosts: Vec<Neighbour>,
}

/// Every usable host address in a subnet, excluding network and broadcast.
///
/// Returned as a list rather than an iterator so the caller can report progress
/// against a known total.
pub fn hosts_in(address: Ipv4Addr, prefix: u8) -> Result<Vec<Ipv4Addr>, SweepRefusal> {
    if !(MIN_PREFIX..=30).contains(&prefix) {
        return Err(SweepRefusal::SubnetTooLarge);
    }
    let mask = u32::MAX
        .checked_shl(u32::from(32 - prefix))
        .unwrap_or(0);
    let network = u32::from(address) & mask;
    let broadcast = network | !mask;

    Ok(((network + 1)..broadcast).map(Ipv4Addr::from).collect())
}

/// Poke one address so the kernel resolves it, and report whether it also
/// answered the echo.
///
/// Two probes are sent because the first is consumed by address resolution on
/// a local segment -- the same warm-up the single-target check makes -- so one
/// probe would time out against every host not already known. The sequence
/// number is derived from the host so a reply arriving late, after its worker
/// has moved on, cannot be counted for a different address.
fn poke(address: Ipv4Addr) -> bool {
    let target = IpAddr::V4(address);
    let Ok(socket) = PingSocket::open(target) else {
        return false;
    };
    let sequence = (u32::from(address) & 0xffff) as u16;

    for attempt in 0..2 {
        match socket.probe(target, sequence.wrapping_add(attempt), HOST_TIMEOUT) {
            Ok(ProbeOutcome::Reply { from, .. }) if from == target => return true,
            Ok(_) => continue,
            Err(_) => return false,
        }
    }
    false
}

/// Sweep the subnet the given interface is attached to.
///
/// `on_progress` receives (completed, total) so a long run stays legible.
pub fn run(
    address: Ipv4Addr,
    prefix: u8,
    mut on_progress: impl FnMut(u32, u32),
) -> Result<SweepResult, SweepRefusal> {
    let targets = hosts_in(address, prefix)?;
    let total = targets.len() as u32;
    let subnet = format!("{}/{}", u32::from(address) & mask_for(prefix), prefix);
    let subnet = subnet
        .split_once('/')
        .map(|(network, bits)| {
            format!("{}/{}", Ipv4Addr::from(network.parse::<u32>().unwrap_or(0)), bits)
        })
        .unwrap_or(subnet);

    let queue = Arc::new(Mutex::new(targets));
    let alive = Arc::new(Mutex::new(Vec::new()));
    let done = Arc::new(AtomicUsize::new(0));

    std::thread::scope(|scope| {
        for _ in 0..WORKERS.min(total as usize).max(1) {
            let queue = Arc::clone(&queue);
            let alive = Arc::clone(&alive);
            let done = Arc::clone(&done);
            scope.spawn(move || loop {
                let Some(next) = queue.lock().ok().and_then(|mut q| q.pop()) else {
                    return;
                };
                if poke(next) {
                    if let Ok(mut found) = alive.lock() {
                        found.push(next);
                    }
                }
                done.fetch_add(1, Ordering::Relaxed);
            });
        }

        // Report from the calling thread while the workers run.
        while done.load(Ordering::Relaxed) < total as usize {
            on_progress(done.load(Ordering::Relaxed) as u32, total);
            std::thread::sleep(Duration::from_millis(120));
        }
    });
    on_progress(total, total);

    let echoed: Vec<Ipv4Addr> = alive.lock().map(|found| found.clone()).unwrap_or_default();

    // Give the last resolutions a moment to land before reading the table.
    std::thread::sleep(Duration::from_millis(300));

    let swept: std::collections::HashSet<String> =
        targets_in(address, prefix).into_iter().map(|entry| entry.to_string()).collect();

    // Anything with a resolved hardware address is on the wire, whether or not
    // it chose to answer the echo.
    let mut hosts: Vec<Neighbour> = neighbours::list(true)
        .into_iter()
        .filter(|entry| {
            swept.contains(&entry.ip)
                && entry.kind != neighbours::NeighbourKind::Unresolved
        })
        .collect();

    // Add anything that replied but left no neighbour entry, which happens when
    // the address is reached through a router rather than the local segment.
    let known: HashMap<String, ()> =
        hosts.iter().map(|entry| (entry.ip.clone(), ())).collect();
    for address in &echoed {
        let key = address.to_string();
        if known.contains_key(&key) {
            continue;
        }
        hosts.push(Neighbour {
            ip: key,
            mac: None,
            kind: neighbours::NeighbourKind::Unresolved,
            vendor: None,
            likely: None,
            interface: None,
            hostname: None,
        });
    }

    hosts.sort_by_key(|entry| entry.ip.parse::<Ipv4Addr>().map(u32::from).unwrap_or(0));
    hosts.dedup_by(|a, b| a.ip == b.ip);

    let responded = hosts.len() as u32;
    Ok(SweepResult { subnet, probed: total, responded, hosts })
}

/// The addresses a sweep covers, or empty when the subnet is out of bounds.
fn targets_in(address: Ipv4Addr, prefix: u8) -> Vec<Ipv4Addr> {
    hosts_in(address, prefix).unwrap_or_default()
}

fn mask_for(prefix: u8) -> u32 {
    u32::MAX.checked_shl(u32::from(32 - prefix)).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_slash_24_yields_the_usable_hosts_only() {
        let hosts = hosts_in(Ipv4Addr::new(192, 168, 2, 224), 24).expect("sweepable");
        assert_eq!(hosts.len(), 254, "network and broadcast are excluded");
        assert_eq!(hosts[0], Ipv4Addr::new(192, 168, 2, 1));
        assert_eq!(hosts[253], Ipv4Addr::new(192, 168, 2, 254));
    }

    #[test]
    fn the_subnet_is_derived_from_the_address_not_assumed() {
        // Same /24 whichever host address is passed in.
        let from_low = hosts_in(Ipv4Addr::new(10, 1, 1, 5), 24).unwrap();
        let from_high = hosts_in(Ipv4Addr::new(10, 1, 1, 250), 24).unwrap();
        assert_eq!(from_low, from_high);
        assert_eq!(from_low[0], Ipv4Addr::new(10, 1, 1, 1));
    }

    #[test]
    fn refuses_a_subnet_too_large_to_be_a_diagnosis() {
        // A /16 is 65,000 probes; nothing here needs that.
        assert_eq!(hosts_in(Ipv4Addr::new(10, 0, 0, 1), 16), Err(SweepRefusal::SubnetTooLarge));
        assert_eq!(hosts_in(Ipv4Addr::new(10, 0, 0, 1), 8), Err(SweepRefusal::SubnetTooLarge));
    }

    #[test]
    fn accepts_the_largest_allowed_subnet() {
        let hosts = hosts_in(Ipv4Addr::new(172, 16, 4, 9), MIN_PREFIX).expect("sweepable");
        assert_eq!(hosts.len(), 1022);
    }

    #[test]
    fn handles_the_smallest_useful_subnet() {
        // A /30 is a point-to-point link: two usable addresses.
        let hosts = hosts_in(Ipv4Addr::new(192, 168, 1, 1), 30).expect("sweepable");
        assert_eq!(hosts.len(), 2);
    }

    #[test]
    fn refuses_a_host_route() {
        // /31 and /32 have no usable host range to sweep.
        assert!(hosts_in(Ipv4Addr::new(192, 168, 1, 1), 31).is_err());
        assert!(hosts_in(Ipv4Addr::new(192, 168, 1, 1), 32).is_err());
    }

    #[test]
    fn the_mask_never_overflows_the_shift() {
        // 32 - 32 = 0 would shift by 32 and panic in debug builds.
        assert_eq!(mask_for(24), 0xffff_ff00);
        assert_eq!(mask_for(32), u32::MAX);
        assert_eq!(mask_for(0), 0);
    }
}
