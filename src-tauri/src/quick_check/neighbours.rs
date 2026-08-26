//! Devices this Mac has recently exchanged traffic with, read from the ARP
//! cache.
//!
//! This is deliberately passive. The kernel keeps a table of neighbours it has
//! already talked to, and reading it sends no packets at all -- it is what
//! `arp -a` prints. That means it cannot claim to list *everything* on the
//! network: a camera this Mac has never contacted will not appear. The UI says
//! so, because "here is your network" would be a lie and the operator would
//! trust it.
//!
//! Randomised addresses are called out rather than shown as an unknown
//! manufacturer. Modern phones and Macs rotate their hardware address for
//! privacy, so on a current network most entries have no manufacturer to find,
//! and reporting that as "unknown vendor" would look like a gap in the data.

use std::ffi::CStr;
use std::net::Ipv4Addr;

use libc::{c_int, sysctl, AF_INET, CTL_NET, PF_ROUTE};
use serde::Serialize;

use super::oui::{self, DeviceKind};

/// `net.route.0.inet.flags` — the routing table filtered to link-layer entries.
const NET_RT_FLAGS: c_int = 2;
/// Set on routes that carry a resolved link-layer address.
const RTF_LLINFO: c_int = 0x400;
/// Verified against <net/route.h> on Darwin arm64; see `route.rs`.
const RT_MSGHDR_LEN: usize = 92;
const RTM_INDEX_OFFSET: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum NeighbourKind {
    /// An ordinary device with a manufacturer-assigned address.
    Device,
    /// A privacy-rotated address, which no manufacturer owns.
    Randomised,
    /// A group address, not a device at all.
    Multicast,
    /// The subnet broadcast address.
    Broadcast,
    /// In the table, but the address was never resolved.
    Unresolved,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Neighbour {
    pub ip: String,
    pub mac: Option<String>,
    pub kind: NeighbourKind,
    pub vendor: Option<String>,
    /// What the manufacturer suggests this is. Always a guess.
    pub likely: Option<DeviceKind>,
    pub interface: Option<String>,
    pub hostname: Option<String>,
}

/// Classify an address before trying to name its manufacturer.
///
/// Order matters: multicast is checked first because the multicast bit and the
/// locally-administered bit live in the same octet, and a group address is not
/// a randomised device.
pub fn classify(mac: Option<&[u8; 6]>) -> NeighbourKind {
    let Some(bytes) = mac else {
        return NeighbourKind::Unresolved;
    };
    if bytes.iter().all(|byte| *byte == 0xff) {
        return NeighbourKind::Broadcast;
    }
    if bytes[0] & 0x01 != 0 {
        return NeighbourKind::Multicast;
    }
    if bytes[0] & 0x02 != 0 {
        return NeighbourKind::Randomised;
    }
    NeighbourKind::Device
}

fn format_mac(bytes: &[u8; 6]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect::<Vec<_>>().join(":")
}

fn dump_arp_table() -> Option<Vec<u8>> {
    let mut mib: [c_int; 6] = [CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS, RTF_LLINFO];
    let mut needed: usize = 0;

    // SAFETY: the first call only sizes the buffer.
    if unsafe {
        sysctl(mib.as_mut_ptr(), mib.len() as u32, std::ptr::null_mut(), &mut needed, std::ptr::null_mut(), 0)
    } != 0
        || needed == 0
    {
        return None;
    }

    let mut buffer = vec![0u8; needed];
    // SAFETY: buffer is `needed` bytes, which is what the kernel asked for.
    if unsafe {
        sysctl(mib.as_mut_ptr(), mib.len() as u32, buffer.as_mut_ptr().cast(), &mut needed, std::ptr::null_mut(), 0)
    } != 0
    {
        return None;
    }
    buffer.truncate(needed);
    Some(buffer)
}

/// Walk the link-layer records, pairing each address with its hardware address.
///
/// Split from the syscall so it can be tested against a captured table.
pub fn parse_table(buffer: &[u8]) -> Vec<(Ipv4Addr, Option<[u8; 6]>, u16)> {
    let mut found = Vec::new();
    let mut offset = 0usize;

    while offset + RT_MSGHDR_LEN <= buffer.len() {
        let msglen = u16::from_ne_bytes([buffer[offset], buffer[offset + 1]]) as usize;
        if msglen < RT_MSGHDR_LEN || offset + msglen > buffer.len() {
            break;
        }
        let message = &buffer[offset..offset + msglen];
        offset += msglen;

        let index = u16::from_ne_bytes([message[RTM_INDEX_OFFSET], message[RTM_INDEX_OFFSET + 1]]);

        // The destination sockaddr_in follows the header.
        let Some(sockaddr) = message.get(RT_MSGHDR_LEN..) else { continue };
        let sa_len = *sockaddr.first().unwrap_or(&0) as usize;
        if sa_len < 8 {
            continue;
        }
        let Some(octets) = sockaddr.get(4..8) else { continue };
        let ip = Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);

        // The sockaddr_dl follows, padded to a 4-byte boundary.
        let padded = (sa_len + 3) & !3;
        let mac = sockaddr.get(padded..).and_then(read_link_address);

        found.push((ip, mac, index));
    }

    found
}

/// Read the hardware address out of a `sockaddr_dl`.
///
/// Layout: sdl_len, sdl_family, sdl_index(2), sdl_type, sdl_nlen, sdl_alen,
/// sdl_slen, then sdl_data holding the name followed by the address.
fn read_link_address(sockaddr: &[u8]) -> Option<[u8; 6]> {
    let name_len = *sockaddr.get(5)? as usize;
    let address_len = *sockaddr.get(6)? as usize;
    if address_len != 6 {
        return None;
    }
    const DATA_OFFSET: usize = 8;
    let start = DATA_OFFSET + name_len;
    let bytes = sockaddr.get(start..start + 6)?;
    Some([bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]])
}

fn interface_name(index: u16) -> Option<String> {
    if index == 0 {
        return None;
    }
    let mut buffer = [0 as libc::c_char; libc::IF_NAMESIZE];
    // SAFETY: buffer is IF_NAMESIZE, which is what if_indextoname requires.
    let result = unsafe { libc::if_indextoname(u32::from(index), buffer.as_mut_ptr()) };
    if result.is_null() {
        return None;
    }
    // SAFETY: if_indextoname NUL-terminates on success.
    let name = unsafe { CStr::from_ptr(buffer.as_ptr()) }.to_string_lossy().into_owned();
    (!name.is_empty()).then_some(name)
}

/// Read the neighbour table and enrich it.
///
/// `resolve_names` costs a reverse lookup per entry, so the caller decides.
pub fn list(resolve_names: bool) -> Vec<Neighbour> {
    let Some(buffer) = dump_arp_table() else {
        return Vec::new();
    };

    let mut neighbours: Vec<Neighbour> = parse_table(&buffer)
        .into_iter()
        .map(|(ip, mac, index)| {
            let kind = classify(mac.as_ref());
            // Only a manufacturer-assigned address can have a manufacturer.
            let vendor = (kind == NeighbourKind::Device)
                .then(|| mac.as_ref().map(format_mac))
                .flatten()
                .and_then(|address| oui::lookup(&address));

            Neighbour {
                hostname: resolve_names
                    .then(|| super::traceroute::reverse_lookup(ip.into()))
                    .flatten(),
                ip: ip.to_string(),
                mac: mac.as_ref().map(format_mac),
                kind,
                vendor: vendor.map(|(name, _)| name.to_string()),
                likely: vendor.map(|(_, kind)| kind),
                interface: interface_name(index),
            }
        })
        .collect();

    // Group and broadcast addresses are infrastructure noise, not neighbours.
    neighbours.retain(|entry| {
        !matches!(entry.kind, NeighbourKind::Multicast | NeighbourKind::Broadcast)
    });

    neighbours.sort_by_key(|entry| entry.ip.parse::<Ipv4Addr>().map(u32::from).unwrap_or(0));
    neighbours.dedup_by(|a, b| a.ip == b.ip && a.mac == b.mac);
    neighbours
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn separates_the_two_meanings_of_a_set_bit_in_the_first_octet() {
        // 0x01 is multicast and 0x02 is locally administered; both live in the
        // same octet and mean entirely different things.
        assert_eq!(classify(Some(&[0xbc, 0x45, 0x29, 0xad, 0x08, 0x59])), NeighbourKind::Device);
        assert_eq!(classify(Some(&[0xe6, 0x70, 0x7b, 0x6a, 0x56, 0xe5])), NeighbourKind::Randomised);
        assert_eq!(classify(Some(&[0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb])), NeighbourKind::Multicast);
        assert_eq!(classify(Some(&[0xff; 6])), NeighbourKind::Broadcast);
        assert_eq!(classify(None), NeighbourKind::Unresolved);
    }

    #[test]
    fn every_randomised_form_is_recognised() {
        // The locally-administered bit set, across all four nibble values.
        for first in [0x02, 0x06, 0x0a, 0x0e, 0x4a, 0xea] {
            assert_eq!(
                classify(Some(&[first, 0, 0, 0, 0, 1])),
                NeighbourKind::Randomised,
                "{first:#04x}"
            );
        }
    }

    #[test]
    fn formats_addresses_the_way_they_are_written() {
        assert_eq!(format_mac(&[0x0e, 0xb2, 0x4e, 0x92, 0x57, 0xd5]), "0e:b2:4e:92:57:d5");
    }

    /// One rt_msghdr followed by a sockaddr_in and a sockaddr_dl.
    fn arp_record(ip: Ipv4Addr, mac: Option<[u8; 6]>, index: u16) -> Vec<u8> {
        let mut message = vec![0u8; RT_MSGHDR_LEN];
        message[RTM_INDEX_OFFSET..RTM_INDEX_OFFSET + 2].copy_from_slice(&index.to_ne_bytes());

        let mut sockaddr_in = vec![0u8; 16];
        sockaddr_in[0] = 16;
        sockaddr_in[1] = AF_INET as u8;
        sockaddr_in[4..8].copy_from_slice(&ip.octets());
        message.extend_from_slice(&sockaddr_in);

        let mut sockaddr_dl = vec![0u8; 20];
        sockaddr_dl[0] = 20;
        sockaddr_dl[1] = 18; // AF_LINK
        sockaddr_dl[5] = 0; // no interface name in sdl_data
        sockaddr_dl[6] = mac.map(|_| 6).unwrap_or(0);
        if let Some(bytes) = mac {
            sockaddr_dl[8..14].copy_from_slice(&bytes);
        }
        message.extend_from_slice(&sockaddr_dl);

        let length = message.len() as u16;
        message[0..2].copy_from_slice(&length.to_ne_bytes());
        message
    }

    #[test]
    fn reads_an_address_and_its_hardware_address() {
        let table = arp_record(Ipv4Addr::new(192, 168, 2, 60), Some([0x4a, 0x9d, 0x33, 0x90, 0x91, 0x4f]), 4);
        let parsed = parse_table(&table);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].0, Ipv4Addr::new(192, 168, 2, 60));
        assert_eq!(parsed[0].1, Some([0x4a, 0x9d, 0x33, 0x90, 0x91, 0x4f]));
    }

    #[test]
    fn an_unresolved_entry_keeps_its_address() {
        // `arp -a` shows these as "(incomplete)"; dropping them would hide a
        // device that is being asked about but not answering.
        let table = arp_record(Ipv4Addr::new(192, 168, 2, 32), None, 4);
        let parsed = parse_table(&table);
        assert_eq!(parsed[0].0, Ipv4Addr::new(192, 168, 2, 32));
        assert_eq!(parsed[0].1, None);
    }

    #[test]
    fn walks_past_the_first_record() {
        let mut table = arp_record(Ipv4Addr::new(10, 0, 0, 1), Some([0xbc, 0x45, 0x29, 1, 2, 3]), 1);
        table.extend(arp_record(Ipv4Addr::new(10, 0, 0, 2), Some([0xbc, 0x45, 0x29, 4, 5, 6]), 1));
        assert_eq!(parse_table(&table).len(), 2);
    }

    #[test]
    fn survives_a_truncated_table() {
        let mut table = arp_record(Ipv4Addr::new(10, 0, 0, 1), Some([1, 2, 3, 4, 5, 6]), 1);
        table.truncate(50);
        assert!(parse_table(&table).is_empty());
    }

    #[test]
    fn an_empty_table_yields_nothing() {
        assert!(parse_table(&[]).is_empty());
    }

    #[test]
    fn reading_the_live_table_never_panics() {
        let found = list(false);
        for entry in &found {
            assert!(entry.ip.parse::<Ipv4Addr>().is_ok());
            // Filtered out during collection.
            assert_ne!(entry.kind, NeighbourKind::Multicast);
            assert_ne!(entry.kind, NeighbourKind::Broadcast);
            // A manufacturer may only be attached to a real assigned address.
            if entry.vendor.is_some() {
                assert_eq!(entry.kind, NeighbourKind::Device);
            }
        }
    }
}
