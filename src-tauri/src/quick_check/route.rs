//! Default-gateway discovery without spawning a process.
//!
//! `/sbin/route -n get default` would answer this in one line, but executing a
//! binary is precisely what App Sandbox review objects to. The same information
//! comes from the kernel routing table via `sysctl`, which is an ordinary
//! syscall and needs no entitlement.

use std::net::{IpAddr, Ipv4Addr};

use libc::{c_int, sysctl, AF_INET, AF_ROUTE, CTL_NET, PF_ROUTE};

/// `net.route.0.inet.dump.0` — the whole IPv4 routing table.
const NET_RT_DUMP: c_int = 1;
/// Set in `rtm_flags` when a route names a gateway.
const RTF_GATEWAY: i32 = 0x2;
/// Set when the route is usable.
const RTF_UP: i32 = 0x1;
/// Bit 0 of `rtm_addrs`: a destination sockaddr is present.
const RTA_DST: i32 = 0x1;
/// Bit 1: a gateway sockaddr follows the destination.
const RTA_GATEWAY: i32 = 0x2;

/// Fetch the raw routing table from the kernel.
fn dump_routing_table() -> Option<Vec<u8>> {
    let mut mib: [c_int; 6] = [CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_DUMP, 0];
    let mut needed: usize = 0;

    // First call sizes the buffer, second call fills it.
    let sized = unsafe {
        sysctl(
            mib.as_mut_ptr(),
            mib.len() as u32,
            std::ptr::null_mut(),
            &mut needed,
            std::ptr::null_mut(),
            0,
        )
    };
    if sized != 0 || needed == 0 {
        return None;
    }

    let mut buffer = vec![0u8; needed];
    let filled = unsafe {
        sysctl(
            mib.as_mut_ptr(),
            mib.len() as u32,
            buffer.as_mut_ptr().cast(),
            &mut needed,
            std::ptr::null_mut(),
            0,
        )
    };
    if filled != 0 {
        return None;
    }
    buffer.truncate(needed);
    Some(buffer)
}

/// The IPv4 gateway for the default route, if there is one.
pub fn default_gateway() -> Option<IpAddr> {
    parse_default_gateway(&dump_routing_table()?)
}

/// Walk the `rt_msghdr` records looking for the default route's gateway.
///
/// Split from the syscall so it can be tested against a captured table.
pub fn parse_default_gateway(buffer: &[u8]) -> Option<IpAddr> {
    // struct rt_msghdr on Darwin: u_short rtm_msglen; u_char rtm_version;
    // u_char rtm_type; u_short rtm_index; ... int rtm_flags; int rtm_addrs;
    // Verified against <net/route.h> on Darwin arm64: rtm_index is followed by
    // two bytes of padding, so the int fields start at 8, not 12.
    const RTM_MSGLEN: usize = 0;
    const RTM_FLAGS: usize = 8;
    const RTM_ADDRS: usize = 12;
    const RT_MSGHDR_LEN: usize = 92;

    let mut offset = 0usize;

    while offset + RT_MSGHDR_LEN <= buffer.len() {
        let msglen =
            u16::from_ne_bytes([buffer[offset + RTM_MSGLEN], buffer[offset + RTM_MSGLEN + 1]])
                as usize;
        if msglen < RT_MSGHDR_LEN || offset + msglen > buffer.len() {
            break;
        }
        let message = &buffer[offset..offset + msglen];
        offset += msglen;

        let flags = i32::from_ne_bytes(message[RTM_FLAGS..RTM_FLAGS + 4].try_into().ok()?);
        let addrs = i32::from_ne_bytes(message[RTM_ADDRS..RTM_ADDRS + 4].try_into().ok()?);

        // Only an up route that names a gateway can be the default route.
        if flags & RTF_GATEWAY == 0 || flags & RTF_UP == 0 {
            continue;
        }
        if addrs & RTA_DST == 0 || addrs & RTA_GATEWAY == 0 {
            continue;
        }

        let mut cursor = RT_MSGHDR_LEN;

        // Destination must be 0.0.0.0 for this to be the *default* route.
        let (destination, destination_len) = read_sockaddr(message, cursor)?;
        if destination != Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)) {
            continue;
        }
        cursor += destination_len;

        let (gateway, _) = read_sockaddr(message, cursor)?;
        if let Some(ip @ IpAddr::V4(_)) = gateway {
            return Some(ip);
        }
    }

    None
}

/// Read one sockaddr and report how many bytes it occupies.
///
/// Entries are padded to 4-byte boundaries, and a zero `sa_len` still consumes
/// a full slot — getting this wrong desynchronizes the whole walk.
fn read_sockaddr(message: &[u8], offset: usize) -> Option<(Option<IpAddr>, usize)> {
    let sa_len = *message.get(offset)? as usize;
    let family = *message.get(offset + 1)? as c_int;

    let padded = if sa_len == 0 { 4 } else { (sa_len + 3) & !3 };

    if family == AF_INET && sa_len >= 8 {
        let octets = message.get(offset + 4..offset + 8)?;
        let ip = Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);
        return Some((Some(IpAddr::V4(ip)), padded));
    }

    // AF_LINK and other families appear in the table; skip them intact.
    let _ = AF_ROUTE;
    Some((None, padded))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build one `rt_msghdr` record with a destination and gateway sockaddr.
    fn route_message(flags: i32, destination: Ipv4Addr, gateway: Ipv4Addr) -> Vec<u8> {
        let mut message = vec![0u8; 92];
        message[8..12].copy_from_slice(&flags.to_ne_bytes());
        message[12..16].copy_from_slice(&(RTA_DST | RTA_GATEWAY).to_ne_bytes());

        for address in [destination, gateway] {
            let mut sockaddr = vec![0u8; 16];
            sockaddr[0] = 16; // sa_len
            sockaddr[1] = AF_INET as u8;
            sockaddr[4..8].copy_from_slice(&address.octets());
            message.extend_from_slice(&sockaddr);
        }

        let length = message.len() as u16;
        message[0..2].copy_from_slice(&length.to_ne_bytes());
        message
    }

    #[test]
    fn finds_the_default_gateway() {
        let table = route_message(
            RTF_UP | RTF_GATEWAY,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::new(192, 168, 2, 1),
        );
        assert_eq!(
            parse_default_gateway(&table),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1)))
        );
    }

    #[test]
    fn skips_non_default_routes() {
        let mut table = route_message(
            RTF_UP | RTF_GATEWAY,
            Ipv4Addr::new(10, 0, 0, 0),
            Ipv4Addr::new(10, 0, 0, 1),
        );
        table.extend(route_message(
            RTF_UP | RTF_GATEWAY,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::new(192, 168, 2, 1),
        ));
        assert_eq!(
            parse_default_gateway(&table),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1)))
        );
    }

    #[test]
    fn ignores_routes_that_are_down() {
        let table =
            route_message(RTF_GATEWAY, Ipv4Addr::UNSPECIFIED, Ipv4Addr::new(192, 168, 2, 1));
        assert_eq!(parse_default_gateway(&table), None);
    }

    #[test]
    fn survives_a_truncated_table() {
        let mut table = route_message(
            RTF_UP | RTF_GATEWAY,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::new(192, 168, 2, 1),
        );
        table.truncate(40);
        assert_eq!(parse_default_gateway(&table), None);
    }

    #[test]
    fn returns_nothing_for_an_empty_table() {
        assert_eq!(parse_default_gateway(&[]), None);
    }
}
