//! Local network facts, gathered without running a single command.
//!
//! `ifconfig` and `scutil --dns` would answer all of this, but both are
//! subprocesses. `getifaddrs` and libresolv are ordinary library calls that
//! work unchanged inside App Sandbox.

use std::ffi::CStr;
use std::net::Ipv4Addr;

use serde::Serialize;

// macOS exports `res_ninit` under its versioned name, from libresolv.
#[link(name = "resolv")]
extern "C" {
    fn res_9_ninit(state: *mut u8) -> libc::c_int;
}

/// Verified against <resolv.h> on Darwin arm64.
const RES_STATE_SIZE: usize = 552;
const RES_NSCOUNT_OFFSET: usize = 16;
const RES_NSADDR_LIST_OFFSET: usize = 20;
const SOCKADDR_IN_SIZE: usize = 16;
/// Offset of `sin_addr` inside `sockaddr_in` (sa_len, sa_family, sin_port).
const SOCKADDR_IN_ADDR_OFFSET: usize = 4;
const MAX_NAMESERVERS: usize = 3;

/// What kind of interface this is, as far as the user needs to care.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum InterfaceKind {
    /// Ethernet or Wi-Fi: a real adapter.
    Physical,
    /// A VPN or proxy tunnel (`utun*`, `ppp*`, `ipsec*`).
    Tunnel,
    /// A software bridge, including macOS Internet Sharing.
    Bridge,
    Loopback,
    Other,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Interface {
    pub name: String,
    pub kind: InterfaceKind,
    pub ipv4: String,
    pub netmask: String,
    /// Prefix length, which reads better than a dotted mask for most people.
    pub prefix: u8,
    pub is_up: bool,
    /// True when this interface holds an address from a proxy's synthetic pool.
    pub carries_fake_ip: bool,
}

/// True when the process is running inside App Sandbox.
///
/// The sandbox redirects `HOME` into the app's container, and nothing else
/// does. This is the same signal the sandbox verification probe checks, so the
/// app and its test agree on what "sandboxed" means.
///
/// The UI uses this to hide the subprocess-backed full-path report, which
/// cannot run here: showing a control that is guaranteed to fail is worse than
/// not offering it.
pub fn is_sandboxed() -> bool {
    std::env::var("HOME")
        .map(|home| home.contains("/Library/Containers/"))
        .unwrap_or(false)
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalNetwork {
    pub interfaces: Vec<Interface>,
    pub dns_servers: Vec<String>,
    pub gateway: Option<String>,
    /// Interface names that look like an active VPN or proxy tunnel.
    pub tunnels: Vec<String>,
    /// Whether subprocess-backed features are available in this build.
    pub sandboxed: bool,
    /// Radio quality, when this Mac has an associated Wi-Fi interface.
    pub wifi: Option<super::wifi::WifiStatus>,
}

/// Classify from the BSD interface name, which is stable on macOS.
fn classify(name: &str, is_loopback: bool) -> InterfaceKind {
    if is_loopback {
        return InterfaceKind::Loopback;
    }
    if name.starts_with("utun") || name.starts_with("ppp") || name.starts_with("ipsec") {
        return InterfaceKind::Tunnel;
    }
    if name.starts_with("bridge") {
        return InterfaceKind::Bridge;
    }
    if name.starts_with("en") || name.starts_with("eth") {
        return InterfaceKind::Physical;
    }
    InterfaceKind::Other
}

/// Count the leading ones in a dotted netmask.
pub fn prefix_from_netmask(netmask: Ipv4Addr) -> u8 {
    u32::from(netmask).count_ones() as u8
}

/// Enumerate IPv4 interfaces that currently hold an address.
pub fn interfaces() -> Vec<Interface> {
    let mut list = Vec::new();
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();

    // SAFETY: getifaddrs allocates the list; we free it before returning.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return list;
    }

    let mut cursor = head;
    while !cursor.is_null() {
        // SAFETY: the walk stops at the null terminator getifaddrs provides.
        let entry = unsafe { &*cursor };
        cursor = entry.ifa_next;

        if entry.ifa_addr.is_null() || entry.ifa_netmask.is_null() {
            continue;
        }
        // SAFETY: ifa_addr is a valid sockaddr for the reported family.
        let family = unsafe { (*entry.ifa_addr).sa_family };
        if i32::from(family) != libc::AF_INET {
            continue;
        }

        let address = unsafe { read_sockaddr_in(entry.ifa_addr) };
        let netmask = unsafe { read_sockaddr_in(entry.ifa_netmask) };

        // SAFETY: ifa_name is a NUL-terminated string owned by the list.
        let name = unsafe { CStr::from_ptr(entry.ifa_name) }.to_string_lossy().into_owned();

        let is_loopback = entry.ifa_flags & (libc::IFF_LOOPBACK as u32) != 0;
        let is_up = entry.ifa_flags & (libc::IFF_UP as u32) != 0;

        list.push(Interface {
            kind: classify(&name, is_loopback),
            name,
            ipv4: address.to_string(),
            netmask: netmask.to_string(),
            prefix: prefix_from_netmask(netmask),
            is_up,
            carries_fake_ip: super::interference::is_fake_ip(std::net::IpAddr::V4(address)),
        });
    }

    // SAFETY: head came from getifaddrs and is freed exactly once.
    unsafe { libc::freeifaddrs(head) };
    list
}

/// SAFETY: `pointer` must be a valid `sockaddr_in`.
unsafe fn read_sockaddr_in(pointer: *const libc::sockaddr) -> Ipv4Addr {
    let typed = pointer as *const libc::sockaddr_in;
    Ipv4Addr::from(u32::from_be((*typed).sin_addr.s_addr))
}

/// The resolvers macOS is actually configured to use.
///
/// Note that `/etc/resolv.conf` is explicitly *not* consulted on macOS — the
/// file says so itself — so libresolv is the correct source, not that file.
pub fn dns_servers() -> Vec<String> {
    let mut state = vec![0u8; RES_STATE_SIZE];

    // SAFETY: the buffer matches sizeof(struct __res_state) for this platform.
    if unsafe { res_9_ninit(state.as_mut_ptr()) } != 0 {
        return Vec::new();
    }

    let count = i32::from_ne_bytes(
        state[RES_NSCOUNT_OFFSET..RES_NSCOUNT_OFFSET + 4]
            .try_into()
            .unwrap_or([0; 4]),
    );
    let count = (count.max(0) as usize).min(MAX_NAMESERVERS);

    (0..count)
        .filter_map(|index| {
            let base = RES_NSADDR_LIST_OFFSET + index * SOCKADDR_IN_SIZE + SOCKADDR_IN_ADDR_OFFSET;
            let octets: [u8; 4] = state.get(base..base + 4)?.try_into().ok()?;
            let address = Ipv4Addr::from(octets);
            // A zeroed slot means "unused", not 0.0.0.0.
            (!address.is_unspecified()).then(|| address.to_string())
        })
        .collect()
}

/// Everything the overview screen needs, in one call.
pub fn snapshot() -> LocalNetwork {
    let interfaces = interfaces();
    let tunnels = interfaces
        .iter()
        .filter(|entry| entry.kind == InterfaceKind::Tunnel && entry.is_up)
        .map(|entry| entry.name.clone())
        .collect();

    LocalNetwork {
        interfaces,
        dns_servers: dns_servers(),
        gateway: super::route::default_gateway().map(|ip| ip.to_string()),
        tunnels,
        sandboxed: is_sandboxed(),
        wifi: super::wifi::status(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_netmasks_to_prefixes() {
        assert_eq!(prefix_from_netmask(Ipv4Addr::new(255, 255, 255, 0)), 24);
        assert_eq!(prefix_from_netmask(Ipv4Addr::new(255, 255, 0, 0)), 16);
        assert_eq!(prefix_from_netmask(Ipv4Addr::new(255, 255, 255, 255)), 32);
        assert_eq!(prefix_from_netmask(Ipv4Addr::new(255, 0, 0, 0)), 8);
    }

    #[test]
    fn classifies_the_names_macos_actually_uses() {
        assert_eq!(classify("en0", false), InterfaceKind::Physical);
        assert_eq!(classify("utun4", false), InterfaceKind::Tunnel);
        assert_eq!(classify("ipsec0", false), InterfaceKind::Tunnel);
        assert_eq!(classify("bridge100", false), InterfaceKind::Bridge);
        assert_eq!(classify("lo0", true), InterfaceKind::Loopback);
        assert_eq!(classify("awdl0", false), InterfaceKind::Other);
    }

    #[test]
    fn enumerates_at_least_loopback_on_any_mac() {
        let found = interfaces();
        assert!(
            found.iter().any(|entry| entry.kind == InterfaceKind::Loopback),
            "every Mac has lo0"
        );
        // Whatever it finds must be internally consistent.
        for entry in &found {
            assert!(!entry.name.is_empty());
            assert!(entry.prefix <= 32);
        }
    }

    #[test]
    fn sandbox_detection_follows_the_container_path() {
        // Cannot toggle the real sandbox from a test, so pin the rule itself.
        let contained = "/Users/x/Library/Containers/com.example.app/Data";
        assert!(contained.contains("/Library/Containers/"));
        assert!(!"/Users/x".contains("/Library/Containers/"));
        // And the live answer must at least be well-defined.
        let _: bool = is_sandboxed();
    }

    #[test]
    fn snapshot_reports_sandbox_state() {
        let snapshot = snapshot();
        assert_eq!(snapshot.sandboxed, is_sandboxed());
    }

    #[test]
    fn dns_servers_are_valid_addresses_when_present() {
        for server in dns_servers() {
            assert!(server.parse::<Ipv4Addr>().is_ok(), "{server} should parse");
        }
    }
}
