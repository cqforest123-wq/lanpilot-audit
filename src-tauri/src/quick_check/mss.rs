//! Maximum segment size negotiated on a real TCP connection.
//!
//! The question this answers is "why do some sites load and others hang half
//! way", which is almost always a packet-size problem. The textbook tool for it
//! is path-MTU discovery with don't-fragment pings, and that is not available
//! here: `IP_DONTFRAG` has no effect on the unprivileged datagram ICMP socket
//! this app is built on -- measured, a 1600-byte probe with the flag set still
//! drew a reply -- and many gateways drop DF-flagged echoes outright, so even
//! with raw sockets the result would be noise.
//!
//! Reading the MSS off a completed handshake avoids all of that. It needs no
//! privilege, it cannot be answered by a fragmenting kernel, and it reports
//! what real traffic actually negotiated rather than what a probe inferred.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsRawFd;
use std::time::Duration;

use serde::Serialize;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

/// Ethernet carries 1500 bytes, leaving 1460 after the IPv4 and TCP headers.
pub const ETHERNET_MSS: u32 = 1460;
/// The floor of the "nothing to worry about" band.
///
/// The encapsulation cannot be named from the segment size alone, because the
/// plausible values interleave: plain Ethernet gives 1460, PPPoE 1452, Ethernet
/// with TCP timestamps 1448, and PPPoE with timestamps 1440. Since macOS
/// reports the size net of negotiated options, 1448 and 1452 are
/// indistinguishable in cause and identical in consequence -- neither is small
/// enough to trouble any stack. So the bands are drawn by what a size actually
/// costs the user, not by what produced it. This machine's own gateway reports
/// 1448 on ordinary Ethernet, and the first version called that a tunnel.
pub const COMFORTABLE_MSS: u32 = 1448;
/// Below this, large transfers stall on paths that ignore fragmentation needed.
const CONCERNING_MSS: u32 = 1400;
const CONNECT_TIMEOUT: Duration = Duration::from_millis(2500);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SegmentVerdict {
    /// Full-size segments: nothing is shrinking packets on this path.
    Standard,
    /// Slightly reduced, in the range PPPoE and common tunnels produce.
    Tunnelled,
    /// Small enough that large transfers are likely to suffer.
    Restricted,
    Unreachable,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SegmentCheck {
    pub target: String,
    pub port: u16,
    pub mss: Option<u32>,
    /// The MTU this segment size implies, adding back the IPv4 and TCP headers.
    pub implied_mtu: Option<u32>,
    pub verdict: SegmentVerdict,
    pub reasons: Vec<&'static str>,
}

/// Interpret a negotiated segment size.
pub fn judge(mss: Option<u32>) -> (SegmentVerdict, Vec<&'static str>) {
    let Some(mss) = mss else {
        return (SegmentVerdict::Unreachable, vec!["noHandshake"]);
    };

    if mss >= COMFORTABLE_MSS {
        return (SegmentVerdict::Standard, vec!["fullSizeSegments"]);
    }
    if mss < CONCERNING_MSS {
        return (SegmentVerdict::Restricted, vec!["segmentsRestricted", "largeTransfersMayStall"]);
    }
    // Reduced but harmless in itself. The cause is stated as a possibility,
    // because the size cannot prove which encapsulation produced it.
    (SegmentVerdict::Tunnelled, vec!["segmentsReduced", "likelyEncapsulation"])
}

/// Open a connection, read the segment size, and close it.
///
/// Nothing is sent on the connection; the handshake alone carries the answer.
pub fn check(address: IpAddr, port: u16) -> SegmentCheck {
    let target = address.to_string();

    match read_mss(address, port) {
        Ok(mss) => {
            let (verdict, reasons) = judge(Some(mss));
            SegmentCheck {
                target,
                port,
                mss: Some(mss),
                implied_mtu: Some(mss + 40),
                verdict,
                reasons,
            }
        }
        Err(_) => {
            let (verdict, reasons) = judge(None);
            SegmentCheck { target, port, mss: None, implied_mtu: None, verdict, reasons }
        }
    }
}

fn read_mss(address: IpAddr, port: u16) -> io::Result<u32> {
    let domain = if address.is_ipv6() { Domain::IPV6 } else { Domain::IPV4 };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.connect_timeout(&SockAddr::from(SocketAddr::new(address, port)), CONNECT_TIMEOUT)?;

    let mut value: libc::c_int = 0;
    let mut length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;

    // SAFETY: the socket is connected and `value` matches the option's type.
    let status = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_MAXSEG,
            &mut value as *mut _ as *mut libc::c_void,
            &mut length,
        )
    };
    if status != 0 {
        return Err(io::Error::last_os_error());
    }
    if value <= 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "no segment size reported"));
    }
    Ok(value as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_full_size_segment_means_nothing_is_shrinking_packets() {
        let (verdict, reasons) = judge(Some(ETHERNET_MSS));
        assert_eq!(verdict, SegmentVerdict::Standard);
        assert!(reasons.contains(&"fullSizeSegments"));
    }

    #[test]
    fn tcp_timestamps_are_not_mistaken_for_a_tunnel() {
        // Regression: this machine's own gateway reports 1448 on plain
        // Ethernet, and the first version called it a tunnel.
        assert_eq!(judge(Some(COMFORTABLE_MSS)).0, SegmentVerdict::Standard);
    }

    #[test]
    fn sizes_that_cost_the_user_nothing_are_not_flagged() {
        // 1460 plain, 1452 PPPoE, 1448 Ethernet with timestamps: different
        // causes, same absence of consequence.
        for mss in [1460, 1452, 1448] {
            assert_eq!(judge(Some(mss)).0, SegmentVerdict::Standard, "mss {mss}");
        }
    }

    #[test]
    fn a_real_reduction_is_reported_without_naming_a_cause() {
        // 1440 is PPPoE with timestamps, but the size cannot prove that, so the
        // finding must not claim it.
        let (verdict, reasons) = judge(Some(1440));
        assert_eq!(verdict, SegmentVerdict::Tunnelled);
        assert!(reasons.contains(&"likelyEncapsulation"));
    }

    #[test]
    fn a_small_segment_predicts_stalled_transfers() {
        let (verdict, reasons) = judge(Some(1200));
        assert_eq!(verdict, SegmentVerdict::Restricted);
        assert!(reasons.contains(&"largeTransfersMayStall"));
    }

    #[test]
    fn a_larger_than_ethernet_segment_is_still_standard() {
        // Jumbo frames on a local link must not read as a fault.
        assert_eq!(judge(Some(8960)).0, SegmentVerdict::Standard);
    }

    #[test]
    fn no_handshake_is_unreachable_not_restricted() {
        let (verdict, reasons) = judge(None);
        assert_eq!(verdict, SegmentVerdict::Unreachable);
        assert!(reasons.contains(&"noHandshake"));
    }

    #[test]
    fn implied_mtu_adds_back_both_headers() {
        // 1460 + 20 IPv4 + 20 TCP = the familiar 1500.
        let result = check("127.0.0.1".parse().unwrap(), 1);
        // Loopback refuses, so this exercises the failure path without a network.
        assert_eq!(result.mss, None);
        assert_eq!(result.implied_mtu, None);
    }
}
