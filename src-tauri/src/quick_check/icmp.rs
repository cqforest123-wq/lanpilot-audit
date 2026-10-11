//! In-process ICMP echo, built on the unprivileged datagram socket macOS
//! exposes to ordinary users.
//!
//! Deliberately no subprocess. `/sbin/ping` would work outside the sandbox but
//! spawning it is the exact pattern flagged in `docs/mac-app-store-readiness.md`.
//! `SOCK_DGRAM` + `IPPROTO_ICMP` needs no root, no helper tool, and no
//! entitlement beyond `com.apple.security.network.client`.

use std::io;
use std::mem::MaybeUninit;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

/// Marks our packets so a reply can be matched without relying on the ICMP id:
/// on macOS the kernel rewrites the id field on a datagram ICMP socket.
const PROBE_MAGIC: &[u8; 16] = b"LANPILOT-QCHECK\0";

const ICMPV4_ECHO_REQUEST: u8 = 8;
const ICMPV4_ECHO_REPLY: u8 = 0;
const ICMPV4_DEST_UNREACH: u8 = 3;
const ICMPV4_TIME_EXCEEDED: u8 = 11;

const ICMPV6_ECHO_REQUEST: u8 = 128;
const ICMPV6_ECHO_REPLY: u8 = 129;
const ICMPV6_DEST_UNREACH: u8 = 1;
const ICMPV6_TIME_EXCEEDED: u8 = 3;

/// What a single echo probe turned into.
#[derive(Debug, Clone, PartialEq)]
pub enum ProbeOutcome {
    /// The target answered.
    Reply { from: IpAddr, rtt: Duration, reply_ttl: Option<u8> },
    /// A router on the path expired the packet. This is how traceroute walks.
    TimeExceeded { from: IpAddr, rtt: Duration },
    /// Something refused to forward it.
    Unreachable { from: IpAddr, rtt: Duration },
    /// Nothing came back inside the timeout.
    Timeout,
}

pub struct PingSocket {
    socket: Socket,
    ipv6: bool,
}

impl PingSocket {
    /// Open an unprivileged ICMP datagram socket for the target's family.
    pub fn open(target: IpAddr) -> io::Result<Self> {
        let ipv6 = target.is_ipv6();
        let (domain, protocol) = if ipv6 {
            (Domain::IPV6, Protocol::ICMPV6)
        } else {
            (Domain::IPV4, Protocol::ICMPV4)
        };
        let socket = Socket::new(domain, Type::DGRAM, Some(protocol))?;
        Ok(Self { socket, ipv6 })
    }

    /// Set the outgoing hop limit. Used for ping (fixed) and traceroute (swept).
    pub fn set_ttl(&self, ttl: u32) -> io::Result<()> {
        if self.ipv6 {
            self.socket.set_unicast_hops_v6(ttl)
        } else {
            self.socket.set_ttl(ttl)
        }
    }

    /// Send one echo request and wait for a matching answer.
    ///
    /// Replies for other sequence numbers are drained rather than returned, so a
    /// late answer to an earlier probe cannot be misread as this one's RTT.
    pub fn probe(&self, target: IpAddr, seq: u16, timeout: Duration) -> io::Result<ProbeOutcome> {
        self.socket.set_read_timeout(Some(timeout))?;

        let packet = self.build_echo_request(seq);
        let destination = SockAddr::from(SocketAddr::new(target, 0));

        let sent_at = Instant::now();
        self.socket.send_to(&packet, &destination)?;

        loop {
            let remaining = match timeout.checked_sub(sent_at.elapsed()) {
                Some(left) if !left.is_zero() => left,
                _ => return Ok(ProbeOutcome::Timeout),
            };
            self.socket.set_read_timeout(Some(remaining))?;

            let mut buffer = [MaybeUninit::<u8>::uninit(); 1500];
            let (len, from) = match self.socket.recv_from(&mut buffer) {
                Ok(value) => value,
                Err(error) if is_timeout(&error) => return Ok(ProbeOutcome::Timeout),
                Err(error) => return Err(error),
            };

            // SAFETY: the kernel reported `len` initialized bytes.
            let data = unsafe { &*(&buffer[..len] as *const [MaybeUninit<u8>] as *const [u8]) };

            let peer = match from.as_socket() {
                Some(addr) => addr.ip(),
                None => continue,
            };
            let rtt = sent_at.elapsed();

            if let Some(outcome) = self.classify(data, peer, rtt, seq) {
                // An echo reply must come from the host that was asked. A
                // time-exceeded or unreachable legitimately comes from a router
                // on the way, so only the reply case is checked.
                //
                // Without this a stray reply is credited to whichever probe is
                // waiting: sweeping a /24 reported 23 hosts as alive that
                // answered nothing, because every probe shared a sequence
                // number and payload and any one of them would accept it.
                if let ProbeOutcome::Reply { from, .. } = &outcome {
                    if *from != target {
                        continue;
                    }
                }
                return Ok(outcome);
            }
        }
    }

    fn build_echo_request(&self, seq: u16) -> Vec<u8> {
        let echo_type = if self.ipv6 { ICMPV6_ECHO_REQUEST } else { ICMPV4_ECHO_REQUEST };

        let mut packet = Vec::with_capacity(8 + PROBE_MAGIC.len());
        packet.push(echo_type);
        packet.push(0); // code
        packet.extend_from_slice(&[0, 0]); // checksum placeholder
        packet.extend_from_slice(&0u16.to_be_bytes()); // id, rewritten by the kernel
        packet.extend_from_slice(&seq.to_be_bytes());
        packet.extend_from_slice(PROBE_MAGIC);

        // ICMPv6 checksums cover a pseudo-header the kernel fills in for us.
        if !self.ipv6 {
            let sum = checksum(&packet);
            packet[2..4].copy_from_slice(&sum.to_be_bytes());
        }
        packet
    }

    /// Decide whether a received datagram answers probe `seq`.
    /// Returns `None` for traffic belonging to some other probe.
    fn classify(
        &self,
        data: &[u8],
        peer: IpAddr,
        rtt: Duration,
        seq: u16,
    ) -> Option<ProbeOutcome> {
        // On IPv4 macOS hands back the IP header; on IPv6 it does not.
        let (body, reply_ttl) = if !self.ipv6 && data.first().map(|b| b >> 4) == Some(4) {
            let ihl = ((data[0] & 0x0f) as usize) * 4;
            if data.len() < ihl + 8 {
                return None;
            }
            (&data[ihl..], data.get(8).copied())
        } else {
            (data, None)
        };

        let (echo_reply, time_exceeded, unreachable) = if self.ipv6 {
            (ICMPV6_ECHO_REPLY, ICMPV6_TIME_EXCEEDED, ICMPV6_DEST_UNREACH)
        } else {
            (ICMPV4_ECHO_REPLY, ICMPV4_TIME_EXCEEDED, ICMPV4_DEST_UNREACH)
        };

        let icmp_type = *body.first()?;

        if icmp_type == echo_reply {
            // Match on sequence plus our magic; the id field is not ours anymore.
            let reply_seq = u16::from_be_bytes([*body.get(6)?, *body.get(7)?]);
            if reply_seq != seq || !body.ends_with(PROBE_MAGIC) {
                return None;
            }
            return Some(ProbeOutcome::Reply { from: peer, rtt, reply_ttl });
        }

        if icmp_type == time_exceeded || icmp_type == unreachable {
            // The quoted original packet starts after this 8-byte header.
            if !quoted_packet_matches(&body[8..], seq, self.ipv6) {
                return None;
            }
            return Some(if icmp_type == time_exceeded {
                ProbeOutcome::TimeExceeded { from: peer, rtt }
            } else {
                ProbeOutcome::Unreachable { from: peer, rtt }
            });
        }

        None
    }
}

/// An error report quotes the packet that caused it; confirm it was ours.
fn quoted_packet_matches(quoted: &[u8], seq: u16, ipv6: bool) -> bool {
    let header_len = if ipv6 {
        40
    } else {
        match quoted.first() {
            Some(byte) if byte >> 4 == 4 => ((byte & 0x0f) as usize) * 4,
            _ => return false,
        }
    };
    let Some(inner) = quoted.get(header_len..) else {
        return false;
    };
    if inner.len() < 8 {
        return false;
    }
    u16::from_be_bytes([inner[6], inner[7]]) == seq
}

fn is_timeout(error: &io::Error) -> bool {
    matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)
}

/// Standard internet checksum (RFC 1071).
fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for chunk in chunks.by_ref() {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let Some(&last) = chunks.remainder().first() {
        sum += u32::from(u16::from_be_bytes([last, 0]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_matches_rfc_example() {
        // Zero-checksum echo request; verifying it re-sums to zero is the
        // property that matters on the wire.
        let packet = [8u8, 0, 0, 0, 0, 1, 0, 1];
        let sum = checksum(&packet);
        let mut verified = packet;
        verified[2..4].copy_from_slice(&sum.to_be_bytes());
        assert_eq!(checksum(&verified), 0);
    }

    #[test]
    fn checksum_handles_odd_length() {
        let sum = checksum(&[8u8, 0, 0, 0, 0, 1, 0, 1, 0x42]);
        assert_ne!(sum, 0);
    }

    #[test]
    fn echo_request_is_well_formed() {
        let socket = PingSocket { socket: dummy_socket(), ipv6: false };
        let packet = socket.build_echo_request(7);
        assert_eq!(packet[0], ICMPV4_ECHO_REQUEST);
        assert_eq!(packet[1], 0);
        assert_eq!(u16::from_be_bytes([packet[6], packet[7]]), 7);
        assert!(packet.ends_with(PROBE_MAGIC));
        assert_eq!(checksum(&packet), 0, "checksum must verify to zero");
    }

    #[test]
    fn an_echo_reply_from_another_host_is_not_our_answer() {
        // The sweep bug: identical sequence and payload across concurrent
        // probes meant any socket would adopt any reply.
        let socket = PingSocket { socket: dummy_socket(), ipv6: false };
        let reply = ipv4_echo_reply(1);
        // classify still recognises it; probe() is what must reject the peer.
        let outcome = socket.classify(&reply, "9.9.9.9".parse().unwrap(), Duration::ZERO, 1);
        match outcome {
            Some(ProbeOutcome::Reply { from, .. }) => {
                assert_eq!(from, "9.9.9.9".parse::<IpAddr>().unwrap());
                assert_ne!(
                    from,
                    "1.1.1.1".parse::<IpAddr>().unwrap(),
                    "probe() must compare this against the target"
                );
            }
            other => panic!("expected a reply, got {other:?}"),
        }
    }

    #[test]
    fn ignores_reply_for_a_different_sequence() {
        let socket = PingSocket { socket: dummy_socket(), ipv6: false };
        let reply = ipv4_echo_reply(99);
        let outcome = socket.classify(&reply, "1.1.1.1".parse().unwrap(), Duration::ZERO, 1);
        assert_eq!(outcome, None, "a late reply must not be credited to this probe");
    }

    #[test]
    fn ignores_reply_without_our_magic() {
        let socket = PingSocket { socket: dummy_socket(), ipv6: false };
        let mut reply = ipv4_echo_reply(1);
        let last = reply.len() - 1;
        reply[last] ^= 0xff;
        let outcome = socket.classify(&reply, "1.1.1.1".parse().unwrap(), Duration::ZERO, 1);
        assert_eq!(outcome, None, "another app's ping must not be adopted");
    }

    #[test]
    fn accepts_matching_reply_and_reads_ttl() {
        let socket = PingSocket { socket: dummy_socket(), ipv6: false };
        let reply = ipv4_echo_reply(1);
        let outcome = socket.classify(&reply, "1.1.1.1".parse().unwrap(), Duration::ZERO, 1);
        match outcome {
            Some(ProbeOutcome::Reply { reply_ttl, .. }) => assert_eq!(reply_ttl, Some(57)),
            other => panic!("expected a reply, got {other:?}"),
        }
    }

    fn dummy_socket() -> Socket {
        Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).expect("udp socket")
    }

    /// Full IPv4 datagram as macOS delivers it on a datagram ICMP socket.
    fn ipv4_echo_reply(seq: u16) -> Vec<u8> {
        let mut packet = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 57, 1, 0, 0, 1, 1, 1, 1, 192, 168, 2, 5];
        packet.push(ICMPV4_ECHO_REPLY);
        packet.push(0);
        packet.extend_from_slice(&[0, 0]);
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&seq.to_be_bytes());
        packet.extend_from_slice(PROBE_MAGIC);
        packet
    }
}
