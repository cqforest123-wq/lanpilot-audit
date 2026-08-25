//! DNS lookups against a chosen resolver, so answers can be compared.
//!
//! The system resolver cannot be pointed at a specific server, and that is
//! exactly what is needed here: asking the configured resolver and a known
//! public one the same question, then comparing, is what exposes a hijacked or
//! synthesized answer. So the query is built and parsed here, over plain UDP.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use serde::Serialize;

const DNS_PORT: u16 = 53;
const QUERY_TIMEOUT: Duration = Duration::from_millis(2000);
const HEADER_LEN: usize = 12;
const TYPE_A: u16 = 1;
const TYPE_TXT: u16 = 16;
const CLASS_IN: u16 = 1;
/// Compression pointers set the top two bits of a length byte.
const POINTER_MASK: u8 = 0xC0;
/// Bounds the pointer chase so a malicious packet cannot loop forever.
const MAX_NAME_JUMPS: usize = 16;

/// The reference resolver. Comparing against it is the whole point, so it must
/// be one the user's own configuration cannot silently become.
pub const PUBLIC_RESOLVER: &str = "1.1.1.1";

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsAnswer {
    pub server: String,
    pub addresses: Vec<String>,
    pub elapsed_ms: Option<f64>,
    /// Stable failure key, or `None` when the query succeeded.
    pub error: Option<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum DnsVerdict {
    /// Both resolvers agree on at least one address.
    Consistent,
    /// The configured resolver returned a synthetic address.
    SyntheticAnswer,
    /// The two resolvers disagree completely.
    Divergent,
    /// The comparison could not be made.
    Inconclusive,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsDiagnosis {
    pub name: String,
    pub system: Vec<DnsAnswer>,
    pub public: DnsAnswer,
    pub verdict: DnsVerdict,
    pub reasons: Vec<&'static str>,
}

/// Encode a host name as a sequence of length-prefixed labels.
fn encode_name(name: &str) -> Option<Vec<u8>> {
    let mut encoded = Vec::new();
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        encoded.push(label.len() as u8);
        encoded.extend_from_slice(label.as_bytes());
    }
    encoded.push(0);
    Some(encoded)
}

/// Build a standard recursive A query.
pub fn build_query(name: &str, id: u16) -> Option<Vec<u8>> {
    build_typed_query(name, id, TYPE_A)
}

/// Build a recursive query for any record type.
pub fn build_typed_query(name: &str, id: u16, record_type: u16) -> Option<Vec<u8>> {
    let encoded = encode_name(name)?;
    let mut packet = Vec::with_capacity(HEADER_LEN + encoded.len() + 4);

    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&0x0100u16.to_be_bytes()); // standard query, recursion desired
    packet.extend_from_slice(&1u16.to_be_bytes()); // one question
    packet.extend_from_slice(&0u16.to_be_bytes()); // no answers
    packet.extend_from_slice(&0u16.to_be_bytes()); // no authority
    packet.extend_from_slice(&0u16.to_be_bytes()); // no additional
    packet.extend_from_slice(&encoded);
    packet.extend_from_slice(&record_type.to_be_bytes());
    packet.extend_from_slice(&CLASS_IN.to_be_bytes());

    Some(packet)
}

/// Step over a name, following compression pointers, and report the offset that
/// follows it in the packet.
fn skip_name(packet: &[u8], mut offset: usize) -> Option<usize> {
    let mut jumps = 0;
    let mut after_pointer = None;

    loop {
        let length = *packet.get(offset)?;

        if length & POINTER_MASK == POINTER_MASK {
            // A pointer ends this name; the caller resumes after its two bytes.
            if after_pointer.is_none() {
                after_pointer = Some(offset + 2);
            }
            jumps += 1;
            if jumps > MAX_NAME_JUMPS {
                return None;
            }
            let low = *packet.get(offset + 1)?;
            offset = (usize::from(length & !POINTER_MASK) << 8) | usize::from(low);
            continue;
        }

        offset += 1;
        if length == 0 {
            return Some(after_pointer.unwrap_or(offset));
        }
        offset += usize::from(length);
    }
}

/// Extract the A records from a response, ignoring everything else.
pub fn parse_answers(packet: &[u8], expected_id: u16) -> Option<Vec<Ipv4Addr>> {
    if packet.len() < HEADER_LEN {
        return None;
    }
    if u16::from_be_bytes([packet[0], packet[1]]) != expected_id {
        return None;
    }

    let questions = u16::from_be_bytes([packet[4], packet[5]]);
    let answers = u16::from_be_bytes([packet[6], packet[7]]);

    let mut offset = HEADER_LEN;
    for _ in 0..questions {
        offset = skip_name(packet, offset)?;
        offset += 4; // QTYPE and QCLASS
    }

    let mut addresses = Vec::new();
    for _ in 0..answers {
        offset = skip_name(packet, offset)?;
        let record_type = u16::from_be_bytes([*packet.get(offset)?, *packet.get(offset + 1)?]);
        let data_len =
            usize::from(u16::from_be_bytes([*packet.get(offset + 8)?, *packet.get(offset + 9)?]));
        offset += 10;

        if record_type == TYPE_A && data_len == 4 {
            let octets: [u8; 4] = packet.get(offset..offset + 4)?.try_into().ok()?;
            addresses.push(Ipv4Addr::from(octets));
        }
        offset += data_len;
    }

    Some(addresses)
}

/// Extract TXT strings from a response.
///
/// TXT data is one or more length-prefixed strings inside the record, which is
/// why it cannot reuse the fixed-width A-record path.
pub fn parse_txt_answers(packet: &[u8], expected_id: u16) -> Option<Vec<String>> {
    if packet.len() < HEADER_LEN {
        return None;
    }
    if u16::from_be_bytes([packet[0], packet[1]]) != expected_id {
        return None;
    }

    let questions = u16::from_be_bytes([packet[4], packet[5]]);
    let answers = u16::from_be_bytes([packet[6], packet[7]]);

    let mut offset = HEADER_LEN;
    for _ in 0..questions {
        offset = skip_name(packet, offset)?;
        offset += 4;
    }

    let mut strings = Vec::new();
    for _ in 0..answers {
        offset = skip_name(packet, offset)?;
        let record_type = u16::from_be_bytes([*packet.get(offset)?, *packet.get(offset + 1)?]);
        let data_len =
            usize::from(u16::from_be_bytes([*packet.get(offset + 8)?, *packet.get(offset + 9)?]));
        offset += 10;

        if record_type == TYPE_TXT {
            let end = offset + data_len;
            let mut cursor = offset;
            while cursor < end {
                let len = usize::from(*packet.get(cursor)?);
                cursor += 1;
                let chunk = packet.get(cursor..cursor + len)?;
                strings.push(String::from_utf8_lossy(chunk).into_owned());
                cursor += len;
            }
        }
        offset += data_len;
    }

    Some(strings)
}

/// Send a prepared query to a resolver and return the raw response.
pub fn exchange(server: Ipv4Addr, packet: &[u8]) -> Option<Vec<u8>> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.set_read_timeout(Some(QUERY_TIMEOUT)).ok()?;
    socket.send_to(packet, SocketAddr::new(IpAddr::V4(server), DNS_PORT)).ok()?;
    let mut buffer = [0u8; 1500];
    let (len, _) = socket.recv_from(&mut buffer).ok()?;
    Some(buffer[..len].to_vec())
}

/// Ask one resolver directly.
pub fn query(server: Ipv4Addr, name: &str) -> DnsAnswer {
    let label = server.to_string();
    let id = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.subsec_nanos())
        .unwrap_or(0)
        & 0xffff) as u16;

    let Some(packet) = build_query(name, id) else {
        return DnsAnswer { server: label, addresses: Vec::new(), elapsed_ms: None, error: Some("badName") };
    };

    let Ok(socket) = UdpSocket::bind("0.0.0.0:0") else {
        return DnsAnswer { server: label, addresses: Vec::new(), elapsed_ms: None, error: Some("socketFailed") };
    };
    let _ = socket.set_read_timeout(Some(QUERY_TIMEOUT));

    let destination = SocketAddr::new(IpAddr::V4(server), DNS_PORT);
    let started = Instant::now();
    if socket.send_to(&packet, destination).is_err() {
        return DnsAnswer { server: label, addresses: Vec::new(), elapsed_ms: None, error: Some("sendFailed") };
    }

    let mut buffer = [0u8; 1500];
    let Ok((len, _)) = socket.recv_from(&mut buffer) else {
        return DnsAnswer { server: label, addresses: Vec::new(), elapsed_ms: None, error: Some("timeout") };
    };
    let elapsed = (started.elapsed().as_secs_f64() * 100_000.0).round() / 100.0;

    match parse_answers(&buffer[..len], id) {
        Some(addresses) => DnsAnswer {
            server: label,
            addresses: addresses.iter().map(|ip| ip.to_string()).collect(),
            elapsed_ms: Some(elapsed),
            error: addresses.is_empty().then_some("noRecords"),
        },
        None => DnsAnswer { server: label, addresses: Vec::new(), elapsed_ms: Some(elapsed), error: Some("badResponse") },
    }
}

/// Compare what the configured resolvers say against a public one.
pub fn diagnose(name: &str, system_servers: &[Ipv4Addr]) -> DnsDiagnosis {
    let system: Vec<DnsAnswer> = system_servers.iter().map(|server| query(*server, name)).collect();
    let public = query(PUBLIC_RESOLVER.parse().unwrap_or(Ipv4Addr::new(1, 1, 1, 1)), name);

    let (verdict, reasons) = compare(&system, &public);
    DnsDiagnosis { name: name.to_string(), system, public, verdict, reasons }
}

/// Pure comparison, split out so every branch is testable without a network.
pub fn compare(system: &[DnsAnswer], public: &DnsAnswer) -> (DnsVerdict, Vec<&'static str>) {
    let mut reasons = Vec::new();

    let system_addresses: Vec<&String> =
        system.iter().flat_map(|answer| answer.addresses.iter()).collect();

    // A synthetic answer is decisive on its own and needs no comparison.
    let synthetic = system_addresses.iter().any(|address| {
        address
            .parse::<IpAddr>()
            .is_ok_and(super::interference::is_fake_ip)
    });
    if synthetic {
        reasons.push("systemReturnedFakeIp");
        return (DnsVerdict::SyntheticAnswer, reasons);
    }

    if system_addresses.is_empty() || public.addresses.is_empty() {
        reasons.push("comparisonUnavailable");
        return (DnsVerdict::Inconclusive, reasons);
    }

    let overlaps = system_addresses.iter().any(|address| public.addresses.contains(address));
    if overlaps {
        reasons.push("resolversAgree");
        return (DnsVerdict::Consistent, reasons);
    }

    // Large sites answer differently per resolver by design, so divergence is
    // reported as a fact to look at, never as proof of tampering.
    reasons.push("resolversDisagree");
    reasons.push("mayBeCdnNotTampering");
    (DnsVerdict::Divergent, reasons)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answer(server: &str, addresses: &[&str]) -> DnsAnswer {
        DnsAnswer {
            server: server.to_string(),
            addresses: addresses.iter().map(|value| value.to_string()).collect(),
            elapsed_ms: Some(5.0),
            error: None,
        }
    }

    #[test]
    fn builds_a_well_formed_query() {
        let packet = build_query("example.com", 0xABCD).expect("valid name");
        assert_eq!(&packet[0..2], &[0xAB, 0xCD]);
        assert_eq!(&packet[2..4], &[0x01, 0x00], "recursion desired");
        assert_eq!(&packet[4..6], &[0x00, 0x01], "one question");
        // 7example3com0
        assert_eq!(packet[12], 7);
        assert_eq!(&packet[13..20], b"example");
        assert_eq!(packet[20], 3);
        assert_eq!(&packet[21..24], b"com");
        assert_eq!(packet[24], 0);
        assert_eq!(&packet[25..29], &[0, 1, 0, 1], "A / IN");
    }

    #[test]
    fn rejects_malformed_names() {
        assert!(build_query("a..b", 1).is_none());
        assert!(build_query(&"a".repeat(64), 1).is_none());
    }

    /// Response with one compressed-name A record, as real servers send.
    fn response_with_a_record(id: u16, address: [u8; 4]) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.extend_from_slice(&id.to_be_bytes());
        packet.extend_from_slice(&0x8180u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&[7]);
        packet.extend_from_slice(b"example");
        packet.extend_from_slice(&[3]);
        packet.extend_from_slice(b"com");
        packet.push(0);
        packet.extend_from_slice(&TYPE_A.to_be_bytes());
        packet.extend_from_slice(&CLASS_IN.to_be_bytes());
        // Answer, with the name as a pointer back to offset 12.
        packet.extend_from_slice(&[0xC0, 0x0C]);
        packet.extend_from_slice(&TYPE_A.to_be_bytes());
        packet.extend_from_slice(&CLASS_IN.to_be_bytes());
        packet.extend_from_slice(&300u32.to_be_bytes());
        packet.extend_from_slice(&4u16.to_be_bytes());
        packet.extend_from_slice(&address);
        packet
    }

    #[test]
    fn parses_a_record_behind_a_compression_pointer() {
        let packet = response_with_a_record(0x1234, [93, 184, 216, 34]);
        let parsed = parse_answers(&packet, 0x1234).expect("parses");
        assert_eq!(parsed, vec![Ipv4Addr::new(93, 184, 216, 34)]);
    }

    #[test]
    fn rejects_a_response_with_the_wrong_id() {
        // Guards against an off-path forgery being accepted.
        let packet = response_with_a_record(0x1234, [1, 2, 3, 4]);
        assert_eq!(parse_answers(&packet, 0x9999), None);
    }

    #[test]
    fn survives_a_truncated_response() {
        let mut packet = response_with_a_record(0x1234, [1, 2, 3, 4]);
        packet.truncate(20);
        assert_eq!(parse_answers(&packet, 0x1234), None);
    }

    #[test]
    fn does_not_loop_on_a_self_referential_pointer() {
        // A pointer to itself would hang a naive parser.
        let mut packet = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0];
        packet.extend_from_slice(&[0xC0, 0x0C]);
        assert_eq!(parse_answers(&packet, 0x1234), None);
    }

    #[test]
    fn a_fake_ip_answer_is_decisive() {
        let (verdict, reasons) = compare(
            &[answer("1.0.0.1", &["198.18.16.6"])],
            &answer("1.1.1.1", &["17.253.144.10"]),
        );
        assert_eq!(verdict, DnsVerdict::SyntheticAnswer);
        assert!(reasons.contains(&"systemReturnedFakeIp"));
    }

    #[test]
    fn agreement_reads_as_consistent() {
        let (verdict, _) = compare(
            &[answer("192.168.1.1", &["93.184.216.34"])],
            &answer("1.1.1.1", &["93.184.216.34"]),
        );
        assert_eq!(verdict, DnsVerdict::Consistent);
    }

    #[test]
    fn divergence_is_reported_without_accusing() {
        let (verdict, reasons) = compare(
            &[answer("192.168.1.1", &["23.1.1.1"])],
            &answer("1.1.1.1", &["104.2.2.2"]),
        );
        assert_eq!(verdict, DnsVerdict::Divergent);
        // A CDN legitimately answers differently per resolver.
        assert!(reasons.contains(&"mayBeCdnNotTampering"));
    }

    #[test]
    fn missing_data_is_inconclusive_not_a_verdict() {
        let (verdict, _) = compare(&[answer("192.168.1.1", &[])], &answer("1.1.1.1", &["1.2.3.4"]));
        assert_eq!(verdict, DnsVerdict::Inconclusive);
    }
}
