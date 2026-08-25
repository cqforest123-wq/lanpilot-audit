//! TCP reachability for a single port.
//!
//! Answers the question ping cannot: "the host is up, but is the service
//! actually listening?" A completed handshake is the only honest proof, so the
//! connection is opened and immediately dropped. Nothing is sent, no banner is
//! read, and no protocol is spoken.

use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use serde::Serialize;

/// Long enough to cross a slow link, short enough that a filtered port does not
/// leave the user staring at a spinner.
const CONNECT_TIMEOUT: Duration = Duration::from_millis(2500);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PortState {
    /// The handshake completed: something is listening.
    Open,
    /// Actively refused, which still proves the host is alive.
    Refused,
    /// No response at all, the signature of a firewall dropping packets.
    Filtered,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PortResult {
    pub port: u16,
    pub state: PortState,
    pub elapsed_ms: f64,
    /// Well-known service name, so the result reads without a port chart.
    pub service: Option<&'static str>,
}

/// Labels for the ports people actually ask about on a small network.
pub fn service_name(port: u16) -> Option<&'static str> {
    Some(match port {
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        80 => "HTTP",
        139 | 445 => "SMB",
        143 => "IMAP",
        443 => "HTTPS",
        548 => "AFP",
        554 => "RTSP",
        587 => "SMTP",
        631 => "IPP",
        993 => "IMAPS",
        1883 => "MQTT",
        3306 => "MySQL",
        3389 => "RDP",
        5432 => "PostgreSQL",
        5900 => "VNC",
        6379 => "Redis",
        8000 | 8080 | 8081 => "HTTP alt",
        8443 => "HTTPS alt",
        8554 => "RTSP alt",
        9000 => "HTTP alt",
        _ => return None,
    })
}

/// Test one port. `state` distinguishes refused from filtered, which is the
/// difference between "wrong port" and "blocked by a firewall".
pub fn check(address: IpAddr, port: u16) -> PortResult {
    let target = SocketAddr::new(address, port);
    let started = Instant::now();
    let state = match TcpStream::connect_timeout(&target, CONNECT_TIMEOUT) {
        Ok(stream) => {
            // Close immediately; the handshake alone is the answer.
            drop(stream);
            PortState::Open
        }
        Err(error) if error.kind() == std::io::ErrorKind::TimedOut => PortState::Filtered,
        // A refusal is a real reply, so it is not "filtered".
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => PortState::Refused,
        Err(_) => PortState::Filtered,
    };

    PortResult {
        port,
        state,
        elapsed_ms: (started.elapsed().as_secs_f64() * 100_000.0).round() / 100.0,
        service: service_name(port),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_the_ports_people_ask_about() {
        assert_eq!(service_name(554), Some("RTSP"));
        assert_eq!(service_name(445), Some("SMB"));
        assert_eq!(service_name(22), Some("SSH"));
        assert_eq!(service_name(65000), None);
    }

    #[test]
    fn a_closed_local_port_is_refused_not_filtered() {
        // Loopback refuses instantly, which must not be reported as a firewall.
        let result = check("127.0.0.1".parse().unwrap(), 1);
        assert_eq!(result.state, PortState::Refused);
        assert!(result.elapsed_ms < 1000.0, "loopback refusal should be immediate");
    }

    #[test]
    fn reports_elapsed_time_for_every_outcome() {
        let result = check("127.0.0.1".parse().unwrap(), 1);
        assert!(result.elapsed_ms >= 0.0);
        assert_eq!(result.port, 1);
    }
}
