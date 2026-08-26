//! Device-aware checks for the equipment on a small operational network.
//!
//! A generic port list answers "is something listening". On a camera network
//! the question is usually "is the *stream* alive", and an open 554 does not
//! answer it: the port stays open when the encoder has hung, when the disk is
//! full, and when the camera has rebooted into a recovery state. So RTSP is
//! spoken well enough to make the service prove itself.
//!
//! Nothing here logs in. `OPTIONS` is the one RTSP method defined to work
//! without authentication -- it asks the server which methods it supports --
//! and a `401` answer is a *success* for this purpose, because only a real RTSP
//! service replies that way. No credentials are sent, guessed, or stored.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use serde::Serialize;

use super::port::{self, PortResult};

const RTSP_TIMEOUT: Duration = Duration::from_millis(2500);
/// Enough for the status line and headers; the body is not read.
const RESPONSE_LIMIT: usize = 2048;

/// What kind of equipment the user is looking at, which decides the port set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum DeviceProfile {
    /// IP camera, NVR, or DVR.
    Camera,
    /// Managed switch, router, or access point.
    Switch,
    /// General-purpose host.
    Generic,
}

impl DeviceProfile {
    /// Ports worth testing for this kind of device, most telling first.
    pub fn ports(self) -> &'static [u16] {
        match self {
            // 8000 and 37777 are the vendor control channels on the two most
            // common Chinese NVR platforms; 34567 is the XMeye-family port.
            DeviceProfile::Camera => &[554, 80, 443, 8000, 8554, 37777, 34567],
            // 23 is included deliberately: finding Telnet open is the point.
            DeviceProfile::Switch => &[443, 80, 22, 23, 161],
            DeviceProfile::Generic => &[80, 443, 22, 445, 3389],
        }
    }

    /// Ports on which an RTSP conversation is worth attempting.
    pub fn rtsp_ports(self) -> &'static [u16] {
        match self {
            DeviceProfile::Camera => &[554, 8554],
            _ => &[],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum RtspState {
    /// Answered with a valid RTSP status line.
    Serving,
    /// Answered, and demands credentials. Still proof of a live RTSP service.
    NeedsCredentials,
    /// Something is listening but does not speak RTSP.
    NotRtsp,
    Unreachable,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RtspCheck {
    pub port: u16,
    pub state: RtspState,
    /// Methods the server advertises, when it says.
    pub methods: Vec<String>,
    /// Server banner, useful for identifying the model.
    pub server: Option<String>,
    pub elapsed_ms: f64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceReport {
    pub target: String,
    pub profile: DeviceProfile,
    pub ports: Vec<PortResult>,
    pub rtsp: Vec<RtspCheck>,
    /// Stable keys the UI turns into localized observations.
    pub findings: Vec<&'static str>,
}

/// Interpret an RTSP response's first line and headers.
pub fn parse_rtsp(response: &str) -> (RtspState, Vec<String>, Option<String>) {
    let mut lines = response.lines();
    let Some(status) = lines.next() else {
        return (RtspState::NotRtsp, Vec::new(), None);
    };
    if !status.starts_with("RTSP/") {
        return (RtspState::NotRtsp, Vec::new(), None);
    }

    let code = status.split_whitespace().nth(1).and_then(|value| value.parse::<u16>().ok());

    let mut methods = Vec::new();
    let mut server = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else { continue };
        match name.trim().to_ascii_lowercase().as_str() {
            "public" => {
                methods = value.split(',').map(|item| item.trim().to_string()).collect();
            }
            "server" => server = Some(value.trim().to_string()),
            _ => {}
        }
    }

    // 401 means a real RTSP service that wants credentials, which answers the
    // question being asked. It is not a failure and no login is attempted.
    let state = match code {
        Some(401) => RtspState::NeedsCredentials,
        Some(_) => RtspState::Serving,
        None => RtspState::NotRtsp,
    };
    (state, methods, server)
}

/// Ask one port whether it speaks RTSP.
pub fn probe_rtsp(address: IpAddr, port: u16) -> RtspCheck {
    let started = Instant::now();
    let elapsed = |started: Instant| (started.elapsed().as_secs_f64() * 100_000.0).round() / 100.0;

    let Ok(mut stream) =
        TcpStream::connect_timeout(&SocketAddr::new(address, port), RTSP_TIMEOUT)
    else {
        return RtspCheck {
            port,
            state: RtspState::Unreachable,
            methods: Vec::new(),
            server: None,
            elapsed_ms: elapsed(started),
        };
    };
    let _ = stream.set_read_timeout(Some(RTSP_TIMEOUT));
    let _ = stream.set_write_timeout(Some(RTSP_TIMEOUT));

    // The address is already validated; it is interpolated into a request line,
    // never a command line.
    let host = match address {
        IpAddr::V6(_) => format!("[{address}]"),
        IpAddr::V4(_) => address.to_string(),
    };
    let request = format!(
        "OPTIONS rtsp://{host}:{port}/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: LANPilot-QuickCheck\r\n\r\n"
    );

    if stream.write_all(request.as_bytes()).is_err() {
        return RtspCheck {
            port,
            state: RtspState::Unreachable,
            methods: Vec::new(),
            server: None,
            elapsed_ms: elapsed(started),
        };
    }

    let mut buffer = vec![0u8; RESPONSE_LIMIT];
    let read = stream.read(&mut buffer).unwrap_or(0);
    let response = String::from_utf8_lossy(&buffer[..read]);
    let (state, methods, server) = parse_rtsp(&response);

    RtspCheck { port, state, methods, server, elapsed_ms: elapsed(started) }
}

/// Run the profile's port set, then speak RTSP where it makes sense.
pub fn inspect(
    address: IpAddr,
    profile: DeviceProfile,
    mut on_progress: impl FnMut(&str, u16),
) -> DeviceReport {
    let mut ports = Vec::new();
    // Sequential, never concurrent: a burst of parallel connects is the shape
    // of a scanner, and this tool must not produce it.
    for &value in profile.ports() {
        on_progress("port", value);
        ports.push(port::check(address, value));
    }

    let mut rtsp = Vec::new();
    for &value in profile.rtsp_ports() {
        let open = ports.iter().any(|entry| entry.port == value && entry.state == port::PortState::Open);
        if !open {
            continue;
        }
        on_progress("rtsp", value);
        rtsp.push(probe_rtsp(address, value));
    }

    let findings = summarize(profile, &ports, &rtsp);
    DeviceReport { target: address.to_string(), profile, ports, rtsp, findings }
}

/// Turn the raw results into observations worth showing.
pub fn summarize(
    profile: DeviceProfile,
    ports: &[PortResult],
    rtsp: &[RtspCheck],
) -> Vec<&'static str> {
    let mut findings = Vec::new();
    let is_open = |port: u16| {
        ports.iter().any(|entry| entry.port == port && entry.state == port::PortState::Open)
    };
    let any_open = ports.iter().any(|entry| entry.state == port::PortState::Open);

    if !any_open {
        let all_filtered = ports.iter().all(|entry| entry.state == port::PortState::Filtered);
        findings.push(if all_filtered { "nothingAnswered" } else { "hostUpNoServices" });
        return findings;
    }

    if profile == DeviceProfile::Camera {
        let streaming = rtsp.iter().any(|entry| {
            matches!(entry.state, RtspState::Serving | RtspState::NeedsCredentials)
        });
        if is_open(554) || is_open(8554) {
            if streaming {
                findings.push("rtspAlive");
            } else {
                // The distinction the whole module exists for.
                findings.push("rtspPortOpenButSilent");
            }
        } else {
            findings.push("noRtspPort");
        }
        if is_open(80) && !is_open(443) {
            findings.push("webUiPlaintext");
        }
    }

    if profile == DeviceProfile::Switch {
        if is_open(23) {
            findings.push("telnetOpen");
        }
        if is_open(80) && !is_open(443) {
            findings.push("webUiPlaintext");
        }
        if is_open(443) || is_open(80) {
            findings.push("webUiAvailable");
        }
        if !is_open(22) && !is_open(23) && !is_open(80) && !is_open(443) {
            findings.push("noManagementInterface");
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quick_check::port::PortState;

    fn result(port: u16, state: PortState) -> PortResult {
        PortResult { port, state, elapsed_ms: 1.0, service: port::service_name(port) }
    }

    fn rtsp_check(port: u16, state: RtspState) -> RtspCheck {
        RtspCheck { port, state, methods: Vec::new(), server: None, elapsed_ms: 1.0 }
    }

    #[test]
    fn reads_a_normal_options_response() {
        let response = "RTSP/1.0 200 OK\r\nCSeq: 1\r\nPublic: DESCRIBE, SETUP, PLAY\r\nServer: Hipcam\r\n\r\n";
        let (state, methods, server) = parse_rtsp(response);
        assert_eq!(state, RtspState::Serving);
        assert_eq!(methods, vec!["DESCRIBE", "SETUP", "PLAY"]);
        assert_eq!(server.as_deref(), Some("Hipcam"));
    }

    #[test]
    fn a_401_proves_the_service_is_real() {
        // Wanting credentials is the strongest possible confirmation that the
        // thing on this port is a working RTSP server.
        let (state, _, _) = parse_rtsp("RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\n\r\n");
        assert_eq!(state, RtspState::NeedsCredentials);
    }

    #[test]
    fn a_web_server_on_the_rtsp_port_is_not_rtsp() {
        let (state, _, _) = parse_rtsp("HTTP/1.1 404 Not Found\r\n\r\n");
        assert_eq!(state, RtspState::NotRtsp);
    }

    #[test]
    fn an_empty_or_garbage_reply_is_not_rtsp() {
        assert_eq!(parse_rtsp("").0, RtspState::NotRtsp);
        assert_eq!(parse_rtsp("\u{0}\u{1}garbage").0, RtspState::NotRtsp);
    }

    #[test]
    fn an_open_but_silent_rtsp_port_is_the_finding_that_matters() {
        // Port open, service dead: the case a port scanner reports as healthy
        // and the operator experiences as a black screen.
        let findings = summarize(
            DeviceProfile::Camera,
            &[result(554, PortState::Open)],
            &[rtsp_check(554, RtspState::NotRtsp)],
        );
        assert!(findings.contains(&"rtspPortOpenButSilent"));
        assert!(!findings.contains(&"rtspAlive"));
    }

    #[test]
    fn a_camera_demanding_credentials_counts_as_alive() {
        let findings = summarize(
            DeviceProfile::Camera,
            &[result(554, PortState::Open)],
            &[rtsp_check(554, RtspState::NeedsCredentials)],
        );
        assert!(findings.contains(&"rtspAlive"));
    }

    #[test]
    fn plaintext_web_management_is_reported() {
        let findings = summarize(
            DeviceProfile::Switch,
            &[result(80, PortState::Open), result(443, PortState::Refused)],
            &[],
        );
        assert!(findings.contains(&"webUiPlaintext"));
        assert!(findings.contains(&"webUiAvailable"));
    }

    #[test]
    fn an_https_switch_is_not_flagged_for_plaintext() {
        let findings = summarize(
            DeviceProfile::Switch,
            &[result(443, PortState::Open), result(80, PortState::Open)],
            &[],
        );
        assert!(!findings.contains(&"webUiPlaintext"));
    }

    #[test]
    fn telnet_is_called_out() {
        let findings =
            summarize(DeviceProfile::Switch, &[result(23, PortState::Open)], &[]);
        assert!(findings.contains(&"telnetOpen"));
    }

    #[test]
    fn separates_a_silent_host_from_a_firewalled_one() {
        let filtered = summarize(
            DeviceProfile::Camera,
            &[result(554, PortState::Filtered), result(80, PortState::Filtered)],
            &[],
        );
        assert!(filtered.contains(&"nothingAnswered"));

        let refused = summarize(
            DeviceProfile::Camera,
            &[result(554, PortState::Refused), result(80, PortState::Refused)],
            &[],
        );
        assert!(refused.contains(&"hostUpNoServices"));
    }

    #[test]
    fn profiles_test_the_ports_their_devices_actually_use() {
        assert!(DeviceProfile::Camera.ports().contains(&554));
        assert!(DeviceProfile::Camera.ports().contains(&37777), "Dahua control channel");
        assert!(DeviceProfile::Switch.ports().contains(&23), "finding Telnet is the point");
        assert!(DeviceProfile::Switch.rtsp_ports().is_empty());
    }
}

/// Hand a device's management page to the default browser.
///
/// The URL is *built here* from a validated address and a port that was
/// observed open, never accepted as a string from the front end: that keeps an
/// arbitrary URL from being opened on the user's behalf. Only http and https
/// are constructed, and `NSWorkspace` is used rather than spawning `open`, so
/// the call works under App Sandbox.
#[cfg(target_os = "macos")]
pub fn open_management_page(address: IpAddr, port: u16) -> Result<(), String> {
    use objc2_app_kit::NSWorkspace;
    use objc2_foundation::{NSString, NSURL};

    let scheme = match port {
        443 | 8443 => "https",
        80 | 8080 | 8000 => "http",
        _ => return Err("unsupportedPort".to_string()),
    };
    let host = match address {
        IpAddr::V6(_) => format!("[{address}]"),
        IpAddr::V4(_) => address.to_string(),
    };
    // Default ports are omitted so the address bar reads the way people expect.
    let url = match (scheme, port) {
        ("https", 443) | ("http", 80) => format!("{scheme}://{host}/"),
        _ => format!("{scheme}://{host}:{port}/"),
    };

    let string = NSString::from_str(&url);
    let Some(target) = NSURL::URLWithString(&string) else {
        return Err("badUrl".to_string());
    };
    if NSWorkspace::sharedWorkspace().openURL(&target) {
        Ok(())
    } else {
        Err("openFailed".to_string())
    }
}

#[cfg(not(target_os = "macos"))]
pub fn open_management_page(_address: IpAddr, _port: u16) -> Result<(), String> {
    Err("unsupportedPlatform".to_string())
}

#[cfg(test)]
mod url_tests {
    use super::*;

    #[test]
    fn only_web_ports_are_openable() {
        // A stream or vendor control port must not become a URL.
        for port in [554, 37777, 22, 23, 161] {
            assert!(open_management_page("192.168.1.1".parse().unwrap(), port).is_err());
        }
    }
}
