//! Proves, rather than assumes, that Quick Check works under App Sandbox.
//!
//! Sign this with `entitlements/appstore.entitlements` and run it. It first
//! establishes that the sandbox is actually enforcing (not merely declared),
//! then exercises every syscall Quick Check depends on.

use std::net::{IpAddr, TcpStream, SocketAddr, UdpSocket};
use std::time::Duration;

use lanpilot_audit_app_lib::quick_check::{dns, egress, icmp, netinfo, port, route, wifi};

fn line(label: &str, ok: bool, detail: String) {
    println!("  [{}] {:<34} {}", if ok { "PASS" } else { "FAIL" }, label, detail);
}

fn main() {
    println!("=== 0. Is the sandbox actually enforcing? ===");

    // The reliable indicator: App Sandbox redirects HOME into the app's
    // container. No entitlement or user consent affects this.
    let home = std::env::var("HOME").unwrap_or_default();
    let contained = home.contains("/Library/Containers/");
    line("HOME redirected to container", contained, home.clone());

    if !contained {
        println!("\n  !! Sandbox is not enforcing; results below prove nothing.\n");
    }

    println!("\n=== 1. Local network facts (getifaddrs / sysctl / libresolv) ===");
    let interfaces = netinfo::interfaces();
    line("getifaddrs", !interfaces.is_empty(), format!("{} interfaces", interfaces.len()));
    let gateway = route::default_gateway();
    line("sysctl route dump", gateway.is_some(), format!("{gateway:?}"));
    let servers = netinfo::dns_servers();
    line("libresolv res_ninit", !servers.is_empty(), format!("{servers:?}"));

    println!("\n=== 2. Unprivileged ICMP echo ===");
    let target: IpAddr = "1.1.1.1".parse().unwrap();
    match icmp::PingSocket::open(target) {
        Ok(socket) => {
            line("open SOCK_DGRAM/IPPROTO_ICMP", true, "socket created".into());
            let outcome = socket.probe(target, 1, Duration::from_millis(2000));
            let replied = matches!(outcome, Ok(icmp::ProbeOutcome::Reply { .. }));
            line("send + receive echo", replied, format!("{outcome:?}"));
        }
        Err(error) => line("open SOCK_DGRAM/IPPROTO_ICMP", false, format!("{error}")),
    }

    println!("\n=== 3. TCP connect ===");
    let result = port::check("1.1.1.1".parse().unwrap(), 443);
    line("TcpStream::connect_timeout", result.state == port::PortState::Open, format!("{result:?}"));
    let refused = TcpStream::connect_timeout(
        &SocketAddr::new("127.0.0.1".parse().unwrap(), 1), Duration::from_millis(500));
    line("loopback connect reaches stack", refused.is_err(), "refused as expected".into());

    println!("\n=== 4. UDP DNS query ===");
    let bound = UdpSocket::bind("0.0.0.0:0");
    line("bind ephemeral UDP", bound.is_ok(), format!("{:?}", bound.as_ref().map(|s| s.local_addr())));
    let answer = dns::query("1.1.1.1".parse().unwrap(), "example.com");
    line("query 1.1.1.1:53", answer.error.is_none(), format!("{:?} err={:?}", answer.addresses, answer.error));

    println!("\n=== 5. Wi-Fi radio (CoreWLAN) ===");
    match wifi::status() {
        Some(status) => {
            // A wired Mac legitimately has no readings; that is not a failure.
            let readable = status.rssi_dbm.is_some() || status.interface.is_some();
            line("CWWiFiClient interface", readable,
                 format!("{:?} rssi={:?} snr={:?} quality={:?}",
                         status.interface, status.rssi_dbm, status.snr_db, status.quality));
        }
        None => line("CWWiFiClient interface", true, "no Wi-Fi hardware (not a failure)".into()),
    }

    println!("\n=== 6. Public egress via DNS ===");
    let seen = egress::lookup();
    line("egress probes", seen.verdict != egress::EgressVerdict::Unknown,
         format!("{:?} primary={:?} secondary={:?}", seen.verdict, seen.primary, seen.secondary));

    println!("\n=== verdict ===");
    println!("  Sandbox enforcing : {}", if contained { "yes" } else { "NO" });
}
