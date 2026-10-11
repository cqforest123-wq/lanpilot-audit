use lanpilot_audit_app_lib::quick_check::{devices, mss};
use std::net::IpAddr;
fn main() {
    let target: IpAddr = std::env::args().nth(1).unwrap_or_else(|| "192.168.2.1".into()).parse().unwrap();
    let profile = match std::env::args().nth(2).as_deref() {
        Some("camera") => devices::DeviceProfile::Camera,
        Some("generic") => devices::DeviceProfile::Generic,
        _ => devices::DeviceProfile::Switch,
    };
    println!("=== {target} as {profile:?} ===");
    let report = devices::inspect(target, profile, |kind, port| println!("  probing {kind} {port}"));
    println!("\n--- ports ---");
    for p in &report.ports {
        println!("  {:>5} {:<10} {:?}", p.port, p.service.unwrap_or("-"), p.state);
    }
    if !report.rtsp.is_empty() {
        println!("--- rtsp ---");
        for r in &report.rtsp {
            println!("  {:>5} {:?} methods={:?} server={:?}", r.port, r.state, r.methods, r.server);
        }
    }
    println!("findings: {:?}", report.findings);

    println!("\n=== MSS ===");
    for (ip, port) in [("192.168.2.1", 80u16), ("1.1.1.1", 443)] {
        let c = mss::check(ip.parse().unwrap(), port);
        println!("  {}:{}  mss={:?} mtu={:?} {:?} {:?}", c.target, c.port, c.mss, c.implied_mtu, c.verdict, c.reasons);
    }
}
