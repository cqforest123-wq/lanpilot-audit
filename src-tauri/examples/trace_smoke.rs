use lanpilot_audit_app_lib::quick_check::traceroute;
fn main() {
    let target = std::env::args().nth(1).unwrap_or_else(|| "1.1.1.1".to_string());
    let ip: std::net::IpAddr = target.parse().expect("ip");
    println!("=== traceroute {ip} ===");
    match traceroute::run(ip, true, |hop| {
        println!("  {:>2}  {:<16} {:<40} {}", hop.ttl,
            hop.address.clone().unwrap_or_else(|| "*".into()),
            hop.hostname.clone().unwrap_or_default(),
            hop.rtt_ms.map(|r| format!("{r:.2} ms")).unwrap_or_default());
    }) {
        Ok(t) => println!("outcome: {:?}  hops: {}", t.outcome, t.hops.len()),
        Err(e) => println!("error: {e}"),
    }
}
