use lanpilot_audit_app_lib::quick_check::{dns, netinfo, port};
use std::net::Ipv4Addr;
fn main() {
    let servers: Vec<Ipv4Addr> = netinfo::dns_servers().iter().filter_map(|s| s.parse().ok()).collect();
    println!("=== DNS diagnosis: www.apple.com ===");
    println!("system resolvers: {servers:?}");
    let d = dns::diagnose("www.apple.com", &servers);
    for a in &d.system { println!("  system {} -> {:?} {:?}ms err={:?}", a.server, a.addresses, a.elapsed_ms, a.error); }
    println!("  public {} -> {:?} {:?}ms err={:?}", d.public.server, d.public.addresses, d.public.elapsed_ms, d.public.error);
    println!("  VERDICT: {:?}  reasons={:?}", d.verdict, d.reasons);

    println!("\n=== TCP ports on the gateway ===");
    let gw: std::net::IpAddr = "192.168.2.1".parse().unwrap();
    for p in [80u16, 443, 22, 554, 9999] {
        let r = port::check(gw, p);
        println!("  {:>5} {:<10} {:?} {:.1}ms", r.port, r.service.unwrap_or("-"), r.state, r.elapsed_ms);
    }
}
