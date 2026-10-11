use lanpilot_audit_app_lib::quick_check::netinfo;
fn main() {
    let snap = netinfo::snapshot();
    println!("gateway: {:?}", snap.gateway);
    println!("dns servers: {:?}", snap.dns_servers);
    println!("tunnels: {:?}", snap.tunnels);
    println!("\ninterfaces:");
    for i in &snap.interfaces {
        println!("  {:<10} {:<16}/{:<2} {:?}{}{}", i.name, i.ipv4, i.prefix, i.kind,
            if i.is_up { " UP" } else { "" },
            if i.carries_fake_ip { "  <-- FAKE-IP POOL" } else { "" });
    }
}
