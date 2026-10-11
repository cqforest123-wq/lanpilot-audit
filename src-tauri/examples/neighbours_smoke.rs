use lanpilot_audit_app_lib::quick_check::neighbours;
fn main() {
    let found = neighbours::list(true);
    println!("{} neighbours\n", found.len());
    for n in &found {
        println!("  {:<16} {:<18} {:<11} {:<28} {}",
            n.ip,
            n.mac.clone().unwrap_or_else(|| "-".into()),
            format!("{:?}", n.kind),
            n.vendor.clone().unwrap_or_default(),
            n.hostname.clone().unwrap_or_default());
    }
}
