use lanpilot_audit_app_lib::quick_check::{netinfo, sweep};
use std::time::Instant;
fn main() {
    let interfaces = netinfo::interfaces();
    let Some(active) = interfaces.iter().find(|i| i.kind == netinfo::InterfaceKind::Physical && i.is_up) else {
        println!("no active physical interface"); return;
    };
    println!("sweeping from {} {}/{}", active.name, active.ipv4, active.prefix);
    let ip = active.ipv4.parse().unwrap();
    let started = Instant::now();
    match sweep::run(ip, active.prefix, |done, total| {
        if done % 50 == 0 || done == total { println!("  {done}/{total}"); }
    }) {
        Ok(r) => {
            println!("\nsubnet {} — probed {} responded {} in {:.1}s",
                     r.subnet, r.probed, r.responded, started.elapsed().as_secs_f64());
            for h in &r.hosts {
                println!("  {:<16} {:<18} {:<10} {:<24} {}",
                    h.ip, h.mac.clone().unwrap_or_else(|| "-".into()),
                    format!("{:?}", h.kind), h.vendor.clone().unwrap_or_default(),
                    h.hostname.clone().unwrap_or_default());
            }
        }
        Err(e) => println!("refused: {e:?}"),
    }
}
