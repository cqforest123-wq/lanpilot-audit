//! Live end-to-end Quick Check.
//! cargo run --manifest-path src-tauri/Cargo.toml --example quick_check_smoke -- <target>
use lanpilot_audit_app_lib::quick_check::runner;

fn main() {
    let target = std::env::args().nth(1).unwrap_or_else(|| "1.1.1.1".to_string());
    println!("=== Quick Check: {target} ===\n");

    match runner::run(&target, |event| {
        println!(
            "  [{}] {}/{}  {}",
            event.phase,
            event.sequence,
            event.total,
            match event.rtt_ms {
                Some(ms) => format!("{ms:.2} ms  from {}", event.from.unwrap_or_default()),
                None => "timeout".to_string(),
            }
        );
    }) {
        Ok(report) => {
            println!("\n--- REPORT ---");
            println!("target           : {}", report.target);
            println!("resolved         : {:?}", report.resolved_address);
            println!("dns              : {:?} ms", report.dns_ms);
            println!("gateway          : {:?}", report.gateway);
            println!("gateway min rtt  : {:?} ms", report.gateway_stats.as_ref().and_then(|s| s.min_ms));
            println!("loss             : {:.1}%", report.stats.loss_pct);
            println!("min/avg/max      : {:?}/{:?}/{:?} ms", report.stats.min_ms, report.stats.avg_ms, report.stats.max_ms);
            println!("jitter           : {:?} ms", report.stats.jitter_ms);
            println!("path verdict     : {:?}", report.interference.verdict);
            println!("path reasons     : {:?}", report.interference.reasons);
            println!("HEALTH           : {:?}", report.health);
            println!("findings         : {:?}", report.findings);
        }
        Err(error) => println!("ERROR: {error}"),
    }
}
