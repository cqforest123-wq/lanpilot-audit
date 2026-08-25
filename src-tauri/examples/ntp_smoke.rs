use lanpilot_audit_app_lib::quick_check::ntp;
fn main() {
    for server in ntp::SERVERS {
        let c = ntp::check(server);
        println!("{:<22} offset={:?} rtt={:?} +/-{:?}  {:?}  {:?}",
                 c.server, c.offset_ms, c.round_trip_ms, c.uncertainty_ms, c.verdict, c.reasons);
    }
    println!("\n--- best available ---");
    let b = ntp::best_available();
    println!("{:<22} offset={:?} rtt={:?} +/-{:?}  {:?}  {:?}",
             b.server, b.offset_ms, b.round_trip_ms, b.uncertainty_ms, b.verdict, b.reasons);
}
