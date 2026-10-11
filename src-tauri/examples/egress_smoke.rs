use lanpilot_audit_app_lib::quick_check::egress;
fn main() {
    let e = egress::lookup();
    println!("primary   : {:?}", e.primary);
    println!("secondary : {:?}", e.secondary);
    println!("verdict   : {:?}", e.verdict);
    println!("reasons   : {:?}", e.reasons);
}
