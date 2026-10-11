use lanpilot_audit_app_lib::quick_check::wifi;
fn main() {
    match wifi::status() {
        Some(s) => {
            println!("interface : {:?}", s.interface);
            println!("rssi      : {:?} dBm", s.rssi_dbm);
            println!("noise     : {:?} dBm", s.noise_dbm);
            println!("snr       : {:?} dB", s.snr_db);
            println!("tx rate   : {:?} Mbps", s.transmit_rate_mbps);
            println!("quality   : {:?}", s.quality);
        }
        None => println!("no Wi-Fi interface"),
    }
}
