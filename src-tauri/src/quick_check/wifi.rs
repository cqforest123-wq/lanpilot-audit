//! Wi-Fi radio quality, read through CoreWLAN.
//!
//! Signal strength explains most of what the other tools measure but cannot
//! account for: a weak or noisy link produces exactly the jitter and sporadic
//! loss that make video stutter, while every wired metric looks fine.
//!
//! Only the radio numbers are read. Since macOS 14, the network *name* and BSSID
//! require Location Services authorization, which would put a location prompt in
//! front of a network tool that has no interest in where the user is. RSSI,
//! noise, and rate need no such permission, and they carry the diagnosis, so the
//! name is simply left out. CoreWLAN is used through `CWWiFiClient`, which is the
//! form Apple documents as sandbox-compatible.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SignalQuality {
    Excellent,
    Good,
    Fair,
    Weak,
    Unusable,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WifiStatus {
    pub interface: Option<String>,
    /// Received signal strength in dBm; closer to zero is stronger.
    pub rssi_dbm: Option<i32>,
    /// Background noise floor in dBm.
    pub noise_dbm: Option<i32>,
    /// Signal-to-noise ratio in dB, the number that actually predicts trouble.
    pub snr_db: Option<i32>,
    pub transmit_rate_mbps: Option<f64>,
    pub quality: Option<SignalQuality>,
}

/// Grade a link from signal and noise.
///
/// SNR is preferred when both are known: -60 dBm in a quiet room is a good
/// link, while the same -60 dBm beside a microwave is not, and RSSI alone
/// cannot tell those apart.
pub fn grade(rssi_dbm: Option<i32>, noise_dbm: Option<i32>) -> Option<SignalQuality> {
    let rssi = rssi_dbm?;
    // A zero RSSI means "no measurement", not a perfect signal.
    if rssi == 0 {
        return None;
    }

    if let Some(noise) = noise_dbm {
        if noise != 0 {
            let snr = rssi - noise;
            return Some(match snr {
                s if s >= 40 => SignalQuality::Excellent,
                s if s >= 25 => SignalQuality::Good,
                s if s >= 15 => SignalQuality::Fair,
                s if s >= 10 => SignalQuality::Weak,
                _ => SignalQuality::Unusable,
            });
        }
    }

    Some(match rssi {
        r if r >= -50 => SignalQuality::Excellent,
        r if r >= -60 => SignalQuality::Good,
        r if r >= -70 => SignalQuality::Fair,
        r if r >= -80 => SignalQuality::Weak,
        _ => SignalQuality::Unusable,
    })
}

/// Signal-to-noise ratio, when both halves were measured.
pub fn snr(rssi_dbm: Option<i32>, noise_dbm: Option<i32>) -> Option<i32> {
    match (rssi_dbm, noise_dbm) {
        (Some(rssi), Some(noise)) if rssi != 0 && noise != 0 => Some(rssi - noise),
        _ => None,
    }
}

/// Read the current Wi-Fi link, or `None` when there is no Wi-Fi interface.
#[cfg(target_os = "macos")]
pub fn status() -> Option<WifiStatus> {
    use objc2_core_wlan::CWWiFiClient;

    // SAFETY: CWWiFiClient vends the interface, which is the documented
    // sandbox-compatible entry point; every value read below is a plain scalar.
    unsafe {
        let client = CWWiFiClient::sharedWiFiClient();
        let interface = client.interface()?;

        let name = interface.interfaceName().map(|value| value.to_string());
        let rssi = interface.rssiValue() as i32;
        let noise = interface.noiseMeasurement() as i32;
        let rate = interface.transmitRate();

        // All-zero readings mean the radio is off or not associated.
        if rssi == 0 && noise == 0 && rate == 0.0 {
            return Some(WifiStatus {
                interface: name,
                rssi_dbm: None,
                noise_dbm: None,
                snr_db: None,
                transmit_rate_mbps: None,
                quality: None,
            });
        }

        let rssi_dbm = (rssi != 0).then_some(rssi);
        let noise_dbm = (noise != 0).then_some(noise);

        Some(WifiStatus {
            interface: name,
            rssi_dbm,
            noise_dbm,
            snr_db: snr(rssi_dbm, noise_dbm),
            transmit_rate_mbps: (rate > 0.0).then_some(rate),
            quality: grade(rssi_dbm, noise_dbm),
        })
    }
}

#[cfg(not(target_os = "macos"))]
pub fn status() -> Option<WifiStatus> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grades_from_snr_when_noise_is_known() {
        // Same RSSI, different noise floors, different verdicts.
        assert_eq!(grade(Some(-60), Some(-100)), Some(SignalQuality::Excellent));
        assert_eq!(grade(Some(-60), Some(-75)), Some(SignalQuality::Fair));
        assert_eq!(grade(Some(-60), Some(-65)), Some(SignalQuality::Unusable));
    }

    #[test]
    fn falls_back_to_rssi_without_a_noise_reading() {
        assert_eq!(grade(Some(-45), None), Some(SignalQuality::Excellent));
        assert_eq!(grade(Some(-65), None), Some(SignalQuality::Fair));
        assert_eq!(grade(Some(-85), None), Some(SignalQuality::Unusable));
    }

    #[test]
    fn treats_zero_as_no_measurement_not_a_perfect_signal() {
        assert_eq!(grade(Some(0), Some(-90)), None);
        assert_eq!(grade(None, Some(-90)), None);
        // A zero noise floor must not be read as a 60 dB ratio.
        assert_eq!(grade(Some(-60), Some(0)), Some(SignalQuality::Good));
    }

    #[test]
    fn computes_snr_only_from_two_real_readings() {
        assert_eq!(snr(Some(-55), Some(-92)), Some(37));
        assert_eq!(snr(Some(-55), None), None);
        assert_eq!(snr(Some(0), Some(-92)), None);
        assert_eq!(snr(Some(-55), Some(0)), None);
    }

    #[test]
    fn reading_the_radio_never_panics() {
        // Wired Macs and machines with the radio off must return cleanly.
        let _ = status();
    }
}
