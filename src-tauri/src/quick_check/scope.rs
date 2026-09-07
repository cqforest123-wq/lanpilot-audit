//! Which networks the operator has said they are entitled to assess.
//!
//! Every other tool acts on an address the user typed, so their intent is the
//! whole authorization. Sweeping is different: it sends packets to every
//! address on whatever segment this Mac happens to be attached to, and that
//! segment is not always theirs. Plugging into a hotel, a client site, or a
//! shared office and pressing a button should not silently probe a few hundred
//! machines belonging to somebody else.
//!
//! This is a consent record, not an access control. Anyone can click yes; the
//! point is that they had to, once per network, and that what they agreed to
//! is written down and can be revoked. The record is kept in the app's own
//! data directory rather than in the front end so it survives a reload and can
//! be listed and withdrawn.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Named after what it holds, so the file is self-explanatory if found.
const FILE_NAME: &str = "authorized-networks.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScopeRecord {
    /// Canonical CIDR, e.g. "192.168.2.0/24".
    pub subnet: String,
    /// ISO-8601 UTC, so a record is meaningful without the app.
    pub authorized_at: String,
    /// Whatever the operator called this network.
    pub note: Option<String>,
}

/// Reduce any host address in a subnet to the subnet itself.
///
/// Without this, authorizing from .224 and later sweeping from .10 would look
/// like two different networks and ask twice.
pub fn canonical_subnet(address: Ipv4Addr, prefix: u8) -> Option<String> {
    if prefix > 32 {
        return None;
    }
    let mask = u32::MAX.checked_shl(u32::from(32 - prefix)).unwrap_or(0);
    let network = Ipv4Addr::from(u32::from(address) & mask);
    Some(format!("{network}/{prefix}"))
}

fn store_path(data_dir: &Path) -> PathBuf {
    data_dir.join(FILE_NAME)
}

/// Read the authorized networks, treating any problem as "none authorized".
///
/// A corrupt or unreadable file must never be read as blanket permission.
pub fn read(data_dir: &Path) -> Vec<ScopeRecord> {
    std::fs::read_to_string(store_path(data_dir))
        .ok()
        .and_then(|body| serde_json::from_str::<Vec<ScopeRecord>>(&body).ok())
        .unwrap_or_default()
}

fn write(data_dir: &Path, records: &[ScopeRecord]) -> Result<(), String> {
    std::fs::create_dir_all(data_dir).map_err(|error| format!("scope:writeFailed:{error}"))?;
    let body = serde_json::to_string_pretty(records)
        .map_err(|error| format!("scope:encodeFailed:{error}"))?;
    std::fs::write(store_path(data_dir), body)
        .map_err(|error| format!("scope:writeFailed:{error}"))
}

/// True when this exact subnet has been authorized.
pub fn is_authorized(records: &[ScopeRecord], subnet: &str) -> bool {
    records.iter().any(|record| record.subnet == subnet)
}

/// Record consent for a subnet. Re-authorizing refreshes the timestamp rather
/// than adding a duplicate.
pub fn authorize(
    data_dir: &Path,
    subnet: &str,
    note: Option<String>,
    now: String,
) -> Result<Vec<ScopeRecord>, String> {
    if parse_cidr(subnet).is_none() {
        return Err("scope:badSubnet".to_string());
    }
    let mut records = read(data_dir);
    records.retain(|record| record.subnet != subnet);
    records.push(ScopeRecord {
        subnet: subnet.to_string(),
        authorized_at: now,
        note: note.filter(|value| !value.trim().is_empty()),
    });
    records.sort_by(|a, b| a.subnet.cmp(&b.subnet));
    write(data_dir, &records)?;
    Ok(records)
}

/// Withdraw consent for a subnet.
pub fn revoke(data_dir: &Path, subnet: &str) -> Result<Vec<ScopeRecord>, String> {
    let mut records = read(data_dir);
    records.retain(|record| record.subnet != subnet);
    write(data_dir, &records)?;
    Ok(records)
}

/// Validate a CIDR string, so a malformed value can never be stored and later
/// compared against a real subnet.
pub fn parse_cidr(value: &str) -> Option<(Ipv4Addr, u8)> {
    let (address, prefix) = value.split_once('/')?;
    let address: Ipv4Addr = address.parse().ok()?;
    let prefix: u8 = prefix.parse().ok()?;
    if prefix > 32 {
        return None;
    }
    // Must already be the network address, not a host inside it.
    if canonical_subnet(address, prefix)? != value {
        return None;
    }
    Some((address, prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("lanpilot-scope-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn any_host_in_a_subnet_names_the_same_network() {
        // Authorizing from one address and sweeping from another must not ask
        // for consent twice.
        assert_eq!(canonical_subnet(Ipv4Addr::new(192, 168, 2, 224), 24).as_deref(), Some("192.168.2.0/24"));
        assert_eq!(canonical_subnet(Ipv4Addr::new(192, 168, 2, 1), 24).as_deref(), Some("192.168.2.0/24"));
        assert_eq!(canonical_subnet(Ipv4Addr::new(10, 4, 9, 200), 16).as_deref(), Some("10.4.0.0/16"));
    }

    #[test]
    fn a_full_length_prefix_does_not_overflow_the_shift() {
        assert_eq!(canonical_subnet(Ipv4Addr::new(10, 0, 0, 5), 32).as_deref(), Some("10.0.0.5/32"));
        assert_eq!(canonical_subnet(Ipv4Addr::new(10, 0, 0, 5), 0).as_deref(), Some("0.0.0.0/0"));
        assert_eq!(canonical_subnet(Ipv4Addr::new(10, 0, 0, 5), 33), None);
    }

    #[test]
    fn rejects_a_cidr_that_is_a_host_rather_than_a_network() {
        // Storing "192.168.2.224/24" would never match a real sweep's subnet.
        assert!(parse_cidr("192.168.2.224/24").is_none());
        assert!(parse_cidr("192.168.2.0/24").is_some());
    }

    #[test]
    fn rejects_malformed_cidrs() {
        for value in ["", "192.168.2.0", "192.168.2.0/", "/24", "192.168.2.0/33", "not/24", "192.168.2.0/24/8"] {
            assert!(parse_cidr(value).is_none(), "{value} should be rejected");
        }
    }

    #[test]
    fn nothing_is_authorized_before_consent_is_given() {
        let dir = temp_dir("empty");
        assert!(read(&dir).is_empty());
        assert!(!is_authorized(&read(&dir), "192.168.2.0/24"));
    }

    #[test]
    fn consent_is_recorded_and_survives_a_reread() {
        let dir = temp_dir("record");
        authorize(&dir, "192.168.2.0/24", Some("office".into()), "2026-09-07T10:00:00Z".into())
            .expect("stored");
        let records = read(&dir);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].subnet, "192.168.2.0/24");
        assert_eq!(records[0].note.as_deref(), Some("office"));
        assert!(is_authorized(&records, "192.168.2.0/24"));
        assert!(!is_authorized(&records, "10.0.0.0/24"), "consent is per network");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn re_authorizing_refreshes_rather_than_duplicates() {
        let dir = temp_dir("refresh");
        authorize(&dir, "192.168.2.0/24", None, "2026-01-01T00:00:00Z".into()).unwrap();
        let records =
            authorize(&dir, "192.168.2.0/24", None, "2026-09-07T10:00:00Z".into()).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].authorized_at, "2026-09-07T10:00:00Z");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn consent_can_be_withdrawn() {
        let dir = temp_dir("revoke");
        authorize(&dir, "192.168.2.0/24", None, "2026-09-07T10:00:00Z".into()).unwrap();
        let records = revoke(&dir, "192.168.2.0/24").unwrap();
        assert!(records.is_empty());
        assert!(!is_authorized(&read(&dir), "192.168.2.0/24"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_malformed_subnet_is_never_stored() {
        let dir = temp_dir("bad");
        assert!(authorize(&dir, "192.168.2.224/24", None, "now".into()).is_err());
        assert!(read(&dir).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_corrupt_store_authorizes_nothing() {
        // Failing open here would turn a damaged file into blanket permission.
        let dir = temp_dir("corrupt");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(store_path(&dir), "{ this is not json").unwrap();
        assert!(read(&dir).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_empty_note_is_dropped_rather_than_stored_blank() {
        let dir = temp_dir("note");
        let records =
            authorize(&dir, "10.0.0.0/24", Some("   ".into()), "now".into()).unwrap();
        assert_eq!(records[0].note, None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
