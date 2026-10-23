//! Evidence-linked device profiles assembled from one completed local audit.

use std::collections::HashMap;

use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NetworkDevice {
    pub ip: String,
    pub mac: Option<String>,
    pub oui: Option<String>,
    pub vendor: Option<String>,
    pub locally_administered_mac: Option<bool>,
    pub ttl: Option<u8>,
    pub inferred_os: Option<String>,
    pub open_ports: Vec<OpenPortEvidence>,
    pub mdns_services: Vec<MdnsServiceEvidence>,
    pub netbios_name: Option<String>,
    pub tailscale_node: Option<TailscaleNodeEvidence>,
    /// Evidence completeness, not a probability that the identity is correct.
    pub confidence_score: u8,
    pub evidence_sources: Vec<String>,
    pub category_guess: Option<String>,
    pub risk_level: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OpenPortEvidence {
    pub port: String,
    pub protocol: Option<String>,
    pub service: Option<String>,
    pub version: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MdnsServiceEvidence {
    pub service_type: String,
    pub instance_name: String,
    pub hostname: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TailscaleNodeEvidence {
    pub hostname: String,
    pub operating_system: Option<String>,
    pub addresses: Vec<String>,
    pub online: Option<bool>,
}

fn rows(content: Option<&str>) -> Result<Vec<HashMap<String, String>>, String> {
    let Some(content) = content else {
        return Ok(Vec::new());
    };
    let mut reader = csv::Reader::from_reader(content.as_bytes());
    let headers = reader
        .headers()
        .map_err(|error| format!("Invalid device evidence CSV: {error}"))?
        .clone();
    reader
        .records()
        .map(|record| {
            let record = record.map_err(|error| format!("Invalid device evidence row: {error}"))?;
            Ok(headers
                .iter()
                .zip(record.iter())
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect())
        })
        .collect()
}

fn value<'a>(row: &'a HashMap<String, String>, key: &str) -> Option<&'a str> {
    row.get(key)
        .map(String::as_str)
        .filter(|value| !value.trim().is_empty())
}

fn ensure_device<'a>(
    devices: &'a mut HashMap<String, NetworkDevice>,
    ip: &str,
) -> &'a mut NetworkDevice {
    devices
        .entry(ip.to_string())
        .or_insert_with(|| NetworkDevice {
            ip: ip.to_string(),
            mac: None,
            oui: None,
            vendor: None,
            locally_administered_mac: None,
            ttl: None,
            inferred_os: None,
            open_ports: Vec::new(),
            mdns_services: Vec::new(),
            netbios_name: None,
            tailscale_node: None,
            confidence_score: 0,
            evidence_sources: Vec::new(),
            category_guess: None,
            risk_level: None,
        })
}

fn add_source(device: &mut NetworkDevice, source: &str) {
    if !device
        .evidence_sources
        .iter()
        .any(|current| current == source)
    {
        device.evidence_sources.push(source.to_string());
    }
}

fn mac_facts(mac: &str) -> (Option<String>, Option<bool>) {
    let octets = mac.split(':').map(str::trim).collect::<Vec<_>>();
    if octets.len() != 6
        || octets.iter().any(|part| {
            !(1..=2).contains(&part.len()) || !part.chars().all(|c| c.is_ascii_hexdigit())
        })
    {
        return (None, None);
    }
    let normalized = octets
        .iter()
        .map(|part| format!("{:02X}", u8::from_str_radix(part, 16).unwrap_or(0)))
        .collect::<Vec<_>>();
    let first = u8::from_str_radix(&normalized[0], 16).ok();
    let oui = Some(normalized[..3].join(":"));
    (oui, first.map(|byte| byte & 0x02 != 0))
}

fn normalize_mac(mac: &str) -> Option<String> {
    mac_facts(mac).0.as_ref()?;
    Some(
        mac.split(':')
            .map(|part| format!("{:02X}", u8::from_str_radix(part.trim(), 16).unwrap_or(0)))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

/// Correlate only exact IP evidence. mDNS hostnames are not guessed onto IPs;
/// callers may extend correlation when a trustworthy resolution is available.
pub fn build_network_devices(
    asset_inventory: Option<&str>,
    passive_assets: Option<&str>,
    reachable_ips: Option<&str>,
    open_ports: Option<&str>,
    mdns_services: Option<&str>,
) -> Result<Vec<NetworkDevice>, String> {
    let mut devices = HashMap::new();

    for row in rows(asset_inventory)? {
        let Some(ip) = value(&row, "ip") else {
            continue;
        };
        let device = ensure_device(&mut devices, ip);
        device.mac = value(&row, "mac")
            .and_then(normalize_mac)
            .or_else(|| device.mac.clone());
        device.vendor = value(&row, "vendor")
            .map(str::to_string)
            .or_else(|| device.vendor.clone());
        device.category_guess = value(&row, "device_category_guess").map(str::to_string);
        device.risk_level = value(&row, "risk_level").map(str::to_string);
        if let Some(mac) = device.mac.as_deref() {
            let (oui, local) = mac_facts(mac);
            device.oui = oui;
            device.locally_administered_mac = local;
        }
        add_source(device, "audit-asset-inventory");
    }

    for row in rows(passive_assets)? {
        let Some(ip) = value(&row, "ip") else {
            continue;
        };
        let device = ensure_device(&mut devices, ip);
        if let Some(mac) = value(&row, "mac") {
            device.mac = normalize_mac(mac).or_else(|| Some(mac.to_string()));
            let (oui, local) = mac_facts(mac);
            device.oui = oui;
            device.locally_administered_mac = local;
            add_source(device, "arp-neighbor-cache");
        }
    }

    if let Some(content) = reachable_ips {
        for ip in content.lines().map(str::trim).filter(|ip| !ip.is_empty()) {
            let device = ensure_device(&mut devices, ip);
            add_source(device, "single-icmp-reachability-check");
        }
    }

    for row in rows(open_ports)? {
        let (Some(ip), Some(port)) = (value(&row, "ip"), value(&row, "port")) else {
            continue;
        };
        let device = ensure_device(&mut devices, ip);
        if !device
            .open_ports
            .iter()
            .any(|entry| entry.port == port && entry.protocol.as_deref() == value(&row, "protocol"))
        {
            device.open_ports.push(OpenPortEvidence {
                port: port.to_string(),
                protocol: value(&row, "protocol").map(str::to_string),
                service: value(&row, "service").map(str::to_string),
                version: value(&row, "version").map(str::to_string),
            });
        }
        add_source(device, "low-intensity-service-check");
    }

    for row in rows(mdns_services)? {
        let Some(hostname) = value(&row, "hostname") else {
            continue;
        };
        let Some(ip) = hostname
            .parse::<std::net::IpAddr>()
            .ok()
            .map(|address| address.to_string())
        else {
            continue;
        };
        let device = ensure_device(&mut devices, &ip);
        device.mdns_services.push(MdnsServiceEvidence {
            service_type: value(&row, "service_type").unwrap_or_default().to_string(),
            instance_name: value(&row, "instance_name").unwrap_or_default().to_string(),
            hostname: Some(hostname.to_string()),
        });
        add_source(device, "bonjour-mdns-observation");
    }

    let mut output = devices
        .into_values()
        .map(|mut device| {
            device.open_ports.sort_by(|a, b| a.port.cmp(&b.port));
            device.evidence_sources.sort();
            device.confidence_score = (device.evidence_sources.len().min(4) * 25) as u8;
            device
        })
        .collect::<Vec<_>>();
    output.sort_by_key(|device| device.ip.parse::<std::net::IpAddr>().ok());
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn joins_only_matching_ip_evidence_and_marks_missing_facts_unknown() {
        let devices = build_network_devices(
            Some("ip,mac,vendor,device_category_guess,risk_level\n192.0.2.10,ea:40:e6:00:00:01,,Unknown,Low\n"),
            Some("ip,mac,interface,source\n192.0.2.10,ea:40:e6:00:00:01,en0,arp-cache\n"),
            Some("192.0.2.10\n"),
            Some("ip,port,protocol,state,service,version\n192.0.2.10,443,tcp,open,https,TLS\n"),
            Some("service_type,instance_name,hostname\n_ssh._tcp,Demo,192.0.2.10\n_ssh._tcp,Unmatched,device.local\n"),
        ).unwrap();
        assert_eq!(devices.len(), 1);
        let device = &devices[0];
        assert_eq!(device.oui.as_deref(), Some("EA:40:E6"));
        assert_eq!(device.locally_administered_mac, Some(true));
        assert_eq!(device.open_ports.len(), 1);
        assert_eq!(device.mdns_services.len(), 1);
        assert_eq!(device.confidence_score, 100);
        assert!(device.ttl.is_none());
        assert!(device.netbios_name.is_none());
        assert!(device.tailscale_node.is_none());
    }

    #[test]
    fn malformed_mac_does_not_create_a_manufacturer_prefix() {
        assert_eq!(
            mac_facts("0:e0:4c:0:0:1"),
            (Some("00:E0:4C".into()), Some(false))
        );
        assert_eq!(
            normalize_mac("0:e0:4c:0:0:1").as_deref(),
            Some("00:E0:4C:00:00:01")
        );
        assert_eq!(
            mac_facts("00:e0:4c:00:00:01"),
            (Some("00:E0:4C".into()), Some(false))
        );
    }
}
