# Governance Toolbox

LANPilot Audit 1.3.0 adds low-intensity, local-first governance observations.
Every real network observation remains behind the existing authorization
confirmation and fixed step allowlist.

| Feature | Data source | Active observation | Outputs |
| --- | --- | --- | --- |
| Enhanced asset inventory | ARP, reachability, existing service results | No additional probing | `asset-inventory.csv`, summary Markdown |
| Service exposure matrix | Existing common-service results | No additional probing | `service-exposure-matrix.csv`, summary Markdown |
| Local network configuration | Read-only macOS network commands | Local observation only | `local-network-config.json`, summary Markdown |
| Bonjour / mDNS observation | `dns-sd` for a fixed short duration | Passive announcement observation | `mdns-services.csv`, summary Markdown |
| Web and TLS baseline | Short requests to already-observed Web services | Low intensity | Web/TLS CSV files and summary Markdown |
| Snapshot comparison | Local historical outputs | No | Snapshot JSON and Markdown |
| Remediation tracking | Local governance metadata | No | Tracking CSV and JSON |
| Enhanced exports | Local report workspace | No | HTML, Excel, JSON, Markdown, CSV, and ZIP |

The toolbox does not accept arbitrary commands, log in to services, test
credentials, alter network or endpoint configuration, or automatically execute
remediation. Device categories are explicitly presented as guesses.
