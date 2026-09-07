# App Review Notes

## What this app is

LANPilot Audit is a local-first network diagnostic and LAN governance assistant
for macOS. It explains why a connection is failing or slow, and helps a small
business document the equipment on its own network.

Everything runs on the user's Mac. Nothing is uploaded.

## The App Store build spawns no subprocess

This is the point most likely to be asked about, so it is stated first.

The store build (`src-tauri/tauri.appstore.conf.json`) runs entirely in-process:

| Capability | Mechanism |
| --- | --- |
| ICMP echo | unprivileged `SOCK_DGRAM` / `IPPROTO_ICMP` socket |
| Routing and neighbour tables | `sysctl` |
| Network interfaces | `getifaddrs` |
| Configured resolvers | libresolv |
| Wi-Fi radio | CoreWLAN `CWWiFiClient` |
| TCP reachability | `TcpStream::connect_timeout` |
| DNS and NTP | ordinary UDP sockets |
| Opening a management page | `NSWorkspace` |

No helper tool, no setuid binary, no elevated privileges, and no `nmap`. The
bundled shell engine used by the Developer ID build is excluded from the store
bundle entirely; `Contents/Resources` holds only `icon.icns`.

## Entitlements

- `com.apple.security.app-sandbox`
- `com.apple.security.network.client`
- `com.apple.security.network.server`

The third is requested even though the app never listens for connections. ICMP
and DNS are connectionless, and App Sandbox treats their replies as inbound: without
this entitlement `sendto` fails with "Operation not permitted". This was verified
both ways — with `network.client` alone the ICMP socket still opens and only the
send fails. The app opens no listening socket, binds no service port, and accepts
no incoming connection.

## What it sends

Only probes, never user data:

- A small, fixed number of ICMP echo requests to one address the user types
- One TCP handshake per port, closed immediately; nothing is written to it
- Standard DNS queries to the resolvers macOS is already configured to use
- Two DNS queries to public resolvers that answer with the querying address,
  used to show the user their own external address. This is a DNS query, not an
  HTTP request: no headers, no user agent, no request body
- Standard NTP client requests to the same public time servers macOS uses

## What it never does

- No credential is sent, guessed, or stored. Where a service is asked to
  identify itself the method used is RTSP `OPTIONS`, which is defined to work
  without authentication; a `401` reply is recorded as a successful
  identification, not as a prompt to try a password.
- No configuration is changed. The system clock is read, never set. Firewall,
  routing, DNS, VLAN, and Wi-Fi settings are not modified.
- No port ranges are swept across hosts. Device checks use a fixed,
  per-device-kind port list, tested one port at a time, never concurrently.
- The Wi-Fi network name and BSSID are deliberately not requested, so no
  Location Services prompt appears and the app never learns the user's location.

## Device discovery, and the consent gate

One feature reaches addresses the user did not name: local device discovery
sends one echo request to each address on the subnet this Mac is attached to,
so the user can find the equipment on their own network. This is the same
local-network discovery offered by Fing, LanScan, and Net Analyzer on the Mac
App Store.

It is bounded and gated:

- The range is computed from the live interface address and netmask. The caller
  supplies no range, and anything larger than a /22 is refused.
- It runs only after the operator explicitly confirms, once per network, that
  the network is theirs to check. The confirmation is stored locally with a
  timestamp, shown in the UI, and can be withdrawn.
- It does not probe addresses outside the local subnet.

## Reviewing without running anything

The interface, saved reports, and the demo data set can be inspected without
starting any check. Real checks are user-initiated: the user types an address
and presses a button.

The whole-path report, which does run bundled local scripts, is hidden at
runtime in the sandboxed build because it cannot work there. It is not part of
the store submission.
