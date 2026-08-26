# Mac App Store Readiness

## Current Review Risks

- App Sandbox restrictions around local script execution. This applies to the
  governance audit engine, which runs bundled shell scripts. It does **not**
  apply to Quick Check.
- The separately installed `nmap` dependency.
- Explaining an authorized network-governance product during review.

## Quick Check Is Sandbox-Clean

Quick Check was built to be submittable on its own, and it clears the risk above
rather than arguing around it:

- No subprocess anywhere in the feature. ICMP echo uses an unprivileged
  datagram socket; the routing table comes from `sysctl`; interfaces come from
  `getifaddrs`; resolvers come from libresolv; TCP and DNS use ordinary sockets.
  Nothing is executed.
- No bundled engine, no `nmap`, no helper tool, no privileged operation.
- Requires `com.apple.security.network.client` and
  `com.apple.security.network.server` — see the verification below.
- Fixed probe count and interval; the user supplies a destination only.
- Functionally equivalent to Apple's own former Network Utility and to `ping`.

This makes Quick Check the natural core of the store variant below.

### Verified under App Sandbox, not assumed

Run `npm run sandbox:verify`. It builds a probe, wraps it in a bundle, signs it
ad-hoc with `entitlements/appstore.entitlements`, and runs it. The probe first
confirms the sandbox actually engaged — `HOME` is redirected into the app's
container — so a passing result cannot come from a sandbox that never started.

Measured on macOS (Darwin 25.5, Apple silicon), all sandboxed:

| Capability | Result |
| --- | --- |
| `getifaddrs` interface enumeration | works |
| `sysctl` routing-table dump | works |
| libresolv `res_ninit` resolver list | works |
| Unprivileged ICMP echo (send + reply) | works |
| `TcpStream::connect_timeout` | works |
| UDP bind and DNS query | works |
| CoreWLAN radio read (RSSI/noise/rate) | works, no Location prompt |
| Public egress lookup over DNS | works |
| NTP clock check over UDP/123 | works |
| Traceroute TTL sweep | works |
| TCP_MAXSEG segment size | works |
| Device profile sweep and RTSP OPTIONS | works |
| Opening a management page via NSWorkspace | works |

**The `network.server` entitlement is load-bearing.** With
`network.client` alone, the same probe fails:

| Capability | client only | client + server |
| --- | --- | --- |
| TCP connect | works | works |
| ICMP socket **open** | works | works |
| ICMP **send** | `EPERM` Operation not permitted | works |
| UDP bind | `EPERM` Operation not permitted | works |

Note that the ICMP socket still *opens* without the entitlement and only the
send fails. A check that merely creates the socket would pass and the shipped
app would be broken, so the verification exercises a full send-and-receive.

## Suggested Store Variant

A **LANPilot Audit Lite** variant should be built around Quick Check, plus
report viewing and low-intensity checks. It must not provide arbitrary
commands, install `nmap`, or bypass authorization. Because Quick Check spawns
nothing, Lite can ship with the sandbox on and the script engine excluded
entirely.

## Review Notes Draft

App is an authorized LAN governance audit assistant. It only runs fixed local
audit steps after explicit user confirmation. It does not perform exploit
activity, credential testing, brute force, unauthorized login, or
configuration changes. Audit evidence remains on the user's Mac.

The app requests `com.apple.security.network.server` even though it never
listens for connections. ICMP echo and DNS are connectionless protocols, and
App Sandbox treats their replies as inbound traffic; without this entitlement
`sendto` fails with "Operation not permitted". The app opens no listening
socket, binds no service port, and accepts no incoming connection.

Quick Check is a set of standard network diagnostics for one address the user
types, equivalent to the `ping`, `nc`, `dig`, and `ifconfig` commands macOS
already ships, presented in plain language for non-technical users.

It launches no process and requires no elevated privileges. It reads local
interface and resolver settings, sends a small fixed number of ICMP echo
requests, opens a single TCP handshake to a port the user names, and sends
standard DNS queries to the resolvers the system is already configured to use.

Wi-Fi signal strength is read through CoreWLAN's `CWWiFiClient`. The app reads
only the radio measurements — signal, noise, and rate — and deliberately does
not request the network name or BSSID, so it never triggers a Location Services
prompt and never learns the user's location.

The public-address feature uses two ordinary DNS queries to public resolvers
that answer with the querying address. It is not an HTTP request and sends no
user data.

Clock accuracy is checked with an ordinary NTP client request to the same public
time servers macOS uses. The app reads the system clock and never sets it. This
is included because a drifted clock presents as a network fault: certificates
appear invalid and two-factor codes are rejected.

Device checks test a fixed, per-device-kind list of ports one at a time. There
is no range syntax, no host sweep, and no concurrency. On camera profiles the
app sends RTSP `OPTIONS`, the method defined to work without authentication,
purely to confirm the streaming service is responding; an open port is not
proof that a camera is working. No credentials are ever sent or guessed, and a
401 response is recorded as a successful identification.

It does not scan address ranges, enumerate hosts, sweep ports, or test
credentials. Ports are tested one at a time and only when named or picked by the
user. Group and broadcast addresses are refused outright so that a single
request can never cause many devices to reply at once, and the monitoring
interval is clamped in the backend so it cannot be driven at a flood rate.

## Building the store variant

```sh
npm run app:build:appstore   # bundles with entitlements/appstore.entitlements
npm run sandbox:verify       # proves the sandboxed build can still measure
```

`src-tauri/tauri.appstore.conf.json` overlays the default config. It is a
separate configuration on purpose: the default Developer ID build must stay
un-sandboxed, because the governance audit engine runs bundled scripts.

Two details in that overlay are easy to get wrong:

- `"resources": null`, not `{}`. Tauri deep-merges configs, so an empty object
  leaves the base `resources` in place and the engine scripts ship anyway.
  Verified: the store bundle's `Contents/Resources` holds only `icon.icns`.
- Entitlements are embedded **at signing time**. A build with no signing
  identity produces an app with no entitlements and no sandbox, and nothing
  warns you. The overlay signs ad-hoc (`"signingIdentity": "-"`) so a local
  build is verifiable; a real submission overrides it with
  `APPLE_SIGNING_IDENTITY`.

The full-path report is hidden at runtime when `netinfo::is_sandboxed()` is
true, so the store build never shows a control that the sandbox would block.

Status of the sandboxed bundle as built today: three entitlements present,
engine scripts excluded, signature valid, app launches, container created, and
no sandbox denials in the system log.

## Naming

Checked against the Mac App Store in August 2026.

**Do not ship the name "Network Doctor."** There is a live Mac App Store app
called exactly that (id6789789507, macOS 14.6+, Apple silicon) occupying the
same category — guided latency, DNS, and reachability checks with findings and
next steps. It was previously this product's feature name and its tagline, which
would have put a competitor's app name in our own App Store metadata. All
occurrences were renamed to **Path Report** (`链路报告`), and the tagline now
comes from `workflow.ts`: "Local-first network governance and reliability
diagnostics".

Neighbouring names to keep clear of, all live on the store:

| Name | Note |
| --- | --- |
| Network Doctor | Direct collision, same category |
| Network Check | id6475325315 |
| NetCheck Connectivity | id1570703771 |
| Network Connection Monitor | id646106690; its own feature is called "Connection Doctor" |
| Network Utility / Network Kit X | networkutility.app, plus Apple's retired bundled tool |
| MacPilot | Koingo Software; establishes "…Pilot" in the Mac utility space |

**"LANPilot" itself returned no App Store conflict** and stays as the product
name. Note that "MacPilot" exists in the same utility category, so the LANPilot
name should stay visually and verbally distinct from it in listing assets.

One caution on the current app name, "LANPilot Audit": security-adjacent words
like *audit* and *scan* draw extra review attention. The review notes below are
written to answer that up front.

## Checklists

- Entitlements: sandbox, network client/server justification, file access.
- Privacy: local storage, no cloud upload, user-controlled export.
- Screenshots: authorization, engine setup, run status, report, export.
- Metadata: restrained governance language, supported languages, limitations.
