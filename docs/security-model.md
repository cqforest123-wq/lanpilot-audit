# Security Model

One rule governs this document: **the app must pass Apple review on its own
facts.** Everything below describes what the app does, so that a reviewer's
questions have answers. It is not a list of promises about what will never be
built — features are decided on their merits, and this file is updated to match
what shipped.

## Two builds

| | App Store | Full |
| --- | --- | --- |
| Config | `src-tauri/tauri.appstore.conf.json` | default `tauri.conf.json` |
| Distribution | Mac App Store | Developer ID, open source |
| Sandbox | on | off |
| Bundled script engine | excluded | included |
| `nmap` dependency | never | optional |

One codebase serves both. `netinfo::is_sandboxed()` detects the sandbox at
runtime by checking whether `HOME` was redirected into a container, and the UI
hides anything that cannot work there rather than offering a control that is
guaranteed to fail.

## What the App Store build does

Quick Check runs entirely in-process. It spawns no subprocess: ICMP uses the
unprivileged `SOCK_DGRAM`/`IPPROTO_ICMP` socket, the routing and neighbour
tables come from `sysctl`, interfaces from `getifaddrs`, resolvers from
libresolv, Wi-Fi from CoreWLAN's `CWWiFiClient`, and links open through
`NSWorkspace`.

Entitlements: `com.apple.security.app-sandbox`,
`com.apple.security.network.client`, and `com.apple.security.network.server`.
The last is required because ICMP and UDP are connectionless and the sandbox
treats their replies as inbound — the app opens no listening socket and accepts
no incoming connection. Verified both ways; see
[mac-app-store-readiness.md](mac-app-store-readiness.md).

Nothing is uploaded. The only traffic leaving the machine is the probes
themselves — echo requests, TCP handshakes, DNS and NTP queries — plus two DNS
queries to public resolvers that answer with the querying address.

## Input handling

The target address is the one user value that reaches network code. It is
parsed by `quick_check::target::parse_target` before anything else runs, and
that parser rejects by default: only an IP literal or an RFC 1123 host name is
accepted. Values beginning with `-` are refused, as are multicast, broadcast,
loopback, unspecified, and link-local addresses.

Probe counts, intervals, packet sizes, timeouts, and port lists are fixed in
the backend. The front end selects a named profile; it never supplies a port
list, a rate, or a URL. Management pages are opened from a URL built in the
backend from an already-validated address and a port observed open.

## Scope

Every tool but one acts on an address the user typed, so their intent is the
authorization. Device discovery is the exception: it sends a request to every
address on whatever segment this Mac is attached to, and that segment is not
always theirs — a hotel, a client site, a shared office.

So the sweep is gated on an explicit, per-network confirmation. The subnet is
read from the live interface and never supplied by the caller, so consent
cannot be recorded for a network the Mac is not on. Confirmations are stored in
the app's own data directory with a timestamp and an optional label, listed in
the UI, and revocable. A corrupt or unreadable store authorizes nothing rather
than failing open.

This is a consent record, not an access control — anyone can click yes. Its
purpose is that they had to, once, and that what they agreed to is written
down.

## Read-only by construction

The app reads network state and sends probes. It sets no configuration, writes
no system state, installs nothing, and requires no elevated privileges. It
sends no credentials and attempts no login: where a service is asked to
identify itself — RTSP `OPTIONS` — the method used is the one defined to work
without authentication, and a `401` reply is recorded as a successful
identification rather than a prompt to try a password.

Wi-Fi reads signal, noise, and rate only. The network name and BSSID are not
requested, so no Location Services prompt appears.

## Verification

`npm run sandbox:verify` builds a probe, signs it with the store entitlements,
confirms the sandbox actually engaged, and exercises every syscall the app
depends on. It is the check that caught the missing `network.server`
entitlement, which would otherwise have shipped an app whose ping could not
send.
