# Security Model

## Quick Check

Quick Check is the one feature that accepts a user-supplied value into network
code, so it is also the most tightly bounded.

- The target is the only user input that reaches the network layer. It is parsed
  by `quick_check::target::parse_target` before anything else runs, and that
  parser rejects by default: only an IP literal or an RFC 1123 host name is
  accepted.
- Values beginning with `-` are rejected. Quick Check never builds a command
  line, but the rule holds regardless so the shape can never become an argument.
- Multicast, broadcast, directed-broadcast, loopback, unspecified, and
  link-local addresses are refused. A single echo to a multicast or broadcast
  address would make every host on the segment reply at once; that is
  amplification, not diagnosis.
- **No subprocess is spawned.** Echo requests use an unprivileged
  `SOCK_DGRAM` / `IPPROTO_ICMP` socket and the gateway is read from the kernel
  routing table via `sysctl`. Quick Check needs no helper binary, no setuid
  tool, and no root.
- Two entitlements are required: `com.apple.security.network.client` **and**
  `com.apple.security.network.server`. The second is not because the app
  listens — it opens no listening socket and accepts no incoming connection.
  ICMP and UDP are connectionless, so the sandbox classifies the arriving echo
  reply and DNS response as inbound and denies the send without it. Verified
  both ways; see `docs/mac-app-store-readiness.md`.
- Probe count, interval, packet size, and timeout are fixed in the backend. The
  user chooses a destination, never a rate — an adjustable rate is what turns a
  diagnostic into a flood tool.
- Nothing is written or changed. Quick Check reads local network state and
  sends probes; it holds no files and alters no configuration. The only traffic
  leaving the machine is the probes themselves — echo requests, TCP handshakes,
  and DNS queries — never the user's data.

### Per-tool boundaries

- **Reachability** — ICMP echo only, via the unprivileged datagram socket.
- **Port** — a single TCP handshake per port, closed immediately. No data is
  sent, no banner is read, and no protocol is spoken. Ports are tested one at a
  time, never concurrently: a burst of simultaneous connects is the shape of a
  scanner, and this tool must not produce it. There is no range syntax and no
  host sweep; one host, one port at a time, each one typed or picked by the user.
- **DNS** — one standard A query per resolver over UDP/53, sent only to the
  resolvers macOS is already configured to use plus one fixed public reference.
  Responses are matched on the query ID before being read.
- **Route** — the same ICMP echo, sent with a deliberately small hop limit and
  raised one step at a time, capped at 30 hops. Hop names come from
  `getnameinfo`, which uses the system resolver and its cache rather than
  generating extra DNS traffic.
- **Clock** — one standard NTP client request per time server over UDP/123, to
  the same public servers macOS itself uses. Nothing is set or changed; the
  system clock is read, never written.
- **Monitor** — one echo per interval. The interval arrives from the front end
  and is therefore clamped in the backend to 500 ms–60 s, so a modified client
  cannot turn it into a flood. It runs until the user stops it.
- **Local network facts** — `getifaddrs` and libresolv, both ordinary library
  calls. Note that `/etc/resolv.conf` is deliberately not read: macOS states in
  that file that it is not consulted for resolution, so it would be a misleading
  source.
- **Wi-Fi radio** — CoreWLAN via `CWWiFiClient`, the form Apple documents as
  sandbox-compatible. Only RSSI, noise, and transmit rate are read. The network
  *name* and BSSID are deliberately not requested: since macOS 14 those require
  Location Services authorization, and a network tool has no business putting a
  location prompt in front of the user. The radio numbers carry the diagnosis on
  their own.
- **Public egress** — this is the one feature that contacts a third party. It
  resolves `o-o.myaddr.l.google.com` at 8.8.8.8 and `myip.opendns.com` at
  208.67.222.222, both of which answer with the querying address. It is a plain
  DNS query, not an HTTP request: no headers, no user agent, no request body,
  and nothing sent that a resolver would not already see. No audit data, host
  name, or local address is transmitted, and nothing is uploaded. Two probes are
  used because their disagreement is itself a finding.

## Remediation Assistant

The Remediation Assistant writes structured guidance only to fixed files under the latest local audit workspace. It cannot accept an output path or command, apply a configuration change, log in to a service, or start a retest without the existing authorization flow. See [remediation-assistant.md](remediation-assistant.md).

- Real audit execution requires a fresh, one-time authorization token.
- The backend accepts only fixed audit step enum values.
- The engine path is fixed under Application Support; development fallback is
  fixed and cannot be supplied by the user.
- All thirteen engine scripts are allowlisted and symbolic links are rejected.
- Governance observations use fixed commands, fixed paths, and bounded durations.
- Snapshot comparison and remediation tracking operate only on local files.
- Bundled and installed engine files must match the deterministic SHA-256
  integrity manifest before installation or audit execution.
- Integrity manifests reject absolute paths, parent-directory traversal,
  duplicate paths, missing files, modified files, symbolic links, and
  unlisted extra files.
- Script environments are cleared before execution.
- User-entered project, site, and note fields never enter command arguments or
  script environments. The Quick Check target is the single exception to the
  user-input rule, and it is admitted only after the whitelist parse described
  above — and even then it is passed to an in-process socket, never to a
  command line.
- External app runtime commands are limited to allowlisted scripts and the
  fixed macOS folder-opening action.
- The app does not modify firewall, routing, DNS, VLAN, or Wi-Fi settings.
- The app does not upload audit data.
