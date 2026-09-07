# App Sandbox Risk Notes

These were open questions. They are now measured facts. Each answer was
verified on macOS (Darwin arm64) with the store entitlements actually applied,
not reasoned about from documentation.

Re-run the verification at any time:

```sh
npm run sandbox:verify
```

It builds a probe, wraps it in a bundle, signs it with
`entitlements/appstore.entitlements`, confirms the sandbox actually engaged
(`HOME` redirected into the container), then exercises every syscall the app
depends on. A passing result cannot come from a sandbox that never started.

## Resolved: can the local engine run under App Sandbox?

**No, and it does not need to.**

The bundled shell engine cannot run sandboxed. Rather than argue the point, the
store build does not contain it: `tauri.appstore.conf.json` sets
`"resources": null` and the resulting bundle's `Contents/Resources` holds only
`icon.icns`.

Quick Check — the feature the store build is built around — spawns no
subprocess at all. Verified sandboxed:

| Capability | Result |
| --- | --- |
| `getifaddrs` interface enumeration | works |
| `sysctl` routing-table dump | works |
| `sysctl` neighbour-table dump | works |
| libresolv resolver list | works |
| Unprivileged ICMP echo, send and reply | works |
| `TcpStream::connect_timeout` | works |
| UDP bind and DNS query | works |
| NTP over UDP/123 | works |
| CoreWLAN radio read | works, no Location prompt |
| `NSWorkspace` opening a link | works |

## Resolved: which network entitlements are needed?

**Both `network.client` and `network.server`.**

ICMP and UDP are connectionless, so App Sandbox treats the arriving reply as
inbound and denies the send without `network.server`. Verified both ways:

| Capability | client only | client + server |
| --- | --- | --- |
| TCP connect | works | works |
| ICMP socket **open** | works | works |
| ICMP **send** | `EPERM` Operation not permitted | works |
| UDP bind | `EPERM` Operation not permitted | works |

Note that the ICMP socket still *opens* without the entitlement and only the
send fails. A check that merely creates the socket would pass and the shipped
app would be unable to ping anything, so the verification exercises a full
send-and-receive.

The app opens no listening socket. See `review-notes.md` for the wording to give
a reviewer who asks why `network.server` is present.

## Resolved: is a store-specific limited mode required?

**Yes, and it is built.**

`netinfo::is_sandboxed()` detects the sandbox at runtime by checking whether
`HOME` was redirected into a container — the same signal the verification probe
uses, so the app and its test agree on what "sandboxed" means. The UI hides the
subprocess-backed whole-path report when it is true, rather than offering a
control that is guaranteed to fail.

## Two build traps worth recording

Both produce a successful-looking build that is silently wrong.

**`"resources": {}` does not clear resources.** Tauri deep-merges configs, so an
empty object leaves the base `resources` in place and the engine scripts ship
anyway. Use `null`.

**Entitlements are embedded at signing time.** A build with no signing identity
produces an app with no entitlements and no sandbox, and nothing warns you. The
store overlay signs ad-hoc so a local build is verifiable; a real submission
overrides it with `APPLE_SIGNING_IDENTITY`.

## Still open

- Verify once more under a real Developer ID / App Store signing identity. All
  measurements above used ad-hoc signing, which activates the sandbox correctly
  but is not the submission path.
- Confirm the export destination flow under sandbox, since it writes outside
  the container.
