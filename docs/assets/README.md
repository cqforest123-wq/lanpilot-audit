# Screenshot And Demo Plan

The committed screenshots are generated from synthetic public demo data in [demo-data/public-demo-audit.json](demo-data/public-demo-audit.json). They use documentation-reserved addresses, redacted MAC values, demo device names, and the sample path `/Users/demo/lanpilot-demo`.

Do not commit screenshots from real customer, family, office, or production networks. Do not commit images that reveal real IP addresses, MAC addresses, gateways, device names, usernames, local paths, Wi-Fi names, hostnames, or raw network evidence.

## High Priority

These README preview screenshots are committed:

1. `dashboard-overview.png` - v1.6.1 modern dashboard with synthetic Stash TUN path.
2. `network-path-map.png` - path map with physical LAN, local gateway, overlay, proxy exit, and internet.
3. `latency-diagnostics.png` - gateway, DNS, and HTTPS timing bars with demo measurements.
4. `troubleshooting-advice-zh.png` - Chinese fault point and troubleshooting advice using demo data.
5. `screenshot-authorization.png` - authorization workflow and safety boundary.
6. `screenshot-report-zh.png` - Chinese report page with demo risk register and Raw Evidence entry.
7. `screenshot-remediation.png` - remediation tickets and service exposure matrix.

## Additional Assets

1. Landing / dashboard.
2. Raw Evidence view.
3. Asset Inventory.
4. Export page.
5. Settings / language.
6. Short GIF showing authorized workflow progress.

## Regenerate Screenshots

```sh
npm install
npm run docs:screenshots
npm run public:check
```

The generator writes temporary HTML outside the repository and updates only:

- `docs/assets/dashboard-overview.png`
- `docs/assets/network-path-map.png`
- `docs/assets/latency-diagnostics.png`
- `docs/assets/troubleshooting-advice-zh.png`
- `docs/assets/screenshot-authorization.png`
- `docs/assets/screenshot-report-zh.png`
- `docs/assets/screenshot-remediation.png`

Before adding or replacing a README image reference, commit the image file first and verify the link with `npm run public:check`.
