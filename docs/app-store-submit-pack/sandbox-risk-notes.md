# App Sandbox Risk Notes

The current direct-distribution app runs a bundled, integrity-checked local
engine and may invoke separately installed `nmap`. App Sandbox restrictions can
prevent this execution model from working unchanged in a Mac App Store build.

Before App Store submission:

- Validate all required local process execution under App Sandbox.
- Validate access to the selected local export destination.
- Document network client/server entitlement needs.
- Decide whether a store-specific limited mode is required.
- Keep the fixed authorization flow and safety boundary unchanged.
