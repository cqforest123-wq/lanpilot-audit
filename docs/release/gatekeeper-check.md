# Gatekeeper Check

- Version: 1.5.1
- Signature classification: Developer ID signed
- Developer ID signed: Yes
- Ad-hoc signed: No
- Notarized/stapled: Yes
- Gatekeeper assessment: Accepted

Developer ID signing and notarization are optional for this local readiness check. Their absence is recorded as a distribution limitation, not a product test failure.

## codesign - App

- Exit status: 0

```text
/usr/bin/codesign -dv --verbose=4 <repo>/src-tauri/target/release/bundle/macos/LANPilot Audit.app
Executable=<repo>/src-tauri/target/release/bundle/macos/LANPilot Audit.app/Contents/MacOS/lanpilot-audit-app
Identifier=com.litao.lanpilotaudit
Format=app bundle with Mach-O thin (arm64)
CodeDirectory v=20500 size=18147 flags=0x10000(runtime) hashes=560+3 location=embedded
VersionPlatform=1
VersionMin=720896
VersionSDK=1705216
Hash type=sha256 size=32
CandidateCDHash sha256=57b651e84b722c0933b2316543724b2a6130ddaa
CandidateCDHashFull sha256=57b651e84b722c0933b2316543724b2a6130ddaa0d0841873270c2126ece983d
Hash choices=sha256
CMSDigest=57b651e84b722c0933b2316543724b2a6130ddaa0d0841873270c2126ece983d
CMSDigestType=2
Executable Segment base=0
Executable Segment limit=6799360
Executable Segment flags=0x1
Page size=16384
CDHash=57b651e84b722c0933b2316543724b2a6130ddaa
Signature size=8963
Authority=Developer ID Application: TAO LI (<team-id>)
Authority=Developer ID Certification Authority
Authority=Apple Root CA
Timestamp=Jun 17, 2026 at 12:34:29
Notarization Ticket=stapled
Info.plist entries=14
TeamIdentifier=<redacted>
Runtime Version=26.5.0
Sealed Resources version=2 rules=13 files=19
Internal requirements count=1 size=184
```

## codesign - DMG

- Exit status: 0

```text
/usr/bin/codesign -dv --verbose=4 <repo>/src-tauri/target/release/bundle/dmg/LANPilot Audit_1.5.1_aarch64.dmg
Executable=<repo>/src-tauri/target/release/bundle/dmg/LANPilot Audit_1.5.1_aarch64.dmg
Identifier=LANPilot Audit_1.5.1_aarch64
Format=disk image
CodeDirectory v=20200 size=316 flags=0x0(none) hashes=1+6 location=embedded
Hash type=sha256 size=32
CandidateCDHash sha256=322463fd08e01ff2a0e900d0601f0be14e6c9a7f
CandidateCDHashFull sha256=322463fd08e01ff2a0e900d0601f0be14e6c9a7f3d8bf431ff074c31865f1ef1
Hash choices=sha256
CMSDigest=322463fd08e01ff2a0e900d0601f0be14e6c9a7f3d8bf431ff074c31865f1ef1
CMSDigestType=2
Page size=none
CDHash=322463fd08e01ff2a0e900d0601f0be14e6c9a7f
Signature size=8962
Authority=Developer ID Application: TAO LI (<team-id>)
Authority=Developer ID Certification Authority
Authority=Apple Root CA
Timestamp=Jun 17, 2026 at 12:34:35
Notarization Ticket=stapled
Info.plist=not bound
TeamIdentifier=<redacted>
Sealed Resources=none
Internal requirements count=1 size=188
```

## spctl - App

- Exit status: 0

```text
/usr/sbin/spctl --assess --type execute --verbose=4 <repo>/src-tauri/target/release/bundle/macos/LANPilot Audit.app
<repo>/src-tauri/target/release/bundle/macos/LANPilot Audit.app: accepted
source=Notarized Developer ID
```

## spctl - DMG

- Exit status: 0

```text
/usr/sbin/spctl --assess --type open --context context:primary-signature --verbose=4 <repo>/src-tauri/target/release/bundle/dmg/LANPilot Audit_1.5.1_aarch64.dmg
<repo>/src-tauri/target/release/bundle/dmg/LANPilot Audit_1.5.1_aarch64.dmg: accepted
source=Notarized Developer ID
```

## stapler - App

- Exit status: 0

```text
/usr/bin/xcrun stapler validate <repo>/src-tauri/target/release/bundle/macos/LANPilot Audit.app
Processing: <repo>/src-tauri/target/release/bundle/macos/LANPilot Audit.app
The validate action worked!
```

## stapler - DMG

- Exit status: 0

```text
/usr/bin/xcrun stapler validate <repo>/src-tauri/target/release/bundle/dmg/LANPilot Audit_1.5.1_aarch64.dmg
Processing: <repo>/src-tauri/target/release/bundle/dmg/LANPilot Audit_1.5.1_aarch64.dmg
The validate action worked!
```

