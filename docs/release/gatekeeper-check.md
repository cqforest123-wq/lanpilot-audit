# Gatekeeper Check

- Version: 1.6.0
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
CodeDirectory v=20500 size=18563 flags=0x10000(runtime) hashes=573+3 location=embedded
VersionPlatform=1
VersionMin=720896
VersionSDK=1705216
Hash type=sha256 size=32
CandidateCDHash sha256=aa653bd7e2236a35b4d8d5a3601287f275420d09
CandidateCDHashFull sha256=aa653bd7e2236a35b4d8d5a3601287f275420d09413d5604ee23502b998e41af
Hash choices=sha256
CMSDigest=aa653bd7e2236a35b4d8d5a3601287f275420d09413d5604ee23502b998e41af
CMSDigestType=2
Executable Segment base=0
Executable Segment limit=6979584
Executable Segment flags=0x1
Page size=16384
CDHash=aa653bd7e2236a35b4d8d5a3601287f275420d09
Signature size=8963
Authority=Developer ID Application: TAO LI (<team-id>)
Authority=Developer ID Certification Authority
Authority=Apple Root CA
Timestamp=Jun 19, 2026 at 10:48:43
Info.plist entries=14
TeamIdentifier=<redacted>
Runtime Version=26.5.0
Sealed Resources version=2 rules=13 files=19
Internal requirements count=1 size=184
```

## codesign - DMG

- Exit status: 0

```text
/usr/bin/codesign -dv --verbose=4 <repo>/src-tauri/target/release/bundle/dmg/LANPilot Audit_1.6.0_aarch64.dmg
Executable=<repo>/src-tauri/target/release/bundle/dmg/LANPilot Audit_1.6.0_aarch64.dmg
Identifier=LANPilot Audit_1.6.0_aarch64
Format=disk image
CodeDirectory v=20200 size=316 flags=0x0(none) hashes=1+6 location=embedded
Hash type=sha256 size=32
CandidateCDHash sha256=c7e0e3e3df4e7b07e41fdf8d4ee1fee7ff5c5a44
CandidateCDHashFull sha256=c7e0e3e3df4e7b07e41fdf8d4ee1fee7ff5c5a440ebfea48846d4405382f9127
Hash choices=sha256
CMSDigest=c7e0e3e3df4e7b07e41fdf8d4ee1fee7ff5c5a440ebfea48846d4405382f9127
CMSDigestType=2
Page size=none
CDHash=c7e0e3e3df4e7b07e41fdf8d4ee1fee7ff5c5a44
Signature size=8962
Authority=Developer ID Application: TAO LI (<team-id>)
Authority=Developer ID Certification Authority
Authority=Apple Root CA
Timestamp=Jun 19, 2026 at 10:48:49
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
/usr/sbin/spctl --assess --type open --context context:primary-signature --verbose=4 <repo>/src-tauri/target/release/bundle/dmg/LANPilot Audit_1.6.0_aarch64.dmg
<repo>/src-tauri/target/release/bundle/dmg/LANPilot Audit_1.6.0_aarch64.dmg: accepted
source=Notarized Developer ID
```

## stapler - App

- Exit status: 65

```text
/usr/bin/xcrun stapler validate <repo>/src-tauri/target/release/bundle/macos/LANPilot Audit.app
Processing: <repo>/src-tauri/target/release/bundle/macos/LANPilot Audit.app
LANPilot Audit.app does not have a ticket stapled to it.
```

## stapler - DMG

- Exit status: 0

```text
/usr/bin/xcrun stapler validate <repo>/src-tauri/target/release/bundle/dmg/LANPilot Audit_1.6.0_aarch64.dmg
Processing: <repo>/src-tauri/target/release/bundle/dmg/LANPilot Audit_1.6.0_aarch64.dmg
The validate action worked!
```

