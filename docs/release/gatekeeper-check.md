# Gatekeeper Check

- Version: 1.5.1
- Signature classification: ad-hoc signed
- Developer ID signed: No
- Ad-hoc signed: Yes
- Notarized/stapled: No
- Gatekeeper assessment: Not accepted

Developer ID signing and notarization are optional for this local readiness check. Their absence is recorded as a distribution limitation, not a product test failure.

## codesign - App

- Exit status: 0

```text
/usr/bin/codesign -dv --verbose=4 <repo>/src-tauri/target/release/bundle/macos/LANPilot Audit.app
Executable=<repo>/src-tauri/target/release/bundle/macos/LANPilot Audit.app/Contents/MacOS/lanpilot-audit-app
Identifier=com.litao.lanpilotaudit
Format=app bundle with Mach-O thin (arm64)
CodeDirectory v=20400 size=18128 flags=0x2(adhoc) hashes=560+3 location=embedded
VersionPlatform=1
VersionMin=720896
VersionSDK=1705216
Hash type=sha256 size=32
CandidateCDHash sha256=dba3021b6c813ed3ac0ab2b39f3feff202b25027
CandidateCDHashFull sha256=dba3021b6c813ed3ac0ab2b39f3feff202b250272d8a22d6543e4f092465c39b
Hash choices=sha256
CMSDigest=dba3021b6c813ed3ac0ab2b39f3feff202b250272d8a22d6543e4f092465c39b
CMSDigestType=2
Executable Segment base=0
Executable Segment limit=6799360
Executable Segment flags=0x1
Page size=16384
CDHash=dba3021b6c813ed3ac0ab2b39f3feff202b25027
Signature=adhoc
Info.plist entries=14
TeamIdentifier=not set
Sealed Resources version=2 rules=13 files=19
Internal requirements count=0 size=12
```

## codesign - DMG

- Exit status: 1

```text
/usr/bin/codesign -dv --verbose=4 <repo>/src-tauri/target/release/bundle/dmg/LANPilot Audit_1.5.1_aarch64.dmg
<repo>/src-tauri/target/release/bundle/dmg/LANPilot Audit_1.5.1_aarch64.dmg: code object is not signed at all
```

## spctl - App

- Exit status: 3

```text
/usr/sbin/spctl --assess --type execute --verbose=4 <repo>/src-tauri/target/release/bundle/macos/LANPilot Audit.app
<repo>/src-tauri/target/release/bundle/macos/LANPilot Audit.app: rejected
```

## spctl - DMG

- Exit status: 3

```text
/usr/sbin/spctl --assess --type open --context context:primary-signature --verbose=4 <repo>/src-tauri/target/release/bundle/dmg/LANPilot Audit_1.5.1_aarch64.dmg
<repo>/src-tauri/target/release/bundle/dmg/LANPilot Audit_1.5.1_aarch64.dmg: rejected
source=no usable signature
```

## stapler - App

- Exit status: 65

```text
/usr/bin/xcrun stapler validate <repo>/src-tauri/target/release/bundle/macos/LANPilot Audit.app
Processing: <repo>/src-tauri/target/release/bundle/macos/LANPilot Audit.app
LANPilot Audit.app does not have a ticket stapled to it.
```

## stapler - DMG

- Exit status: 65

```text
/usr/bin/xcrun stapler validate <repo>/src-tauri/target/release/bundle/dmg/LANPilot Audit_1.5.1_aarch64.dmg
Processing: <repo>/src-tauri/target/release/bundle/dmg/LANPilot Audit_1.5.1_aarch64.dmg
LANPilot Audit_1.5.1_aarch64.dmg does not have a ticket stapled to it.
```

