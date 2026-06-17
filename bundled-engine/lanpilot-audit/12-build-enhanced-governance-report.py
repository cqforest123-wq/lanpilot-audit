#!/usr/bin/env python3
import csv
import json
import os
import pathlib
from datetime import datetime

LAB = pathlib.Path(os.environ.get("LANPILOT_LAB_DIR", pathlib.Path.home() / "lanpilot-audit-latest")).resolve()
ASSETS = LAB / "02-assets"
SERVICES = LAB / "03-services"
RISKS = LAB / "04-risk"
TRACKING = LAB / "05-remediation"
REPORTS = LAB / "06-report"
HISTORY = LAB / "07-history"
for directory in (ASSETS, SERVICES, TRACKING, REPORTS, HISTORY):
    directory.mkdir(parents=True, exist_ok=True)


def rows(relative):
    path = LAB / relative
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8", errors="replace") as handle:
        return list(csv.DictReader(handle))


def write_csv(path, fields, data):
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(data)


def services_by_ip():
    result = {}
    for item in rows("03-services/reachable-open-ports.csv"):
        result.setdefault(item["ip"], []).append(item)
    return result


def guess_category(ip, services, gateway):
    ports = {item["port"] for item in services}
    if ip == gateway:
        return "Gateway"
    if ports & {"445", "139"}:
        return "NAS / file sharing"
    if ports & {"9100", "515", "631"}:
        return "Printer"
    if ports & {"554"}:
        return "Camera / CCTV"
    if ports & {"22", "3389", "5900"}:
        return "Remote administration host"
    if ports & {"80", "443", "8080", "8443"}:
        return "Web service host"
    return "Unknown"


def risk_by_asset():
    levels = {"Low": 1, "Medium": 2, "High": 3}
    result = {}
    for item in rows("04-risk/network-issues-register.csv"):
        asset, severity = item.get("asset", ""), item.get("severity", "Low")
        if levels.get(severity, 0) > levels.get(result.get(asset, ""), 0):
            result[asset] = severity
    return result


def network_summary():
    result = {}
    path = LAB / "00-scope/network-summary.txt"
    if path.exists():
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                result[key] = value
    return result


def build_assets():
    observed = rows("02-assets/passive-arp-assets.csv")
    services = services_by_ip()
    risks = risk_by_asset()
    gateway = network_summary().get("default_gateway", "")
    reachable = set((LAB / "02-assets/reachable-client-ips.txt").read_text(errors="replace").split()) if (LAB / "02-assets/reachable-client-ips.txt").exists() else set()
    ips = {item["ip"] for item in observed} | set(services) | reachable | ({gateway} if gateway else set())
    passive = {item["ip"]: item for item in observed}
    output = []
    for ip in sorted(ips):
        item = passive.get(ip, {})
        exposed = services.get(ip, [])
        output.append({
            "ip": ip,
            "mac": item.get("mac", ""),
            "vendor": item.get("vendor", ""),
            "reachability": "reachable" if ip in reachable or exposed else "observed",
            "observed_services": "; ".join(f"{x.get('service') or 'unknown'}/{x.get('port')}" for x in exposed),
            "device_category_guess": guess_category(ip, exposed, gateway),
            "risk_level": risks.get(ip, "Low"),
            "first_seen": item.get("first_seen", ""),
            "last_seen": item.get("last_seen", datetime.now().astimezone().isoformat()),
        })
    fields = ["ip","mac","vendor","reachability","observed_services","device_category_guess","risk_level","first_seen","last_seen"]
    write_csv(ASSETS / "asset-inventory.csv", fields, output)
    (REPORTS / "asset-inventory-summary.md").write_text(
        "# Asset Inventory Summary\n\n"
        f"- Assets observed: {len(output)}\n"
        f"- Category guesses: {', '.join(sorted({x['device_category_guess'] for x in output})) or 'None'}\n\n"
        "Device categories are governance-oriented guesses based only on observed network evidence.\n",
        encoding="utf-8",
    )
    return output


def exposure_type(port):
    if port in {"80", "443", "8080", "8443"}: return "Web service exposure"
    if port in {"139", "445"}: return "SMB exposure"
    if port in {"22", "3389", "5900"}: return "Remote administration exposure"
    if port in {"53", "67", "68"}: return "Infrastructure service exposure"
    return "Unknown service exposure"


def build_exposures(gateway):
    output = []
    for item in rows("03-services/reachable-open-ports.csv"):
        kind = "Gateway management exposure" if item["ip"] == gateway and item["port"] in {"80","443","8080","8443"} else exposure_type(item["port"])
        risk = "Medium" if kind in {"SMB exposure","Remote administration exposure","Gateway management exposure"} else "Low"
        owner = "Network administrator" if item["ip"] == gateway or kind == "Infrastructure service exposure" else "Asset owner"
        output.append({"asset":item["ip"],"service":item.get("service",""),"port":item["port"],"protocol":item.get("protocol","tcp"),
            "exposure_type":kind,"business_justification_status":"Not documented","recommended_owner":owner,"risk_level":risk,
            "recommended_action":"Confirm business purpose, document ownership, and restrict unnecessary exposure."})
    fields = ["asset","service","port","protocol","exposure_type","business_justification_status","recommended_owner","risk_level","recommended_action"]
    write_csv(SERVICES / "service-exposure-matrix.csv", fields, output)
    (REPORTS / "service-exposure-summary.md").write_text(
        "# Service Exposure Matrix Summary\n\n"
        f"- Observed exposures: {len(output)}\n"
        f"- Assets with exposure: {len({x['asset'] for x in output})}\n\n"
        "The matrix is derived from existing low-intensity common-service observations.\n", encoding="utf-8")
    return output


def previous_lab():
    candidates = sorted((path for path in LAB.parent.glob("lanpilot-audit-run-*") if path.resolve() != LAB), reverse=True)
    return candidates[0] if candidates else None


def build_diff(assets, exposures):
    previous = previous_lab()
    old_assets, old_exposures, old_risks = set(), set(), {"High":0,"Medium":0,"Low":0}
    if previous:
        old_assets = {x.get("ip","") for x in read_other(previous / "02-assets/asset-inventory.csv")}
        old_exposures = {(x.get("asset",""),x.get("port",""),x.get("protocol","")) for x in read_other(previous / "03-services/service-exposure-matrix.csv")}
        for item in read_other(previous / "04-risk/network-issues-register.csv"):
            if item.get("severity") in old_risks: old_risks[item["severity"]] += 1
    new_assets = {x["ip"] for x in assets}; new_exposures = {(x["asset"],x["port"],x["protocol"]) for x in exposures}
    current_risks = {"High":0,"Medium":0,"Low":0}
    for item in rows("04-risk/network-issues-register.csv"):
        if item.get("severity") in current_risks: current_risks[item["severity"]] += 1
    diff = {"previous_lab": str(previous) if previous else None, "new_assets": sorted(new_assets-old_assets), "removed_assets": sorted(old_assets-new_assets),
        "new_exposures": sorted("/".join(x) for x in new_exposures-old_exposures), "resolved_exposures": sorted("/".join(x) for x in old_exposures-new_exposures),
        "risk_count_changes": {key: current_risks[key]-old_risks[key] for key in current_risks}}
    (HISTORY / "snapshot-diff.json").write_text(json.dumps(diff, indent=2) + "\n", encoding="utf-8")
    (REPORTS / "snapshot-diff.md").write_text("# Snapshot Diff\n\n" + "\n".join([
        f"- Previous audit: {diff['previous_lab'] or 'No previous audit available'}",
        f"- New assets: {len(diff['new_assets'])}", f"- Removed assets: {len(diff['removed_assets'])}",
        f"- New exposures: {len(diff['new_exposures'])}", f"- Resolved exposures: {len(diff['resolved_exposures'])}",
        f"- Risk changes: {diff['risk_count_changes']}",
    ]) + "\n", encoding="utf-8")


def read_other(path):
    if not path.exists(): return []
    with path.open(newline="", encoding="utf-8", errors="replace") as handle: return list(csv.DictReader(handle))


def build_tracking():
    fields = ["finding_id","owner","due_date","status","notes","priority","business_justification"]
    path = TRACKING / "remediation-tracking.csv"
    existing = {x["finding_id"]: x for x in read_other(path)}
    output = []
    for issue in rows("04-risk/network-issues-register.csv"):
        finding_id = issue["issue_id"]
        output.append(existing.get(finding_id, {"finding_id":finding_id,"owner":"","due_date":"","status":"Open","notes":"","priority":issue["severity"],"business_justification":""}))
    write_csv(path, fields, output)
    (TRACKING / "remediation-tracking.json").write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")


def build_json_summary(assets, exposures):
    summary = {"generated_at": datetime.now().astimezone().isoformat(), "asset_count": len(assets), "exposure_count": len(exposures),
        "risk_counts": {level: sum(1 for x in rows("04-risk/network-issues-register.csv") if x.get("severity") == level) for level in ("High","Medium","Low")},
        "local_first": True}
    (REPORTS / "governance-summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")


assets = build_assets()
exposures = build_exposures(network_summary().get("default_gateway", ""))
build_diff(assets, exposures)
build_tracking()
build_json_summary(assets, exposures)
(LAB / "00-scope/step-status/build_enhanced_governance_report.json").write_text(json.dumps({
    "step":"build_enhanced_governance_report","state":"completed","message":"Enhanced governance reports generated",
    "updated_at":datetime.now().astimezone().isoformat()
}) + "\n", encoding="utf-8")
print(f"Enhanced governance reports generated in {REPORTS}")
