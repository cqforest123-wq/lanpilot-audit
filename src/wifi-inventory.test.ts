import { describe, expect, it } from "vitest";
import { filterWifiDevices, type WifiInventoryEntry } from "./wifi-inventory";

const devices: WifiInventoryEntry[] = [
  { ip: "192.0.2.1", mac: "00:11:22:33:44:55", hostname: "router-demo", vendor: "Acme Networks", likely: "network" },
  { ip: "192.0.2.24", mac: "02:aa:bb:cc:dd:ee", hostname: "", vendor: null, likely: "endpoint" },
  { ip: "192.0.2.40", mac: null, hostname: null, vendor: null, likely: null },
];

describe("filterWifiDevices", () => {
  it("filters by inferred category and includes unclassified devices under other", () => {
    expect(filterWifiDevices(devices, "network", "").map(({ ip }) => ip)).toEqual(["192.0.2.1"]);
    expect(filterWifiDevices(devices, "other", "").map(({ ip }) => ip)).toEqual(["192.0.2.40"]);
  });

  it("searches across IP, MAC, hostname, and manufacturer without case sensitivity", () => {
    expect(filterWifiDevices(devices, "all", "ACME").map(({ ip }) => ip)).toEqual(["192.0.2.1"]);
    expect(filterWifiDevices(devices, "all", "02:AA").map(({ ip }) => ip)).toEqual(["192.0.2.24"]);
  });

  it("combines the text query with the selected category", () => {
    expect(filterWifiDevices(devices, "endpoint", "192.0.2.1")).toEqual([]);
    expect(filterWifiDevices(devices, "endpoint", "192.0.2.24").map(({ ip }) => ip)).toEqual(["192.0.2.24"]);
  });
});
