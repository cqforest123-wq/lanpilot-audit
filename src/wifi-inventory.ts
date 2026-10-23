export type WifiDeviceFilter = "all" | "network" | "camera" | "endpoint" | "other";

export interface WifiInventoryEntry {
  ip: string;
  mac: string | null;
  hostname: string | null;
  vendor: string | null;
  likely: "camera" | "network" | "endpoint" | null;
}

export function filterWifiDevices<T extends WifiInventoryEntry>(
  devices: readonly T[],
  filter: WifiDeviceFilter,
  query: string,
): T[] {
  const normalizedQuery = query.trim().toLocaleLowerCase();
  return devices.filter((device) => {
    const category = device.likely ?? "other";
    if (filter !== "all" && category !== filter) return false;
    if (!normalizedQuery) return true;
    return [device.ip, device.mac, device.hostname, device.vendor]
      .some((value) => value?.toLocaleLowerCase().includes(normalizedQuery));
  });
}
