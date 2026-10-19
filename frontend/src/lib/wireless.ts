export type WirelessBounds = [number, number, number, number];

export type WirelessDataset = {
  id: string;
  name: string;
  status: string;
  devices?: number;
  observations?: number;
  bounds?: WirelessBounds | null;
  error?: string;
  progress?: number | Record<string, unknown>;
  imported_at?: string;
  source?: string;
  timestamp_timezone?: string;
};

export type WirelessCompanyLink = {
  company_id: string;
  company_name: string;
  role: string;
  confidence?: number;
  evidence?: string | string[] | Record<string, unknown>;
  distance_m?: number | null;
  status?: string;
  rejected_by_user?: boolean;
  source_url?: string;
  facility_name?: string;
};

export type WirelessLocation = {
  latitude: number;
  longitude: number;
  observations?: number;
  gps_accuracy?: number | null;
  rssi?: number | null;
  first_seen?: string;
  last_seen?: string;
};

export type WirelessDevice = {
  id: string;
  identifier: string;
  name: string;
  type: string;
  observations: number;
  first_seen?: string;
  last_seen?: string;
  latitude?: number | null;
  longitude?: number | null;
  gps_accuracy?: number | null;
  rssi?: number | null;
  company_links?: WirelessCompanyLink[];
  locations?: WirelessLocation[];
  locations_total?: number;
  locations_truncated?: boolean;
  provenance?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
  timestamp_timezone?: string;
  attribution?: {
    total?: number;
    truncated?: boolean;
    advertised_provider_conflict?: boolean;
    manufacturer_assignment_conflict?: boolean;
  };
};

export type WirelessStats = {
  datasets: number;
  devices: number;
  observations: number;
  located_devices?: number;
  company_links: number;
  signal_types?: Record<string, number>;
};

export type CompanyWirelessSummary = {
  devices?: number | unknown[];
  device_count?: number;
  distinct_device_count?: number;
  counts_by_role?: Record<string, number>;
  facility_count?: number;
};

export type WirelessFeature = {
  type: "Feature";
  geometry: { type: "Point"; coordinates: [number, number] };
  properties: { count: number; device_id?: string; name?: string; type?: string; rssi?: number };
};

export type WirelessMapData = {
  type: "FeatureCollection";
  features: WirelessFeature[];
  total: number;
  truncated: boolean;
};

export const RADIO_LABELS: Record<string, string> = {
  WIFI: "Wi-Fi",
  BLE: "Bluetooth LE",
  BT: "Bluetooth",
  GSM: "GSM",
  LTE: "LTE",
  NR: "5G NR",
};
export const RADIO_COLORS: Record<string, string> = {
  WIFI: "#6ad8c7",
  BLE: "#a3a0ff",
  BT: "#d7a0ee",
  GSM: "#e7b965",
  LTE: "#6ab6ee",
  NR: "#ee8f91",
};
export const WIRELESS_ROLES: Record<string, string> = {
  manufacturer: "Registered manufacturer",
  candidate_business: "Nearby business candidate",
  registered_manufacturer: "Registered manufacturer",
  advertised_provider: "Advertised provider",
  nearby_business_candidate: "Nearby business candidate",
  confirmed_operator: "Confirmed operator",
};

export function wirelessTime(value: string | undefined) {
  return value?.startsWith("1970-01-01")
    ? "Unknown (source epoch sentinel)"
    : value
      ? value.replace("T", " ")
      : "Not recorded";
}

export function wirelessTimeLabel(timezone: string | undefined) {
  return timezone === "UTC" ? "Observation time · UTC" : "FirstSeen · source timezone unspecified";
}

export function wirelessRssi(value: number | null | undefined) {
  return value == null
    ? "Not recorded"
    : value >= 0
      ? `${value} (raw source value)`
      : `${value} dBm`;
}

export function wirelessAccuracy(value: number | null | undefined) {
  return value == null
    ? "Not recorded"
    : `${value.toLocaleString(undefined, { maximumFractionDigits: 2 })} m`;
}

export function validBounds(value: WirelessBounds | null | undefined): value is WirelessBounds {
  return Boolean(
    value &&
    value.length === 4 &&
    value.every(Number.isFinite) &&
    value[0] <= value[2] &&
    value[1] <= value[3],
  );
}

export function mapParams(bounds: WirelessBounds, zoom: number, filters: Record<string, string>) {
  return {
    ...filters,
    bbox: bounds.map((value) => value.toFixed(6)).join(","),
    zoom: String(Math.max(0, Math.min(19, Math.round(zoom)))),
  };
}
