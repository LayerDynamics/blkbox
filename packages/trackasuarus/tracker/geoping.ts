import type { TrackerClient } from "../client.ts";
import type { GeolocationData } from "../types.ts";

/**
 * Geolocate IP address with latency measurement
 *
 * This wraps the TrackerClient's geolocateIp with optional
 * latency measurement for performance monitoring.
 */
export async function geoping(
  client: TrackerClient,
  ip: string,
  options: { measureLatency?: boolean } = {}
): Promise<GeolocationData | null> {
  const start = performance.now();
  const geo = client.geolocateIp(ip);
  const latency = performance.now() - start;

  if (!geo) return null;

  if (options.measureLatency) {
    // Enhance with latency data
    return {
      ...geo,
      metadata: {
        ...geo.metadata,
        lookup_latency_ms: latency,
      },
    };
  }

  return geo;
}

/**
 * Batch geolocate multiple IPs
 *
 * Uses the TrackerClient's bulk geolocation capability
 * for efficient batch lookups.
 */
export async function geopingBatch(
  client: TrackerClient,
  ips: string[]
): Promise<Map<string, GeolocationData | null>> {
  return await client.bulkGeolocate(ips);
}

/**
 * Check if country is high-risk
 *
 * Based on common sources of malicious traffic.
 * This is a heuristic and should not be used as the sole
 * factor for decision-making.
 */
export function isHighRiskCountry(geo: GeolocationData | null): boolean {
  if (!geo?.country_code) return false;

  // Countries commonly associated with high attack volumes
  // Note: This is for threat scoring, not blocking
  const highRisk = ["CN", "RU", "KP", "IR", "SY", "VN", "BR"];

  return highRisk.includes(geo.country_code);
}

/**
 * Infer timezone from geolocation
 *
 * Returns timezone string or estimates from longitude if not available.
 */
export function inferTimezone(geo: GeolocationData | null): string {
  if (geo?.timezone) return geo.timezone;

  // Fallback: estimate from longitude
  // Each 15 degrees of longitude ≈ 1 hour time zone
  if (geo?.longitude) {
    const offsetHours = Math.round(geo.longitude / 15);
    return `UTC${offsetHours >= 0 ? '+' : ''}${offsetHours}`;
  }

  return "UTC";
}

/**
 * Calculate distance between two geolocations (km)
 *
 * Uses the Haversine formula to calculate great-circle distance.
 * Useful for detecting impossible travel (same IP from different locations).
 */
export function calculateDistance(
  geo1: GeolocationData,
  geo2: GeolocationData
): number {
  if (!geo1.latitude || !geo1.longitude || !geo2.latitude || !geo2.longitude) {
    return 0;
  }

  const R = 6371; // Earth radius in km
  const dLat = (geo2.latitude - geo1.latitude) * Math.PI / 180;
  const dLon = (geo2.longitude - geo1.longitude) * Math.PI / 180;

  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(geo1.latitude * Math.PI / 180) *
    Math.cos(geo2.latitude * Math.PI / 180) *
    Math.sin(dLon / 2) * Math.sin(dLon / 2);

  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
}

/**
 * Detect impossible travel
 *
 * Checks if two geolocations are too far apart given the time difference.
 * Useful for detecting VPN switching or IP spoofing.
 */
export function detectImpossibleTravel(
  geo1: GeolocationData,
  geo2: GeolocationData,
  timeDiffSeconds: number
): boolean {
  const distance = calculateDistance(geo1, geo2);
  if (distance === 0) return false;

  // Maximum possible speed: 1000 km/h (commercial aircraft)
  const maxSpeed = 1000;
  const timeDiffHours = timeDiffSeconds / 3600;
  const maxPossibleDistance = maxSpeed * timeDiffHours;

  return distance > maxPossibleDistance;
}

/**
 * Get geographic region from country code
 *
 * Groups countries into broader regions for analysis.
 */
export function getRegion(countryCode: string): string {
  const regions: Record<string, string[]> = {
    "North America": ["US", "CA", "MX"],
    "South America": ["BR", "AR", "CL", "CO", "PE", "VE"],
    "Europe": ["GB", "FR", "DE", "IT", "ES", "NL", "PL", "UA", "RO"],
    "Asia": ["CN", "JP", "IN", "KR", "ID", "TH", "VN", "PH", "SG"],
    "Middle East": ["IR", "IQ", "SA", "TR", "IL", "AE"],
    "Africa": ["ZA", "EG", "NG", "KE", "MA"],
    "Oceania": ["AU", "NZ"],
  };

  for (const [region, countries] of Object.entries(regions)) {
    if (countries.includes(countryCode)) {
      return region;
    }
  }

  return "Other";
}

/**
 * Check if IP is from a known VPN/proxy service
 *
 * This is a basic check based on common VPN provider ranges.
 * For production, consider using a commercial VPN detection service.
 */
export function isLikelyVPN(geo: GeolocationData | null): boolean {
  if (!geo) return false;

  // Check ASN for known VPN providers
  const vpnAsns = [
    "AS174",    // Cogent (common VPN provider)
    "AS13335",  // Cloudflare (Warp VPN)
    "AS30633",  // Leaseweb (VPS/VPN)
    "AS46562",  // Total Server Solutions (VPN)
  ];

  if (geo.asn && vpnAsns.includes(geo.asn)) {
    return true;
  }

  // Check organization names
  if (geo.isp) {
    const vpnKeywords = ["vpn", "proxy", "hosting", "datacenter", "cloud"];
    const ispLower = geo.isp.toLowerCase();
    return vpnKeywords.some(keyword => ispLower.includes(keyword));
  }

  return false;
}
