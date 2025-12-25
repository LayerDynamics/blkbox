// TrackerClient - FFI wrapper for BlkBox tracking functions

import type {
  AttackSession,
  EnrichedAttackEvent,
  GeolocationData,
} from "./types.ts";

/**
 * Client for accessing BlkBox tracking functionality via FFI
 *
 * This class wraps the tracking-specific FFI functions:
 * - blkbox_geolocate_ip
 * - blkbox_get_ip_sessions
 * - blkbox_get_enriched_attacks
 *
 * Usage:
 * ```typescript
 * const blkbox = new BlkBoxFFI();
 * const tracker = blkbox.getTrackerClient();
 *
 * const geo = tracker.geolocateIp("8.8.8.8");
 * const sessions = tracker.getIpSessions("1.2.3.4");
 * const enriched = tracker.getEnrichedAttacks(10, 0);
 * ```
 */
export class TrackerClient {
  private runtime: Deno.PointerValue;
  private lib: Deno.DynamicLibrary<any>;
  private encoder = new TextEncoder();
  private decoder = new TextDecoder();

  constructor(runtime: Deno.PointerValue, lib: Deno.DynamicLibrary<any>) {
    this.runtime = runtime;
    this.lib = lib;
  }

  /**
   * Geolocate an IP address using MaxMind and/or Cloudflare data
   *
   * @param ipAddress - IP address to geolocate
   * @returns GeolocationData or null if lookup fails
   *
   * Example:
   * ```typescript
   * const geo = tracker.geolocateIp("8.8.8.8");
   * console.log(geo?.country_code);  // "US"
   * console.log(geo?.organization);  // "Google LLC"
   * ```
   */
  geolocateIp(ipAddress: string): GeolocationData | null {
    // Allocate buffer for IP string (null-terminated)
    const ipBuffer = this.encoder.encode(ipAddress + "\0");

    // Allocate buffer for JSON response (16KB should be enough)
    const buffer = new Uint8Array(16384);

    const result = this.lib.symbols.blkbox_geolocate_ip(
      this.runtime,
      ipBuffer,
      buffer,
      buffer.length,
    );

    // Negative result indicates error
    if (result < 0) {
      return null;
    }

    // Zero result means no data found
    if (result === 0) {
      return null;
    }

    // Decode JSON response
    const jsonStr = this.decoder.decode(buffer.slice(0, result));

    try {
      return JSON.parse(jsonStr) as GeolocationData;
    } catch (_error) {
      return null;
    }
  }

  /**
   * Get all attack sessions associated with an IP address
   *
   * @param ipAddress - IP address to look up
   * @returns Array of attack sessions
   *
   * Example:
   * ```typescript
   * const sessions = tracker.getIpSessions("1.2.3.4");
   * for (const session of sessions) {
   *   console.log(`Session ${session.session_hash}:`);
   *   console.log(`  Attacks: ${session.attack_count}`);
   *   console.log(`  Threat Level: ${session.aggregate_threat_level}/10`);
   * }
   * ```
   */
  getIpSessions(ipAddress: string): AttackSession[] {
    // Allocate buffer for IP string (null-terminated)
    const ipBuffer = this.encoder.encode(ipAddress + "\0");

    // Allocate buffer for JSON response (64KB for multiple sessions)
    const buffer = new Uint8Array(65536);

    const result = this.lib.symbols.blkbox_get_ip_sessions(
      this.runtime,
      ipBuffer,
      buffer,
      buffer.length,
    );

    // Negative result indicates error
    if (result < 0) {
      return [];
    }

    // Zero result means no sessions found
    if (result === 0) {
      return [];
    }

    // Decode JSON response
    const jsonStr = this.decoder.decode(buffer.slice(0, result));

    try {
      return JSON.parse(jsonStr) as AttackSession[];
    } catch (_error) {
      return [];
    }
  }

  /**
   * Get enriched attack events with all tracking data
   *
   * @param limit - Maximum number of events to return
   * @param offset - Number of events to skip (for pagination)
   * @returns Array of enriched attack events
   *
   * Example:
   * ```typescript
   * // Get latest 10 enriched attacks
   * const attacks = tracker.getEnrichedAttacks(10, 0);
   *
   * for (const enriched of attacks) {
   *   console.log(`Attack from ${enriched.attack.source_ip}`);
   *   console.log(`  Country: ${enriched.geolocation?.country_name}`);
   *   console.log(`  Fingerprints: ${enriched.fingerprints.length}`);
   *   console.log(`  Session: ${enriched.session?.session_hash}`);
   * }
   *
   * // Get next 10 (pagination)
   * const nextAttacks = tracker.getEnrichedAttacks(10, 10);
   * ```
   */
  getEnrichedAttacks(limit: number, offset: number): EnrichedAttackEvent[] {
    // Allocate buffer for JSON response (128KB for multiple enriched events)
    const buffer = new Uint8Array(131072);

    const result = this.lib.symbols.blkbox_get_enriched_attacks(
      this.runtime,
      limit,
      offset,
      buffer,
      buffer.length,
    );

    // Negative result indicates error
    if (result < 0) {
      return [];
    }

    // Zero result means no events found
    if (result === 0) {
      return [];
    }

    // Decode JSON response
    const jsonStr = this.decoder.decode(buffer.slice(0, result));

    try {
      return JSON.parse(jsonStr) as EnrichedAttackEvent[];
    } catch (_error) {
      return [];
    }
  }

  /**
   * Bulk geolocate multiple IP addresses
   *
   * @param ipAddresses - Array of IP addresses to geolocate
   * @returns Map of IP address to GeolocationData
   *
   * Example:
   * ```typescript
   * const ips = ["8.8.8.8", "1.1.1.1", "208.67.222.222"];
   * const geoMap = await tracker.bulkGeolocate(ips);
   *
   * for (const [ip, geo] of geoMap) {
   *   console.log(`${ip}: ${geo.country_code} - ${geo.organization}`);
   * }
   * ```
   */
  async bulkGeolocate(
    ipAddresses: string[],
  ): Promise<Map<string, GeolocationData>> {
    const results = new Map<string, GeolocationData>();

    for (const ip of ipAddresses) {
      const geo = this.geolocateIp(ip);
      if (geo) {
        results.set(ip, geo);
      }
    }

    return results;
  }

  /**
   * Get session summary statistics for an IP
   *
   * @param ipAddress - IP address to analyze
   * @returns Summary statistics or null if no sessions found
   *
   * Example:
   * ```typescript
   * const stats = tracker.getSessionStats("1.2.3.4");
   * console.log(`Total attacks: ${stats?.total_attacks}`);
   * console.log(`Active sessions: ${stats?.active_sessions}`);
   * console.log(`Average threat: ${stats?.avg_threat_level}`);
   * ```
   */
  getSessionStats(
    ipAddress: string,
  ): {
    total_attacks: number;
    active_sessions: number;
    max_threat_level: number;
    avg_threat_level: number;
    first_seen: string;
    last_seen: string;
  } | null {
    const sessions = this.getIpSessions(ipAddress);

    if (sessions.length === 0) {
      return null;
    }

    const totalAttacks = sessions.reduce(
      (sum, s) => sum + s.attack_count,
      0,
    );
    const maxThreat = Math.max(
      ...sessions.map((s) => s.aggregate_threat_level),
    );
    const avgThreat = sessions.reduce(
      (sum, s) => sum + s.aggregate_threat_level,
      0,
    ) / sessions.length;

    const firstSeen = sessions.reduce((earliest, s) =>
      s.first_seen < earliest ? s.first_seen : earliest
    , sessions[0].first_seen);

    const lastSeen = sessions.reduce((latest, s) =>
      s.last_seen > latest ? s.last_seen : latest
    , sessions[0].last_seen);

    return {
      total_attacks: totalAttacks,
      active_sessions: sessions.length,
      max_threat_level: maxThreat,
      avg_threat_level: avgThreat,
      first_seen: firstSeen,
      last_seen: lastSeen,
    };
  }
}
