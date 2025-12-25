/**
 * Trackasuarus - Tracking and Intelligence Package
 *
 * Provides:
 * - Attacker tracking and session correlation
 * - Geolocation and threat analysis
 * - Anti-fingerprinting (Mask)
 * - MAC address collection (for LAN deployments)
 */

// CLIENT - FFI Wrapper
export { TrackerClient } from "./client.ts";

// TYPES
export type {
  GeolocationData,
  AttackSession,
  ThreatAnalysis,
  TrackingResult,
  FingerprintEntry,
  CloudflareMetadata,
  EnrichedAttackEvent,
  AttackEvent,
} from "./types.ts";

// TRACKER - Intelligence Gathering
export {
  Tracker,
  TrackingEmitter,
  trackAndEmit,
  geoping,
  geopingBatch,
  isHighRiskCountry,
  inferTimezone,
  calculateDistance,
  detectImpossibleTravel,
  getRegion,
  isLikelyVPN,
  collectMacAddress,
  isLocalNetwork,
  extractMacFromIPv6,
  getVendorFromMac,
  isVirtualMachine,
} from "./tracker/mod.ts";

export type { MacAddressInfo } from "./tracker/mod.ts";

// MASK - Anti-Fingerprinting
export { Mask, createDefaultMask, maskedResponse } from "./mask/mod.ts";
export type { MaskConfig } from "./mask/mod.ts";
