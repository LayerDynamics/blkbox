// TypeScript interfaces for BlkBox tracking system
// These types match the Rust data structures exactly

import { AttackEvent } from "../../lib_deno/types.ts";

/**
 * Geolocation data for an IP address
 * Source can be Cloudflare headers, MaxMind DB, or hybrid
 */
export interface GeolocationData {
  ip: string;
  country_code?: string;
  country_name?: string;
  region?: string;
  city?: string;
  latitude?: number;
  longitude?: number;
  postal_code?: string;
  timezone?: string;
  asn?: number;
  isp?: string;
  organization?: string;
  is_anonymous_proxy: boolean;
  is_satellite_provider: boolean;
  source: "Cloudflare" | "MaxMind" | "Hybrid" | "Direct" | "Unknown";
}

/**
 * Fingerprint types supported by BlkBox
 */
export type FingerprintType =
  | "JA3"           // TLS client fingerprint
  | "JA3S"          // TLS server fingerprint
  | "Hassh"         // SSH client fingerprint
  | "HasshServer"   // SSH server fingerprint
  | "UserAgent"     // HTTP User-Agent fingerprint
  | "Canvas"        // Browser canvas fingerprint
  | "HeaderOrder"   // HTTP header order fingerprint
  | "ToolDetection"; // Attack tool detection

/**
 * A single fingerprint entry
 */
export interface FingerprintEntry {
  fingerprint_type: FingerprintType;
  value: string;
  confidence: number;  // 0.0 to 1.0
  metadata?: string;   // JSON-encoded additional data
}

/**
 * Cloudflare metadata extracted from request headers
 */
export interface CloudflareMetadata {
  cf_ray?: string;
  cf_connecting_ip?: string;
  cf_ipcountry?: string;
  cf_visitor?: string;
  cf_threat_score?: number;
  cf_request_id?: string;
  cf_colo?: string;
}

/**
 * Attack session representing correlated attacks from same source
 */
export interface AttackSession {
  id?: number;
  session_hash: string;
  source_ip: string;
  first_seen: string;  // ISO 8601 timestamp
  last_seen: string;   // ISO 8601 timestamp
  attack_count: number;
  protocol_count: number;
  protocols_used: string[];
  fingerprints: Record<string, string>;  // fingerprint_type -> value
  aggregate_threat_level: number;  // 0-10 scale
  threat_escalation: boolean;
  persistence_score: number;  // 0.0 to 1.0
  attack_ids: number[];
  geolocation?: string;  // JSON-encoded GeolocationData
}

/**
 * Enriched attack event with all tracking data
 */
export interface EnrichedAttackEvent {
  attack: AttackEvent;
  geolocation?: GeolocationData;
  fingerprints: FingerprintEntry[];
  cloudflare?: CloudflareMetadata;
  session?: AttackSession;
}

/**
 * Threat analysis result
 */
export interface ThreatAnalysis {
  score: number;  // 0-10 scale
  level: "low" | "medium" | "high" | "critical";
  factors: string[];
  is_repeat_attacker: boolean;
  is_escalating: boolean;
  recommended_action: "log" | "alert" | "block" | "strikeback";
}

/**
 * Tracking result from tracking an attack
 */
export interface TrackingResult {
  geolocation: GeolocationData | null;
  session: AttackSession | null;
  threat_analysis: ThreatAnalysis;
  recommended_action: "log" | "alert" | "block" | "strikeback";
}
