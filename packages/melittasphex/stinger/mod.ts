/**
 * Stinger Module - Strike-Back Orchestration
 *
 * The Stinger module implements BlkBox's strike-back capabilities, providing
 * automated payload deployment with comprehensive safeguards.
 *
 * ## Components
 *
 * - **StingerService**: Main orchestration service that makes deployment decisions
 * - **PayloadManager**: Manages active payloads and intelligence gathering
 * - **ResponseModifier**: Injects payloads into protocol responses
 *
 * ## Usage
 *
 * ```typescript
 * import { StingerService } from "./packages/melittasphex/stinger/mod.ts";
 * import type { StingerConfig } from "./packages/melittasphex/stinger/mod.ts";
 *
 * const config: StingerConfig = {
 *   enabled: true,
 *   autoTrigger: false,
 *   threatThreshold: 7.5,
 *   minAttackCount: 3,
 *   dryRun: true,
 *   requireApproval: true,
 *   allowedPayloads: ["system_info", "browser_recon"],
 *   prohibitedPayloads: ["log_wiper"],
 *   whitelistIps: [],
 *   whitelistCidrs: ["10.0.0.0/8"],
 *   allowedCountries: [],
 *   prohibitedCountries: ["US"],
 *   payloadExpirationHours: 24,
 *   maxCallbacksPerPayload: 100,
 *   c2Port: 8443,
 *   c2UseTls: false,
 *   legal: {
 *     counselConsulted: true,
 *     authorizationOnFile: true,
 *     jurisdiction: "EU",
 *     warningBannerEnabled: true
 *   }
 * };
 *
 * const stinger = new StingerService(ffi, config);
 *
 * // Process attack and decide on deployment
 * const decision = await stinger.processAttack(attackEvent);
 *
 * if (decision?.decision === "approve") {
 *   console.log("Payload deployed automatically");
 * } else if (decision?.decision === "queue") {
 *   console.log("Awaiting manual approval");
 *   const pending = stinger.getPendingApprovals();
 *   // Later: approve manually
 *   await stinger.approvePendingDeployment(pending[0].deploymentId, "admin");
 * }
 * ```
 *
 * ## Safeguards
 *
 * The Stinger module includes multiple safety mechanisms:
 *
 * 1. **Whitelist Protection**: Never deploy to whitelisted IPs or CIDRs
 * 2. **Legitimate Scanner Detection**: Blocks Shodan, Censys, Googlebot, etc.
 * 3. **Geofencing**: Allow/block based on country codes
 * 4. **Minimum Threshold**: Requires minimum attack count before deployment
 * 5. **Payload Restrictions**: Configurable allow/deny lists for payload types
 * 6. **Manual Approval**: High-risk payloads require human authorization
 * 7. **Dry Run Mode**: Test without actual deployment
 * 8. **Legal Framework**: Requires legal review and authorization
 *
 * ## Architecture
 *
 * ```
 * Attack Event
 *      ↓
 * StingerService.processAttack()
 *      ↓
 * Threat Assessment
 *      ↓
 * Safeguard Checks
 *      ↓
 * Decision: approve/queue/deny
 *      ↓
 * CookiejarClient.generatePayload()
 *      ↓
 * ResponseModifier.inject()
 *      ↓
 * Payload Delivered
 * ```
 */

// ========================================
// STINGER SERVICE - Main orchestration
// ========================================
export {
  StingerService,
  type StingerConfig,
  type DeploymentDecision,
  type SafeguardResults,
  type DeploymentRecord,
} from "./stinger_service.ts";

// ========================================
// PAYLOAD MANAGEMENT - Types and utilities
// ========================================
export {
  PayloadManager,
  PayloadStatus,
  ObfuscationLevel,
  IntelligenceDataType,
  RiskLevel,
  recommendPayloadType,
  validatePayloadConfig,
  recommendObfuscationLevel,
  type PayloadMetadata,
  type PayloadGenerationConfig,
  type PayloadIntelligence,
  type C2CallbackData,
  type PayloadRecommendation,
  type PayloadValidation,
  type TemplateVariables,
  type PayloadStatistics,
} from "./payload.ts";

// ========================================
// RESPONSE MODIFICATION - Payload injection
// ========================================
export {
  ResponseModifier,
  BatchModifier,
  InjectionStrategy,
  type InjectionResult,
  type InjectionConfig,
} from "./modifier.ts";

// ========================================
// CONVENIENCE EXPORTS
// ========================================

/**
 * Quick setup function for standard Stinger configuration
 */
export function createStingerConfig(overrides?: Partial<import("./stinger_service.ts").StingerConfig>): import("./stinger_service.ts").StingerConfig {
  const defaults: import("./stinger_service.ts").StingerConfig = {
    enabled: false, // Disabled by default for safety
    autoTrigger: false, // Manual triggering by default
    threatThreshold: 7.5, // Require high threat score
    minAttackCount: 3, // Require at least 3 attacks
    dryRun: true, // Dry run mode by default
    requireApproval: true, // Require manual approval
    allowedPayloads: [
      "system_info",
      "browser_recon",
      "beacon",
    ], // Only low-risk payloads
    prohibitedPayloads: [
      "log_wiper", // Always prohibited
    ],
    whitelistIps: [], // No whitelisted IPs by default
    whitelistCidrs: [
      "10.0.0.0/8",
      "172.16.0.0/12",
      "192.168.0.0/16",
    ], // RFC1918 private networks
    allowedCountries: [], // All countries allowed by default
    prohibitedCountries: [], // No prohibited countries by default
    payloadExpirationHours: 24, // 24 hour expiration
    maxCallbacksPerPayload: 100, // Max 100 callbacks
    c2Port: 8443, // C2 on port 8443
    c2UseTls: false, // No TLS by default (use reverse proxy)
    legal: {
      counselConsulted: false, // MUST be set to true manually
      authorizationOnFile: false, // MUST be set to true manually
      jurisdiction: "",
      warningBannerEnabled: true,
    },
  };

  return { ...defaults, ...overrides };
}

/**
 * Validate Stinger configuration
 */
export function validateStingerConfig(
  config: import("./stinger_service.ts").StingerConfig,
): { valid: boolean; errors: string[]; warnings: string[] } {
  const errors: string[] = [];
  const warnings: string[] = [];

  // Legal checks
  if (config.enabled && !config.dryRun) {
    if (!config.legal.counselConsulted) {
      errors.push("Legal counsel must be consulted before enabling strike-back");
    }
    if (!config.legal.authorizationOnFile) {
      errors.push("Written authorization must be on file before enabling strike-back");
    }
    if (!config.legal.jurisdiction) {
      errors.push("Jurisdiction must be specified");
    }
  }

  // Safety checks
  if (config.enabled && !config.requireApproval) {
    warnings.push("Auto-approval is enabled - high risk");
  }

  if (config.enabled && config.autoTrigger) {
    warnings.push("Auto-trigger is enabled - payloads will deploy automatically");
  }

  if (config.threatThreshold < 5.0) {
    warnings.push("Threat threshold is low - may deploy to low-risk targets");
  }

  if (config.minAttackCount < 3) {
    warnings.push("Minimum attack count is low - may deploy after single attack");
  }

  // Payload checks
  if (config.allowedPayloads.includes("log_wiper")) {
    errors.push("LogWiper payload is prohibited and cannot be allowed");
  }

  const highRiskPayloads = ["reverse_tcp", "command_injection", "file_exfiltration"];
  const hasHighRisk = highRiskPayloads.some((p) =>
    config.allowedPayloads.includes(p)
  );
  if (hasHighRisk && !config.requireApproval) {
    warnings.push(
      "High-risk payloads are allowed without approval requirement",
    );
  }

  // Network checks
  if (config.whitelistCidrs.length === 0) {
    warnings.push("No CIDR whitelist - may deploy to internal networks");
  }

  // Expiration checks
  if (config.payloadExpirationHours > 168) {
    // 7 days
    warnings.push("Payload expiration exceeds 7 days - consider shorter duration");
  }

  if (config.maxCallbacksPerPayload > 500) {
    warnings.push("Max callbacks is very high - consider lower limit");
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
  };
}

/**
 * Check if Stinger is ready for production use
 */
export function isProductionReady(
  config: import("./stinger_service.ts").StingerConfig,
): { ready: boolean; reason?: string } {
  const validation = validateStingerConfig(config);

  if (!validation.valid) {
    return {
      ready: false,
      reason: `Configuration errors: ${validation.errors.join(", ")}`,
    };
  }

  if (!config.legal.counselConsulted) {
    return {
      ready: false,
      reason: "Legal counsel must be consulted",
    };
  }

  if (!config.legal.authorizationOnFile) {
    return {
      ready: false,
      reason: "Written authorization must be on file",
    };
  }

  if (config.dryRun) {
    return {
      ready: false,
      reason: "Dry run mode is enabled - disable for production",
    };
  }

  return { ready: true };
}
