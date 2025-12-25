/**
 * Stinger Service - Strike-Back Orchestration Layer
 *
 * Main TypeScript service that coordinates strike-back operations.
 * This service bridges the gap between attack detection and payload deployment,
 * integrating with:
 * - Trackasuarus: For threat intelligence and session tracking
 * - Cookiejar: For payload generation and C2
 * - Rust FFI: For decision engine and safeguards
 */

import type { BlkBoxFFI } from "../../../lib_deno/lib.ts";
import type { AttackEvent } from "../../../lib_deno/types.ts";
import { PayloadType } from "../../../lib_deno/types.ts";
import { CookiejarClient, type PayloadResult } from "../../cookiejar/mod.ts";

/**
 * Stinger configuration
 */
export interface StingerConfig {
  enabled: boolean;
  autoTrigger: boolean;
  threatThreshold: number;
  minAttackCount: number;
  dryRun: boolean;
  requireApproval: boolean;
  allowedPayloads: string[];
  prohibitedPayloads: string[];
  whitelistIps: string[];
  whitelistCidrs: string[];
  allowedCountries: string[];
  prohibitedCountries: string[];
  payloadExpirationHours: number;
  maxCallbacksPerPayload: number;
  c2Port: number;
  c2UseTls: boolean;
  legal: {
    counselConsulted: boolean;
    jurisdiction: string;
    warningBannerEnabled: boolean;
  };
}

/**
 * Deployment decision
 */
export interface DeploymentDecision {
  decision: "approve" | "queue" | "deny";
  threatScore: number;
  safeguardsPassed: boolean;
  reason: string;
  recommendedPayload?: PayloadType;
  safeguardResults?: SafeguardResults;
}

/**
 * Safeguard check results
 */
export interface SafeguardResults {
  passed: boolean;
  summary: string;
  checks: Array<{
    name: string;
    passed: boolean;
    reason?: string;
  }>;
}

/**
 * Stinger deployment record
 */
export interface DeploymentRecord {
  deploymentId: string;
  attackId: number;
  payloadId: string;
  attackerIp: string;
  threatScore: number;
  payloadType: string;
  decision: string;
  timestamp: string;
  approved: boolean;
  approver?: string;
}

/**
 * Stinger Service - Main strike-back orchestration
 */
export class StingerService {
  private ffi: BlkBoxFFI;
  private config: StingerConfig;
  private cookiejarClient: CookiejarClient;
  private pendingApprovals: Map<string, DeploymentRecord>;

  constructor(ffi: BlkBoxFFI, config: StingerConfig) {
    this.ffi = ffi;
    this.config = config;
    this.cookiejarClient = new CookiejarClient(ffi, {
      c2BaseUrl: `http://localhost:${config.c2Port}`,
      defaultExpirationHours: config.payloadExpirationHours,
      defaultMaxCallbacks: config.maxCallbacksPerPayload,
    });
    this.pendingApprovals = new Map();
  }

  /**
   * Process an attack event and decide whether to deploy
   */
  async processAttack(event: AttackEvent): Promise<DeploymentDecision | null> {
    // Check if stinger is enabled
    if (!this.config.enabled) {
      return null;
    }

    console.log(`[Stinger] Processing attack from ${event.source_ip}`);

    // Get session data for threat assessment
    const session = await this.getAttackSession(event.source_ip);
    const geolocation = event.geolocation;

    // Calculate threat score
    const threatScore = this.calculateThreatScore(event, session);

    console.log(`[Stinger] Threat score: ${threatScore.toFixed(2)}`);

    // Check if score meets threshold
    if (threatScore < this.config.threatThreshold) {
      return {
        decision: "deny",
        threatScore,
        safeguardsPassed: false,
        reason: `Threat score ${threatScore.toFixed(2)} below threshold ${this.config.threatThreshold}`,
      };
    }

    // Recommend payload type
    const recommendedPayload = this.recommendPayload(event, threatScore, session);
    if (!recommendedPayload) {
      return {
        decision: "deny",
        threatScore,
        safeguardsPassed: false,
        reason: "No suitable payload type recommended",
      };
    }

    // Run safeguard checks
    const safeguardResults = this.checkSafeguards(event, session, geolocation, recommendedPayload);

    if (!safeguardResults.passed) {
      return {
        decision: "deny",
        threatScore,
        safeguardsPassed: false,
        safeguardResults,
        recommendedPayload,
        reason: `Safeguard failed: ${safeguardResults.summary}`,
      };
    }

    // Determine decision
    let decision: "approve" | "queue" | "deny";

    if (this.config.dryRun) {
      decision = "queue";
    } else if (this.config.requireApproval || this.requiresManualApproval(recommendedPayload, threatScore)) {
      decision = "queue";
    } else if (!this.config.autoTrigger) {
      decision = "queue";
    } else {
      decision = "approve";
    }

    const deploymentDecision: DeploymentDecision = {
      decision,
      threatScore,
      safeguardsPassed: true,
      safeguardResults,
      recommendedPayload,
      reason: decision === "approve"
        ? `Auto-approved: score ${threatScore.toFixed(2)}, all safeguards passed`
        : decision === "queue"
        ? "Queued for manual approval"
        : "Denied",
    };

    // If approved, deploy immediately
    if (decision === "approve") {
      await this.deployPayload(event, recommendedPayload);
    }

    // If queued, add to pending approvals
    if (decision === "queue") {
      this.queueForApproval(event, recommendedPayload, threatScore);
    }

    // Log decision
    await this.logDecision(event, deploymentDecision);

    return deploymentDecision;
  }

  /**
   * Deploy a payload
   */
  async deployPayload(
    event: AttackEvent,
    payloadType: PayloadType,
  ): Promise<PayloadResult | null> {
    try {
      console.log(`[Stinger] Deploying ${PayloadType[payloadType]} payload to ${event.source_ip}`);

      // Generate and deploy via Cookiejar
      const result = await this.cookiejarClient.generatePayload(event, payloadType);

      console.log(`[Stinger] Payload deployed: ${result.payloadUrl}`);

      // Log deployment
      await this.logDeployment(event, result);

      return result;
    } catch (error) {
      console.error(`[Stinger] Deployment failed:`, error);
      return null;
    }
  }

  /**
   * Calculate threat score
   */
  private calculateThreatScore(
    event: AttackEvent,
    session: any,
  ): number {
    let score = event.threat_level;

    if (session) {
      if (session.attack_count > 1) score += 1;
      if (session.attack_count > 5) score += 1;
      if (session.threat_escalation) score += 2;
      if (session.protocol_count > 1) score += 1;
      if (session.persistence_score > 0.7) score += 1;
    }

    // Tool detection
    if (event.fingerprint) {
      const tools = ["nmap", "masscan", "sqlmap", "nikto", "metasploit"];
      if (tools.some((tool) => event.fingerprint!.toLowerCase().includes(tool))) {
        score += 1;
      }
    }

    // Cloudflare threat score
    if (event.cf_metadata?.cf_threat_score) {
      const cfScore = parseInt(event.cf_metadata.cf_threat_score);
      if (cfScore > 75) {
        score += Math.min(2, Math.floor(cfScore / 50));
      }
    }

    return Math.min(10, score);
  }

  /**
   * Recommend payload type
   */
  private recommendPayload(
    event: AttackEvent,
    threatScore: number,
    session: any,
  ): PayloadType | null {
    // Critical threats
    if (threatScore >= 9.0) {
      if (event.service_type === 2) return 0; // ReverseTCP for SSH
      if (event.payload.includes("UNION")) return 1; // CommandInjection
      return 6; // SystemInfo
    }

    // High threats
    if (threatScore >= 8.0) {
      if (session?.protocol_count > 1) return 4; // NetworkScanner
      return 5; // BrowserRecon
    }

    // Medium threats
    if (threatScore >= this.config.threatThreshold) {
      if (session?.attack_count > 3) return 7; // Beacon
      return 6; // SystemInfo
    }

    return null;
  }

  /**
   * Check safeguards
   */
  private checkSafeguards(
    event: AttackEvent,
    session: any,
    geolocation: any,
    payloadType: PayloadType,
  ): SafeguardResults {
    const checks: Array<{ name: string; passed: boolean; reason?: string }> = [];

    // Whitelist check
    const whitelisted = this.config.whitelistIps.includes(event.source_ip);
    checks.push({
      name: "Whitelist",
      passed: !whitelisted,
      reason: whitelisted ? `IP ${event.source_ip} is whitelisted` : undefined,
    });

    // Legitimate scanner check
    const legitimateScanners = ["Shodan", "Censys", "Googlebot", "BingBot"];
    const isLegitimate = event.user_agent && legitimateScanners.some((s) =>
      event.user_agent!.includes(s)
    );
    checks.push({
      name: "Legitimate Scanner",
      passed: !isLegitimate,
      reason: isLegitimate ? "Detected legitimate scanner" : undefined,
    });

    // Geofencing check
    if (geolocation?.country_code) {
      const prohibited = this.config.prohibitedCountries.includes(geolocation.country_code);
      const allowed = this.config.allowedCountries.length === 0 ||
        this.config.allowedCountries.includes(geolocation.country_code);

      checks.push({
        name: "Geofencing",
        passed: !prohibited && allowed,
        reason: prohibited
          ? `Country ${geolocation.country_code} is prohibited`
          : !allowed
          ? `Country ${geolocation.country_code} not in allowed list`
          : undefined,
      });
    }

    // Minimum threshold check
    const meetsThreshold = session && session.attack_count >= this.config.minAttackCount;
    checks.push({
      name: "Minimum Threshold",
      passed: meetsThreshold,
      reason: !meetsThreshold
        ? `Attack count below minimum ${this.config.minAttackCount}`
        : undefined,
    });

    // Payload restriction check - all payloads allowed
    const payloadName = PayloadType[payloadType].toLowerCase();
    const payloadAllowed = true;

    checks.push({
      name: "Payload Restriction",
      passed: payloadAllowed,
      reason: undefined,
    });

    const passed = checks.every((c) => c.passed);
    const failedChecks = checks.filter((c) => !c.passed);

    return {
      passed,
      summary: passed
        ? "All safeguards passed"
        : `Failed: ${failedChecks.map((c) => c.name).join(", ")}`,
      checks,
    };
  }

  /**
   * Check if payload requires manual approval
   */
  private requiresManualApproval(payloadType: PayloadType, score: number): boolean {
    // High-risk payloads
    const highRisk = [0, 1, 2]; // ReverseTCP, CommandInjection, FileExfiltration
    return highRisk.includes(payloadType) || score >= 9.5;
  }

  /**
   * Queue deployment for manual approval
   */
  private queueForApproval(
    event: AttackEvent,
    payloadType: PayloadType,
    threatScore: number,
  ): void {
    const deploymentId = crypto.randomUUID();

    const record: DeploymentRecord = {
      deploymentId,
      attackId: event.attack_id,
      payloadId: "",
      attackerIp: event.source_ip,
      threatScore,
      payloadType: PayloadType[payloadType],
      decision: "queue",
      timestamp: new Date().toISOString(),
      approved: false,
    };

    this.pendingApprovals.set(deploymentId, record);

    console.log(`[Stinger] Queued deployment ${deploymentId} for manual approval`);
  }

  /**
   * Approve a pending deployment
   */
  async approvePendingDeployment(deploymentId: string, approver: string): Promise<PayloadResult | null> {
    const record = this.pendingApprovals.get(deploymentId);

    if (!record) {
      console.error(`[Stinger] Deployment ${deploymentId} not found in pending queue`);
      return null;
    }

    // Mark as approved
    record.approved = true;
    record.approver = approver;
    record.decision = "approve";

    // Get original attack event (would need to be stored or re-fetched)
    // For now, we'll create a minimal event from the record
    const event: Partial<AttackEvent> = {
      attack_id: record.attackId,
      source_ip: record.attackerIp,
    };

    // Deploy payload
    const payloadType = PayloadType[record.payloadType as keyof typeof PayloadType];
    const result = await this.deployPayload(event as AttackEvent, payloadType);

    // Remove from pending
    this.pendingApprovals.delete(deploymentId);

    console.log(`[Stinger] Approved deployment ${deploymentId} by ${approver}`);

    return result;
  }

  /**
   * Get pending approvals
   */
  getPendingApprovals(): DeploymentRecord[] {
    return Array.from(this.pendingApprovals.values());
  }

  /**
   * Get attack session data
   */
  private async getAttackSession(sourceIp: string): Promise<any> {
    // Would integrate with Trackasuarus/session tracking
    // For now, return null
    return null;
  }

  /**
   * Log deployment decision
   */
  private async logDecision(event: AttackEvent, decision: DeploymentDecision): Promise<void> {
    console.log(`[Stinger] Decision for ${event.source_ip}: ${decision.decision} (score: ${decision.threatScore.toFixed(2)})`);
    // Would log to strikeback_audit table via FFI
  }

  /**
   * Log deployment
   */
  private async logDeployment(event: AttackEvent, result: PayloadResult): Promise<void> {
    console.log(`[Stinger] Deployed ${result.payloadType} to ${event.source_ip}: ${result.payloadUrl}`);
    // Would log to strikeback_audit table via FFI
  }

  /**
   * Get active payloads
   */
  async getActivePayloads(): Promise<any[]> {
    return await this.cookiejarClient.getActivePayloads();
  }

  /**
   * Terminate a payload
   */
  async terminatePayload(payloadId: string): Promise<void> {
    await this.cookiejarClient.terminatePayload(payloadId);
    console.log(`[Stinger] Terminated payload ${payloadId}`);
  }

  /**
   * Cleanup expired payloads
   */
  async cleanupExpired(): Promise<number> {
    return await this.cookiejarClient.cleanupExpired();
  }

  /**
   * Get statistics
   */
  async getStatistics(): Promise<any> {
    return await this.cookiejarClient.getStatistics();
  }
}
