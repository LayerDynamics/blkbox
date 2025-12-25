// High-level tracking API for BlkBox

import type { TrackerClient } from "../client.ts";
import type { AttackEvent } from "../../../lib_deno/types.ts";
import type {
  AttackSession,
  GeolocationData,
  ThreatAnalysis,
  TrackingResult,
} from "../types.ts";

/**
 * High-level tracker for coordinating all tracking operations
 *
 * Usage:
 * ```typescript
 * const blkbox = new BlkBoxFFI();
 * const tracker = new Tracker(blkbox.getTrackerClient());
 *
 * // Track an attack event
 * const result = await tracker.trackAttack(event);
 * console.log(`Threat Level: ${result.threat_analysis.score}/10`);
 * console.log(`Action: ${result.recommended_action}`);
 * ```
 */
export class Tracker {
  constructor(private client: TrackerClient) {}

  /**
   * Track an attack event and return comprehensive analysis
   *
   * @param event - Attack event to track
   * @returns Complete tracking result with geolocation, session, and threat analysis
   */
  async trackAttack(event: AttackEvent): Promise<TrackingResult> {
    // 1. Geolocate the source IP
    const geo = this.client.geolocateIp(event.source_ip);

    // 2. Get or create session for this IP
    const sessions = this.client.getIpSessions(event.source_ip);
    const session = sessions.length > 0 ? sessions[0] : null;

    // 3. Analyze threat level
    const threatAnalysis = this.analyzeThreat(event, sessions);

    // 4. Determine recommended action
    const recommendedAction = this.determineAction(threatAnalysis);

    return {
      geolocation: geo,
      session: session,
      threat_analysis: threatAnalysis,
      recommended_action: recommendedAction,
    };
  }

  /**
   * Analyze threat level based on attack characteristics and session history
   *
   * @param event - Current attack event
   * @param sessions - Attack sessions for this IP
   * @returns Threat analysis with score and recommendations
   */
  private analyzeThreat(
    event: AttackEvent,
    sessions: AttackSession[],
  ): ThreatAnalysis {
    let score = event.threat_level;
    const factors: string[] = [];

    // Base threat from event
    factors.push(`Base threat: ${event.threat_level}/10`);

    // Repeat attacker detection
    const isRepeat = sessions.length > 0 && sessions[0].attack_count > 1;
    if (isRepeat) {
      score += 1;
      factors.push(
        `Repeat attacker (${sessions[0].attack_count} attacks)`,
      );
    }

    // Threat escalation detection
    const isEscalating = sessions.length > 0 && sessions[0].threat_escalation;
    if (isEscalating) {
      score += 2;
      factors.push("Threat escalation detected");
    }

    // Multi-protocol attacks
    if (sessions.length > 0 && sessions[0].protocol_count > 1) {
      score += 1;
      factors.push(
        `Multi-protocol attack (${sessions[0].protocol_count} protocols)`,
      );
    }

    // High persistence score
    if (sessions.length > 0 && sessions[0].persistence_score > 0.7) {
      score += 1;
      factors.push(
        `High persistence (${sessions[0].persistence_score.toFixed(2)})`,
      );
    }

    // Tool detection
    if (event.metadata?.includes("tool_detected")) {
      score += 1;
      factors.push("Known attack tool detected");
    }

    // Cap score at 10
    score = Math.min(score, 10);

    // Determine threat level
    let level: "low" | "medium" | "high" | "critical";
    if (score <= 3) {
      level = "low";
    } else if (score <= 6) {
      level = "medium";
    } else if (score <= 8) {
      level = "high";
    } else {
      level = "critical";
    }

    return {
      score,
      level,
      factors,
      is_repeat_attacker: isRepeat,
      is_escalating: isEscalating,
      recommended_action: this.scoreToAction(score),
    };
  }

  /**
   * Determine recommended action based on threat analysis
   *
   * @param analysis - Threat analysis result
   * @returns Recommended action
   */
  private determineAction(
    analysis: ThreatAnalysis,
  ): "log" | "alert" | "block" | "strikeback" {
    if (analysis.score >= 9) {
      return "strikeback";
    } else if (analysis.score >= 7) {
      return "block";
    } else if (analysis.score >= 5) {
      return "alert";
    } else {
      return "log";
    }
  }

  /**
   * Convert threat score to action
   *
   * @param score - Threat score (0-10)
   * @returns Recommended action
   */
  private scoreToAction(
    score: number,
  ): "log" | "alert" | "block" | "strikeback" {
    if (score >= 9) return "strikeback";
    if (score >= 7) return "block";
    if (score >= 5) return "alert";
    return "log";
  }

  /**
   * Get attacker profile for an IP address
   *
   * @param ipAddress - IP address to profile
   * @returns Attacker profile with geolocation and session data
   */
  async getAttackerProfile(ipAddress: string): Promise<{
    ip: string;
    geolocation: GeolocationData | null;
    sessions: AttackSession[];
    stats: ReturnType<TrackerClient["getSessionStats"]>;
    threat_level: "low" | "medium" | "high" | "critical";
  }> {
    const geo = this.client.geolocateIp(ipAddress);
    const sessions = this.client.getIpSessions(ipAddress);
    const stats = this.client.getSessionStats(ipAddress);

    let threat_level: "low" | "medium" | "high" | "critical" = "low";
    if (stats && stats.max_threat_level >= 9) {
      threat_level = "critical";
    } else if (stats && stats.max_threat_level >= 7) {
      threat_level = "high";
    } else if (stats && stats.max_threat_level >= 5) {
      threat_level = "medium";
    }

    return {
      ip: ipAddress,
      geolocation: geo,
      sessions,
      stats,
      threat_level,
    };
  }

  /**
   * Get top attackers by threat level
   *
   * @param limit - Maximum number of attackers to return
   * @returns Array of top attackers with their profiles
   */
  async getTopAttackers(limit: number): Promise<Array<{
    ip: string;
    total_attacks: number;
    threat_level: number;
    country?: string;
  }>> {
    // Get enriched attacks
    const enriched = this.client.getEnrichedAttacks(1000, 0);

    // Group by IP and aggregate
    const ipMap = new Map<string, {
      attacks: number;
      maxThreat: number;
      country?: string;
    }>();

    for (const item of enriched) {
      const ip = item.attack.source_ip;
      const existing = ipMap.get(ip);

      if (existing) {
        existing.attacks++;
        existing.maxThreat = Math.max(
          existing.maxThreat,
          item.attack.threat_level,
        );
      } else {
        ipMap.set(ip, {
          attacks: 1,
          maxThreat: item.attack.threat_level,
          country: item.geolocation?.country_code,
        });
      }
    }

    // Convert to array and sort by threat level
    const attackers = Array.from(ipMap.entries())
      .map(([ip, data]) => ({
        ip,
        total_attacks: data.attacks,
        threat_level: data.maxThreat,
        country: data.country,
      }))
      .sort((a, b) => b.threat_level - a.threat_level)
      .slice(0, limit);

    return attackers;
  }
}
