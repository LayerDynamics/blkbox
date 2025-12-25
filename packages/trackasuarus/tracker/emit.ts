import { Tracker } from "./track.ts";
import { TrackerClient } from "../client.ts";
import type { AttackEvent } from "../types.ts";

/**
 * TrackingEmitter
 *
 * Bridges the Tracker intelligence layer with the event-pipeline.
 * Converts TrackingResult into a format suitable for event processing.
 */
export class TrackingEmitter {
  private tracker: Tracker;

  constructor(client: TrackerClient) {
    this.tracker = new Tracker(client);
  }

  /**
   * Emit tracking data for event pipeline
   *
   * This method:
   * 1. Tracks the attack using the Tracker
   * 2. Extracts relevant tracking data
   * 3. Returns a normalized format for event-pipeline.ts
   */
  async emitTracking(event: AttackEvent) {
    const result = await this.tracker.trackAttack(event);

    return {
      // Session tracking
      session_id: result.session?.session_hash || `session_${event.source_ip}_${Date.now()}`,
      attack_count: result.session?.attack_count || 1,
      is_new_session: !result.session || result.session.attack_count === 1,
      threat_escalation: result.session?.threat_escalation || false,
      protocol_count: result.session?.protocol_count || 1,
      persistence_score: (result.session?.persistence_score || 0) / 100,

      // Fingerprinting
      fingerprints: Object.values(result.session?.fingerprints || {}),

      // Geolocation
      geolocation: result.geolocation,

      // Threat analysis
      threat_level: result.threat_analysis.score,
      threat_category: result.threat_analysis.category,
      recommended_action: result.threat_analysis.recommended_action,
    };
  }

  /**
   * Get attacker profile (for advanced analysis)
   */
  async getAttackerProfile(ip: string) {
    return await this.tracker.getAttackerProfile(ip);
  }

  /**
   * Get top attackers (for dashboard/reporting)
   */
  async getTopAttackers(limit = 10) {
    return await this.tracker.getTopAttackers(limit);
  }
}

/**
 * Convenience function for one-off tracking emissions
 */
export async function trackAndEmit(event: AttackEvent, client: TrackerClient) {
  const emitter = new TrackingEmitter(client);
  return await emitter.emitTracking(event);
}
