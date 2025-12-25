/**
 * Event Pipeline - Middleware-style Event Processing
 *
 * The event pipeline processes attack events through a series of processors:
 * 1. Ingestion: Validate and normalize the event
 * 2. Tracking: Track attacker session, fingerprints, patterns (Trackasuarus)
 * 3. Decision: Evaluate threat and decide on strike-back (Stinger)
 * 4. Action: Execute decisions (deploy payloads, update firewall, etc.)
 * 5. Storage: Persist event and metadata to database
 *
 * Each processor can:
 * - Enrich the event context
 * - Make decisions
 * - Trigger actions
 * - Short-circuit the pipeline if needed
 */

import type { AttackEvent } from "../../lib_deno/types.ts";
import { BlkBoxFFI } from "../../lib_deno/lib.ts";
import { TrackerClient, TrackingEmitter } from "../../packages/trackasuarus/mod.ts";
import type { StingerService, DeploymentDecision } from "../../packages/melittasphex/stinger/stinger_service.ts";

/**
 * Event context - carries data through the pipeline
 */
export interface EventContext {
  event: AttackEvent;
  timestamp: Date;

  // Tracking data (from Trackasuarus)
  tracking?: {
    session_id?: string;
    attack_count: number;
    is_new_session: boolean;
    threat_escalation: boolean;
    protocol_count: number;
    persistence_score: number;
    fingerprints: string[];
  };

  // Decision data (from Stinger)
  decision?: DeploymentDecision;

  // Actions taken
  actions: string[];

  // Additional metadata
  metadata: Record<string, any>;

  // Pipeline control
  shouldContinue: boolean;
}

/**
 * Event processor interface
 */
export interface EventProcessor {
  name: string;
  process(event: AttackEvent, context: EventContext): Promise<EventContext>;
}

/**
 * Event Pipeline - Orchestrates event processing
 */
export class EventPipeline {
  private processors: EventProcessor[] = [];

  constructor() {
    // Processors will be added via addProcessor()
  }

  /**
   * Add a processor to the pipeline
   */
  addProcessor(processor: EventProcessor): void {
    this.processors.push(processor);
    console.log(`[EventPipeline] Registered processor: ${processor.name}`);
  }

  /**
   * Process an attack event through the pipeline
   */
  async process(event: AttackEvent): Promise<EventContext> {
    // Initialize context
    let context: EventContext = {
      event,
      timestamp: new Date(),
      actions: [],
      metadata: {},
      shouldContinue: true
    };

    // Run through processors
    for (const processor of this.processors) {
      if (!context.shouldContinue) {
        console.log(`[EventPipeline] Pipeline short-circuited at ${processor.name}`);
        break;
      }

      try {
        context = await processor.process(event, context);
      } catch (error) {
        console.error(`[EventPipeline] Processor ${processor.name} failed:`, error);
        context.metadata[`${processor.name}_error`] = String(error);
        // Continue processing despite error
      }
    }

    return context;
  }

  /**
   * Get list of registered processors
   */
  getProcessors(): string[] {
    return this.processors.map(p => p.name);
  }
}

/**
 * Ingestion Processor - Validates and normalizes events
 */
export class IngestionProcessor implements EventProcessor {
  name = "ingestion";

  async process(event: AttackEvent, context: EventContext): Promise<EventContext> {
    // Validate event
    if (!event.source_ip || !event.timestamp) {
      console.warn(`[${this.name}] Invalid event: missing required fields`);
      context.shouldContinue = false;
      return context;
    }

    // Normalize threat level
    if (event.threat_level < 0) event.threat_level = 0;
    if (event.threat_level > 10) event.threat_level = 10;

    // Add metadata
    context.metadata.ingestion_time = new Date().toISOString();
    context.metadata.source_port = event.source_port;

    return context;
  }
}

/**
 * Tracking Processor - Tracks attackers and sessions
 */
export class TrackingProcessor implements EventProcessor {
  name = "tracking";
  private emitter: TrackingEmitter;

  constructor(ffi: BlkBoxFFI) {
    const client = new TrackerClient(ffi.runtime, ffi.lib);
    this.emitter = new TrackingEmitter(client);
  }

  async process(event: AttackEvent, context: EventContext): Promise<EventContext> {
    try {
      // Use real Trackasuarus tracking
      const tracking = await this.emitter.emitTracking(event);
      context.tracking = tracking;
      context.metadata.tracking_complete = true;
    } catch (error) {
      console.error("Tracking processor failed:", error);
      // Fallback to minimal tracking on error
      context.tracking = {
        session_id: `session_${event.source_ip}_${Date.now()}`,
        attack_count: 1,
        is_new_session: true,
        threat_escalation: false,
        protocol_count: 1,
        persistence_score: 0.1,
        fingerprints: event.fingerprint ? [event.fingerprint] : [],
        geolocation: null,
        threat_level: event.threat_level,
        threat_category: "unknown",
        recommended_action: "log",
      };
      context.metadata.tracking_error = String(error);
    }

    return context;
  }
}

/**
 * Decision Processor - Evaluates threat and decides on response
 */
export class DecisionProcessor implements EventProcessor {
  name = "decision";

  constructor(private stingerService?: StingerService) {}

  async process(event: AttackEvent, context: EventContext): Promise<EventContext> {
    if (!this.stingerService) {
      // No stinger service, skip decision
      return context;
    }

    if (!context.tracking) {
      console.warn(`[${this.name}] No tracking data available, skipping decision`);
      return context;
    }

    // Evaluate threat and decide on strike-back
    try {
      const decision = await this.stingerService.processAttack(event);

      if (decision) {
        context.decision = decision;
        context.metadata.decision_made = true;
        context.metadata.decision_type = decision.decision;
        context.metadata.threat_score = decision.threatScore;
      }
    } catch (error) {
      console.error(`[${this.name}] Decision failed:`, error);
    }

    return context;
  }
}

/**
 * Action Processor - Executes decisions
 */
export class ActionProcessor implements EventProcessor {
  name = "action";

  constructor(private stingerService?: StingerService) {}

  async process(event: AttackEvent, context: EventContext): Promise<EventContext> {
    if (!context.decision) {
      // No decision to act on
      return context;
    }

    const decision = context.decision;

    // Handle approved deployments
    if (decision.decision === "approve") {
      context.actions.push("strikeback_deployed");
      console.log(`[${this.name}] ⚡ Strike-back deployed to ${event.source_ip}`);
    }

    // Handle queued deployments
    if (decision.decision === "queue") {
      context.actions.push("strikeback_queued");
      console.log(`[${this.name}] 📋 Strike-back queued for approval`);
    }

    // Handle denied deployments
    if (decision.decision === "deny") {
      context.actions.push("strikeback_denied");
      console.log(`[${this.name}] 🚫 Strike-back denied: ${decision.reason}`);
    }

    context.metadata.actions_executed = context.actions.length;

    return context;
  }
}

/**
 * Storage Processor - Persists event and context to database
 */
export class StorageProcessor implements EventProcessor {
  name = "storage";

  async process(event: AttackEvent, context: EventContext): Promise<EventContext> {
    // In real implementation, this would call FFI to store in database
    // For now, we'll just log

    console.log(`[${this.name}] Storing event from ${event.source_ip}`);

    // Would call: await ffi.storeAttackEvent(event, context.tracking, context.decision);

    context.metadata.stored = true;
    context.metadata.storage_time = new Date().toISOString();

    return context;
  }
}

/**
 * Cloudflare Processor - Updates Cloudflare firewall rules
 */
export class CloudflareProcessor implements EventProcessor {
  name = "cloudflare";

  constructor(
    private enabled: boolean = false,
    private threatThreshold: number = 8.0
  ) {}

  async process(event: AttackEvent, context: EventContext): Promise<EventContext> {
    if (!this.enabled) {
      return context;
    }

    // Check if threat level warrants Cloudflare blocking
    const threatScore = context.decision?.threatScore || event.threat_level;

    if (threatScore >= this.threatThreshold) {
      console.log(`[${this.name}] 🛡️  Adding ${event.source_ip} to Cloudflare firewall`);

      // In real implementation, would call Cloudflare API
      // await cloudflare.blockIp(event.source_ip, duration);

      context.actions.push("cloudflare_blocked");
      context.metadata.cloudflare_blocked = true;
    }

    return context;
  }
}

/**
 * Logging Processor - Logs events for debugging
 */
export class LoggingProcessor implements EventProcessor {
  name = "logging";

  constructor(private logLevel: "debug" | "info" | "warn" | "error" = "info") {}

  async process(event: AttackEvent, context: EventContext): Promise<EventContext> {
    if (this.logLevel === "debug") {
      console.log(`[${this.name}] Event:`, {
        source_ip: event.source_ip,
        service_type: event.service_type,
        threat_level: event.threat_level,
        tracking: context.tracking,
        decision: context.decision?.decision,
        actions: context.actions
      });
    } else if (this.logLevel === "info") {
      const timestamp = new Date(event.timestamp).toLocaleString();
      console.log(
        `[${timestamp}] ${event.source_ip} → ${event.service_type} ` +
        `(threat: ${event.threat_level}) → ${context.actions.join(", ") || "no action"}`
      );
    }

    return context;
  }
}

/**
 * Rate Limiting Processor - Prevents processing flood
 */
export class RateLimitingProcessor implements EventProcessor {
  name = "rate_limiting";
  private ipCounters: Map<string, { count: number; resetTime: number }> = new Map();
  private maxRequestsPerMinute: number;

  constructor(maxRequestsPerMinute: number = 60) {
    this.maxRequestsPerMinute = maxRequestsPerMinute;

    // Cleanup old entries every minute
    setInterval(() => this.cleanup(), 60000);
  }

  async process(event: AttackEvent, context: EventContext): Promise<EventContext> {
    const now = Date.now();
    const ip = event.source_ip;

    let counter = this.ipCounters.get(ip);

    if (!counter || now > counter.resetTime) {
      // New window
      counter = {
        count: 1,
        resetTime: now + 60000 // 1 minute from now
      };
      this.ipCounters.set(ip, counter);
    } else {
      // Increment counter
      counter.count++;
    }

    if (counter.count > this.maxRequestsPerMinute) {
      console.warn(`[${this.name}] Rate limit exceeded for ${ip} (${counter.count}/${this.maxRequestsPerMinute})`);
      context.shouldContinue = false;
      context.metadata.rate_limited = true;
    }

    return context;
  }

  private cleanup(): void {
    const now = Date.now();
    for (const [ip, counter] of this.ipCounters.entries()) {
      if (now > counter.resetTime) {
        this.ipCounters.delete(ip);
      }
    }
  }
}

/**
 * Create a standard event pipeline with all processors
 */
export function createStandardPipeline(
  stingerService?: StingerService,
  config?: {
    cloudflare?: { enabled: boolean; threatThreshold: number };
    logging?: { level: "debug" | "info" | "warn" | "error" };
    rateLimit?: { maxRequestsPerMinute: number };
  }
): EventPipeline {
  const pipeline = new EventPipeline();

  // Add processors in order
  pipeline.addProcessor(new IngestionProcessor());

  // Rate limiting (optional)
  if (config?.rateLimit) {
    pipeline.addProcessor(new RateLimitingProcessor(config.rateLimit.maxRequestsPerMinute));
  }

  // Tracking
  pipeline.addProcessor(new TrackingProcessor());

  // Decision making
  if (stingerService) {
    pipeline.addProcessor(new DecisionProcessor(stingerService));
  }

  // Action execution
  if (stingerService) {
    pipeline.addProcessor(new ActionProcessor(stingerService));
  }

  // Cloudflare integration (optional)
  if (config?.cloudflare?.enabled) {
    pipeline.addProcessor(new CloudflareProcessor(
      config.cloudflare.enabled,
      config.cloudflare.threatThreshold
    ));
  }

  // Storage
  pipeline.addProcessor(new StorageProcessor());

  // Logging (optional)
  if (config?.logging) {
    pipeline.addProcessor(new LoggingProcessor(config.logging.level));
  }

  return pipeline;
}
